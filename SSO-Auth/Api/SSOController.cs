using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;
using Jellyfin.Plugin.SSO_Auth.Helpers;
using MediaBrowser.Common.Api;
using MediaBrowser.Common.Extensions;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The sso api controller.
/// </summary>
[ApiController]
[Route("[controller]")]
public class SSOController : ControllerBase
{
    // The uniform-rejection policy and its bodies live on LoginStatusMapper; the direct provider-lookup
    // rejections that stay in the controller reuse its NoMatchingProviderMessage so the wording is
    // defined once (#318).
    private const string NoMatchingProviderMessage = LoginStatusMapper.NoMatchingProviderMessage;

    // Display names for the audit log (the internal link-map mode tokens are the lowercase "oid"/"saml").
    private const string OpenIdProtocol = "OpenID";
    private const string SamlProtocol = "SAML";

    private readonly IUserManager _userManager;
    // The session-minting flow (#318): permissions + avatar + default-provider, then AuthenticateDirect.
    // The controller passes the HttpContext-derived remote endpoint in and keeps no session/avatar field.
    private readonly SessionMinter _sessionMinter;
    private readonly IAuthorizationContext _authContext;
    private readonly ILogger<SSOController> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly IHttpClientFactory _httpClientFactory;

    // The account-linking workflow (resolve/adopt/create, legacy re-key, revoke); the controller keeps
    // the authz guards, the one-time-use replay/state consume, and the HTTP mapping (#318).
    private readonly CanonicalLinkService _canonicalLinks;
    // The in-flight OpenID authorize-state store (cap, lifetime, throttled sweep and capacity signal
    // all live inside; see OidcStateStore). One process-wide instance, like the SAML caches below.
    private static readonly OidcStateStore StateStore = new();

    // One-time-use tracking for consumed SAML assertion IDs (replay protection).
    private static readonly SamlReplayCache SamlReplays = new SamlReplayCache();

    // Outstanding SAML AuthnRequest IDs, for InResponseTo correlation of solicited responses (#156).
    private static readonly SamlRequestCache SamlRequests = new SamlRequestCache();

    // Cache of the two per-discovery-URL facts the challenge reads in one fetch — PKCE-S256 support (#141)
    // and whether the AS advertises the RFC 9207 response-`iss` parameter (#210) — so a login does not
    // fetch discovery every time (the document changes rarely). Only definitive results are cached; a
    // fetch failure is not cached, so it retries on the next login. The short TTL bounds how long a
    // provider's changed metadata is stale.
    private static readonly ConcurrentDictionary<string, (bool PkceS256, bool ResponseIssuerAdvertised, DateTime FetchedAt)> DiscoveryFactsCache = new();
    private static readonly TimeSpan DiscoveryFactsCacheTtl = TimeSpan.FromMinutes(15);

    // How long an issued SAML AuthnRequest ID stays valid for correlation — the interactive leg
    // (challenge -> IdP login/MFA -> POST back -> mint), matching OidcStateStore.DefaultLifetime.
    private static readonly TimeSpan SamlRequestLifetime = TimeSpan.FromMinutes(15);

    // Opt-in per-client rate limiter over the anonymous SSO flow endpoints (#128).
    private static readonly SsoRateLimiter RateLimiter = new SsoRateLimiter();

    /// <summary>
    /// Initializes a new instance of the <see cref="SSOController"/> class.
    /// </summary>
    /// <param name="logger">Instance of the <see cref="ILogger{SSOController}"/> interface.</param>
    /// <param name="loggerFactory">Instance of the <see cref="ILoggerFactory"/> interface.</param>
    /// <param name="sessionManager">Instance of the <see cref="ISessionManager"/> interface.</param>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="userManager">Instance of the <see cref="IUserManager"/> interface.</param>
    /// <param name="cryptoProvider">Instance of the <see cref="ICryptoProvider"/> interface.</param>
    /// <param name="providerManager">Instance of the <see cref="IProviderManager"/> interface.</param>
    /// <param name="httpClientFactory">Instance of the <see cref="IHttpClientFactory"/> interface.</param>
    /// <param name="serverConfigurationManager">Instance of the <see cref="IServerConfigurationManager"/> interface.</param>
    public SSOController(
        ILogger<SSOController> logger,
        ILoggerFactory loggerFactory,
        ISessionManager sessionManager,
        IUserManager userManager,
        IAuthorizationContext authContext,
        ICryptoProvider cryptoProvider,
        IProviderManager providerManager,
        IHttpClientFactory httpClientFactory,
        IServerConfigurationManager serverConfigurationManager)
    {
        _userManager = userManager;
        _authContext = authContext;
        _cryptoProvider = cryptoProvider;
        _logger = logger;
        _loggerFactory = loggerFactory;
        _httpClientFactory = httpClientFactory;
        _canonicalLinks = new CanonicalLinkService(userManager, cryptoProvider, SSOPlugin.Instance.ConfigStore, logger);
        var avatarService = new AvatarService(userManager, providerManager, serverConfigurationManager, logger, SsoHttp.UserAgent);
        _sessionMinter = new SessionMinter(userManager, avatarService, sessionManager, logger);
        _logger.LogInformation("SSO Controller initialized");
    }

    /// <summary>
    /// The GET endpoint for OpenID provider to callback to. Returns a webpage that parses client data and completes auth.
    /// </summary>
    /// <param name="provider">The ID of the provider which will use the callback information.</param>
    /// <param name="state">The current request state.</param>
    /// <returns>A webpage that will complete the client-side flow.</returns>
    // Actually a GET: https://github.com/IdentityModel/IdentityModel.OidcClient/issues/325
    [HttpGet("OID/r/{provider}")]
    [HttpGet("OID/redirect/{provider}")]
    public async Task<ActionResult> OidPost(
        [FromRoute] string provider,
        [FromQuery] string state) // Although this is a GET function, this function is called `Post` for consistency with SAML
    {
        if (RateLimitCheck("callback") is { } throttled)
        {
            return throttled;
        }

        // Unknown and disabled providers share one rejection so neither can be probed apart, matching
        // the guard-clause form the SAML sibling (SamlPost) already uses.
        var config = FindOidConfig(provider);
        if (config is not { Enabled: true })
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        if (string.IsNullOrEmpty(state))
        {
            return BadRequest("Missing state");
        }

        if (StateStore.PeekCurrent(state, provider, DateTime.Now, Request.Cookies[AuthorizeStateBinding.CookieName]) is not { } pending)
        {
            // Unknown, expired, minted for a different provider, or from a different browser than the
            // one that started the flow (#326) — reject (details on PeekCurrent / AuthorizeStateBinding).
            return BadRequest("Invalid or expired state");
        }

        var oidcClient = CreateCallbackOidcClient(config, provider, pending.ProviderInformation);
        var result = await oidcClient.ProcessResponseAsync(Request.QueryString.Value, pending.OidcState).ConfigureAwait(false);

        if (result.IsError)
        {
            return ReturnError(StatusCodes.Status400BadRequest, $"Error logging in: {result.Error} - {result.ErrorDescription}");
        }

        // RFC 9207 (#125, hardened #210): the library parses the authorization-response `iss` but never
        // checks it. When present it must match the authorization server this callback is bound to — its
        // discovery issuer (§2.4's canonical anchor, from the reused #247 or freshly-discovered
        // ProviderInformation) OR the redeemed id_token's issuer. Both are accepted so a provider whose
        // issuer legitimately differs from its discovery location (DoNotValidateIssuerName / templated /
        // multi-tenant) is not locked out — there the response iss equals the concrete id_token iss, not
        // the templated discovery iss. A response iss matching neither is a mix-up, so reject. When the
        // server advertised the parameter (captured at challenge), a missing iss is a downgrade and is
        // likewise rejected; otherwise absence is tolerated so IdPs that never emit `iss` keep working.
        if (!config.DoNotValidateResponseIssuer
            && OidcResponseIssuer.IsRejected(Request.Query["iss"], oidcClient.Options.ProviderInformation?.IssuerName, result.IdentityToken, pending.ResponseIssuerRequired))
        {
            _logger.LogWarning("OpenID login denied for provider {Provider}: the authorization-response issuer was absent-but-required or matched neither the discovery issuer nor the id_token issuer (RFC 9207 mix-up check).", provider?.ReplaceLineEndings(string.Empty));
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SsoResponseInvalid));
        }

        // Derive the authorize-state values (username, validity, admin, Live TV, folders, avatar)
        // from the verified login's claims and the provider configuration; Complete applies them
        // to the stored pending state.
        var derived = OidcAuthorizeStateBuilder.Build(result.User.Claims, config);

        // Fail closed (#155): a valid OpenID login must resolve a stable subject to key the account
        // link on. sub is an OIDC Core MUST and (post-#134) the id_token validator has verified the
        // token, so a missing sub means a non-conformant provider — reject rather than fall back to
        // keying on the mutable username.
        if (derived.Valid && string.IsNullOrWhiteSpace(derived.Subject))
        {
            _logger.LogWarning("OpenID login denied for provider {Provider}: the id_token carried no 'sub' claim to key the account link on.", provider?.ReplaceLineEndings(string.Empty));
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
        }

        pending.Complete(derived);

        bool isLinking = pending.IsLinking;

        if (derived.Valid)
        {
            _logger.LogInformation("Is request linking: {IsLinking}", isLinking);
            return HtmlAuthPage(nonce => WebResponse.Generator(data: state, provider: provider, baseUrl: GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride), mode: "OID", nonce: nonce, isLinking: isLinking));
        }

        _logger.LogWarning(
            "OpenID login denied for {Username}: no role matched the allow-list, or the login resolved no username. Claims: {@Claims}. Roles expected (any one of): {@ExpectedClaims}",
            derived.Username?.ReplaceLineEndings(string.Empty),
            result.User.Claims.Select(o => new { Type = o.Type?.ReplaceLineEndings(string.Empty), Value = o.Value?.ReplaceLineEndings(string.Empty) }),
            config.Roles);

        return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
    }

    /// <summary>
    /// Initiates the login flow for OpenID. This redirects the user to the auth provider.
    /// </summary>
    /// <param name="provider">The name of the provider.</param>
    /// <param name="isLinking">Whether or not this request is to link accounts (Rather than authenticate).</param>
    /// <returns>An asynchronous result for the authentication.</returns>
    [HttpGet("OID/p/{provider}")]
    [HttpGet("OID/start/{provider}")]
    public async Task<ActionResult> OidChallenge(string provider, [FromQuery] bool isLinking = false)
    {
        if (RateLimitCheck("challenge") is { } throttled)
        {
            return throttled;
        }

        StateStore.PruneExpired(DateTime.Now);
        var config = FindOidConfig(provider);
        if (config is not { Enabled: true })
        {
            // Unknown and disabled providers share one rejection so neither can be probed apart (no
            // enumeration oracle), and the answer no longer depends on host middleware mapping a thrown
            // ArgumentException — the in-process 400 is fail-closed regardless of the deployment (#318).
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        // RFC 9700 §2.1.1: confirm the authorization server advertises PKCE (S256) before relying on
        // it. OidcClient sends code_challenge unconditionally but never checks this, so a server that
        // ignores PKCE would silently downgrade authorization-code-injection protection (#141). Fail
        // closed when the provider is marked RequirePkce; otherwise emit an audit warning and proceed.
        // One discovery read yields both facts the challenge needs: PKCE-S256 support (gated below) and
        // whether the AS advertises the RFC 9207 response-`iss` parameter (persisted on the state below,
        // so the callback can require `iss` without a second fetch) (#210).
        var discoveryFacts = await ReadDiscoveryFactsAsync(config, provider).ConfigureAwait(false);
        var pkceSupported = discoveryFacts.PkceS256;
        if (pkceSupported == false)
        {
            if (config.RequirePkce)
            {
                _logger.LogWarning("OpenID login refused for provider {Provider}: RequirePkce is set but the authorization server does not advertise PKCE (S256).", provider?.ReplaceLineEndings(string.Empty));
                return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.PkceNotSupported));
            }

            SsoAudit.PkceNotAdvertised(_logger, provider);
        }
        else if (pkceSupported is null && config.RequirePkce)
        {
            _logger.LogWarning("OpenID login refused for provider {Provider}: RequirePkce is set but the discovery document could not be read to confirm PKCE (S256).", provider?.ReplaceLineEndings(string.Empty));
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.PkceUnverifiable));
        }

        bool newPath = ResolveChallengeNewPath(config.NewPath, isLinking, value => config.NewPath = value);

        string redirectUri = SsoUrlBuilder.OidRedirectUri(GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride), newPath, provider);

        var oidcClient = CreateOidcClient(config, redirectUri, BuildScopeString(config));
        var state = await oidcClient.PrepareLoginAsync().ConfigureAwait(false);

        if (state.IsError)
        {
            return ReturnError(StatusCodes.Status400BadRequest, $"Error preparing login: {state.Error} - {state.ErrorDescription}");
        }

        // Bind this authorize state to the browser that started it (#326): record a fresh random id on
        // the state and hand the same value to the browser as a cookie. The callbacks require the cookie
        // to match before honoring the state, so a state started in one browser cannot be completed in
        // another (the forced-login / session-fixation defense).
        var bindingId = AuthorizeStateBinding.NewId();

        // IsLinking tracks whether this is a linking request rather than a login. The state value
        // is a fresh CSPRNG token, so a collision is effectively impossible; a refusal is almost
        // always the capacity backstop under a flood, and the store throttles its warning signal.
        // The client key bounds how much of the store one source can occupy (#327); a proxy/private
        // source normalizes to null and is exempt.
        var clientKey = SsoRateLimiter.NormalizeClientKey(HttpContext.Connection.RemoteIpAddress);
        if (!StateStore.TryAdd(state, provider, isLinking, DateTime.Now, bindingId, clientKey, out var shouldWarnCapacity))
        {
            if (shouldWarnCapacity)
            {
                _logger.LogWarning("OpenID authorize state refused for provider {Provider}: a CSPRNG-token collision (effectively impossible) or the store is at capacity (warning throttled).", provider?.ReplaceLineEndings(string.Empty));
            }

            return ReturnError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
        }

        // Carry the discovery metadata PrepareLoginAsync just fetched and validated (against this
        // provider's DiscoveryPolicy) to the callback, so ProcessResponseAsync reuses it instead of
        // re-running discovery + JWKS (#247). Recorded after the state is registered; reuse is bounded
        // by this state's lifetime.
        StateStore.SetProviderInformation(state.State, oidcClient.Options.ProviderInformation);

        // RFC 9207 §2.4 (#210): if this provider's discovery advertises the response-`iss` parameter,
        // carry that on the state so the callback requires `iss` to be present (its absence would be a
        // downgrade). Only set when advertised; the state's tolerant default keeps providers that never
        // advertise it working. Read from the same discovery fetch above, so the callback needs no second.
        if (discoveryFacts.ResponseIssuerAdvertised)
        {
            StateStore.MarkResponseIssuerRequired(state.State);
        }

        // Set the cookie only after the state is registered, so a refused challenge leaves no cookie.
        Response.Cookies.Append(AuthorizeStateBinding.CookieName, bindingId, AuthorizeStateBinding.CookieOptions(OidcStateStore.DefaultLifetime));

        return Redirect(state.StartUrl);
    }

    // Test-only reset of the process-wide OpenID caches this controller keeps as private statics: the
    // in-flight authorize-state store and the discovery-facts cache. A test that drives the login flow
    // mutates these, so without a reset the state leaks into a sibling test in the same non-parallel
    // collection. The other static caches are deliberately not cleared here: the SAML replay/request
    // caches key on random IDs and the rate limiter is isolated by per-test client IP, so they cannot
    // bleed between tests. Internal and reachable only through InternalsVisibleTo; it is never wired to
    // an endpoint or DI, so it adds no runtime or security surface. Callback/challenge coverage relies
    // on it for isolation (#289).
    internal static void ResetOidStateForTests()
    {
        StateStore.Clear();
        DiscoveryFactsCache.Clear();
    }

    // Test-only: clears the outstanding-SAML-request cache so a prior test's seeded or in-flight entry
    // (e.g. one left behind by a signature-failing response that returns before the consume) cannot leak
    // into the next test. Same test-only surface as ResetOidStateForTests (internal, InternalsVisibleTo).
    internal static void ResetSamlRequestsForTests() => SamlRequests.Clear();

    // Test-only seed of a single authorize-state entry so a test can exercise the OidAuth callback
    // (which consumes an already-validated state that the browser redirect leg normally populates)
    // without standing up the full token-exchange flow. Same test-only surface as ResetOidStateForTests
    // (internal, InternalsVisibleTo, no endpoint/DI) — never reachable in production.
    internal static void SeedOidStateForTests(string token, TimedAuthorizeState state)
    {
        StateStore.Seed(token, state);
    }

    // Test-only seed of an outstanding SAML AuthnRequest so a test can exercise SamlAuth's browser
    // binding (#415) — normally populated by the SamlChallenge redirect leg — without deriving the
    // random request id from the emitted AuthnRequest. Same test-only surface as SeedOidStateForTests
    // (internal, InternalsVisibleTo, no endpoint/DI); never reachable in production.
    internal static void SeedSamlRequestForTests(string provider, string requestId, string bindingId, DateTime expiryUtc) =>
        SamlRequests.Register(ProviderScopedKey.For(provider, requestId), bindingId, expiryUtc, DateTime.UtcNow, clientKey: null, out _);

    // Reads a provider's config under the config lock, so an anonymous login-path lookup does not race an
    // admin Add/Del mutating the live provider dictionary in place — a Dictionary read-during-write is
    // undefined behaviour in .NET (throw, misread, or a spin on a corrupted chain during a resize) (#252).
    // Returns null for an unknown provider so call sites branch on a null check instead of catching
    // KeyNotFoundException as control flow (#241). An uncontended lock is nanoseconds; it is only held long
    // during a first-login/admin persist, which is exactly when a consistent read matters.
    private static OidConfig FindOidConfig(string provider) =>
        SSOPlugin.Instance.ReadConfiguration(configuration => configuration.OidConfigs.TryGetValue(provider, out var config) ? config : null);

    private static SamlConfig FindSamlConfig(string provider) =>
        SSOPlugin.Instance.ReadConfiguration(configuration => configuration.SamlConfigs.TryGetValue(provider, out var config) ? config : null);

    // Resolves whether this challenge uses the "new", more descriptive redirect path, and records that
    // as server-managed runtime state on the provider config. A non-linking challenge derives the
    // spelling from the request path (a `.../start/...` route means the new path) and stores it through
    // `record`, so a later linking flow — which cannot know which redirect path the identity provider
    // has registered — reuses the last login's spelling. A linking challenge only reads the stored
    // value and records nothing. `record` is passed because OidConfig and SamlConfig do not share a
    // base type. (See ExpectedAcsUrls for the same reason this value is remembered across requests.)
    private bool ResolveChallengeNewPath(bool currentNewPath, bool isLinking, Action<bool> record)
    {
        if (isLinking)
        {
            return currentNewPath;
        }

        var newPath = ChallengePath.IsNewPath(Request.Path.Value);
        record(newPath);
        return newPath;
    }

    // Builds the space-delimited OpenID scope string, always leading with the base "openid profile".
    // OidScopes is null when a provider was stored without scopes (#368, e.g. via the OID/Add API) —
    // normalize to empty so neither the challenge nor the callback throws (an unhandled 500 on the
    // anonymous challenge endpoint) or pads the scope string with null entries. Blank elements inside a
    // non-null array are dropped too, so a persisted null/empty/whitespace scope cannot inject a
    // doubled or trailing separator (#407). Shared by both sites.
    internal static string BuildScopeString(OidConfig config)
        => string.Join(" ", (config.OidScopes ?? Array.Empty<string>())
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Prepend("openid profile"));

    // Builds the OidcClient that both the challenge and the callback use. Pure mechanical assembly:
    // the redirect URI and the scope string are the only two inputs the endpoints derive differently,
    // so the caller supplies them. Constructed in the same order as before the extraction, so a null
    // OidEndpoint still fails at the same point (the Uri constructor, after the options object).
    private OidcClient CreateOidcClient(OidConfig config, string redirectUri, string scope, ProviderInformation providerInformation = null)
    {
        var options = new OidcClientOptions
        {
            Authority = config.OidEndpoint?.Trim(),
            ClientId = config.OidClientId?.Trim(),
            ClientSecret = config.OidSecret?.Trim(),
            RedirectUri = redirectUri,
            Scope = scope,
            DisablePushedAuthorization = config.DisablePushedAuthorization,
            LoggerFactory = _loggerFactory,
            LoadProfile = !config.DoNotLoadProfile,
            HttpClientFactory = o => SsoHttp.CreateClient(_httpClientFactory)
        };
        var oidEndpointUri = new Uri(config.OidEndpoint?.Trim());
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(oidEndpointUri.GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.ValidateEndpoints = !config.DoNotValidateEndpoints; // For Google and other providers with different endpoints
        options.Policy.Discovery.RequireHttps = !config.DisableHttps;
        options.Policy.Discovery.ValidateIssuerName = !config.DoNotValidateIssuerName;

        // OidcClient 7.x validates nothing about the id_token unless a validator is supplied (its
        // fallback only base64-decodes the payload). Signature validation is required and has no
        // config toggle: an unvalidated id_token is a forgeable login (#134).
        options.Policy.RequireIdentityTokenSignature = true;
        options.IdentityTokenValidator = new OidcIdTokenValidator();

        // Reuse the challenge's already-fetched, policy-validated discovery metadata when the callback
        // supplies it (#247), so ProcessResponseAsync does not re-run discovery + JWKS. Pre-assigning
        // ProviderInformation sets the client's internal _useDiscovery = false, which also disables the
        // library's invalid_signature JWKS-refresh-and-retry. Two directions of key change, both bounded
        // by the authorize state's ~15-minute lifetime: a key rotated IN during the window (the id_token
        // signed by a key the challenge did not capture) fails this callback closed and self-heals on
        // retry (the next challenge fetches fresh keys); a key rotated OUT / revoked during the window
        // stays accepted until the state expires, since the callback validates against the captured
        // set — a far tighter exposure than the platform-default 24-hour JWKS cache, and never wider than
        // the state lifetime. Populated only from a validated fetch (never hand-filled), so the
        // DiscoveryPolicy (RequireHttps / ValidateIssuerName / ValidateEndpoints) is not bypassed.
        if (providerInformation is not null)
        {
            options.ProviderInformation = providerInformation;
        }

        return new OidcClient(options);
    }

    // Fetches the provider's OpenID discovery document and reports the discovery facts. The discovery URL is
    // the admin-configured authority + the well-known path (the same document OidcClient uses); the fetch
    // is bounded by a timeout and never throws — a transient failure returns the tolerant default so the
    // caller decides (PKCE fails closed only under RequirePkce; response-`iss` stays optional). Best-effort:
    // this does not replace OidcClient's own discovery, which fails the login if the provider is truly down.
    private async Task<DiscoveryFacts> ReadDiscoveryFactsAsync(OidConfig config, string provider)
    {
        var authority = config.OidEndpoint?.Trim();
        if (string.IsNullOrEmpty(authority) || !Uri.TryCreate(authority, UriKind.Absolute, out _))
        {
            return new DiscoveryFacts(null, false);
        }

        // OidEndpoint is usually the issuer/authority, but some providers (e.g. PocketID) configure the
        // full .well-known URL; append the discovery path only when it is not already present, matching how
        // OidcClient resolves the same document.
        var trimmed = authority.TrimEnd('/');
        var discoveryUrl = trimmed.EndsWith("/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase)
            ? trimmed
            : trimmed + "/.well-known/openid-configuration";

        if (DiscoveryFactsCache.TryGetValue(discoveryUrl, out var cached) && DateTime.UtcNow - cached.FetchedAt < DiscoveryFactsCacheTtl)
        {
            return new DiscoveryFacts(cached.PkceS256, cached.ResponseIssuerAdvertised);
        }

        try
        {
            using var client = SsoHttp.CreateClient(_httpClientFactory);
            client.Timeout = TimeSpan.FromSeconds(10);
            var json = await client.GetStringAsync(discoveryUrl).ConfigureAwait(false);
            var pkceS256 = PkceDiscovery.SupportsS256(json);
            var responseIssuerAdvertised = OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(json);
            DiscoveryFactsCache[discoveryUrl] = (pkceS256, responseIssuerAdvertised, DateTime.UtcNow);
            return new DiscoveryFacts(pkceS256, responseIssuerAdvertised);
        }
        catch (Exception e)
        {
            _logger.LogWarning(
                e,
                "Could not fetch the OpenID discovery document for provider {Provider} to verify PKCE support; proceeding unless RequirePkce is set.",
                provider?.ReplaceLineEndings(string.Empty));
            return new DiscoveryFacts(null, false);
        }
    }

    // Callback-side client: the redirect URI is rebuilt from the callback's own route (the IdP calls
    // back on exactly the route the authorization request advertised), so the token request's
    // redirect_uri matches the authorization request's as RFC 6749 requires (#98). The scope string
    // is normalized the same way as the challenge side (BuildScopeString) — both tolerate a null
    // OidScopes identically (#368).
    private OidcClient CreateCallbackOidcClient(OidConfig config, string provider, ProviderInformation providerInformation)
    {
        var redirectUri = SsoUrlBuilder.OidCallbackRedirectUri(GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride), Request.Path.Value, provider);
        return CreateOidcClient(config, redirectUri, BuildScopeString(config), providerInformation);
    }

    // Rejects a malformed canonical base-URL override (#139) at the OID/SAML Add endpoints. These persist
    // through MutateConfiguration, which passes the live configuration object, so they bypass the
    // config-page save-time validation in ProviderConfigStore.Save (which only runs for a fresh
    // incoming config). Without this, a malformed override set via the Add API would be persisted and then
    // silently fall back to the request Host at login. Throwing keeps it out of the store, so the
    // "rejected at every admin write path" invariant holds. Blank is valid (the feature is off).
    internal static void RejectInvalidBaseUrlOverride(string baseUrlOverride)
    {
        if (CanonicalBaseUrl.IsInvalidOverride(baseUrlOverride))
        {
            throw new ArgumentException("The Base URL override must be an absolute http(s) URL such as https://jellyfin.example.com, or left blank.");
        }
    }

    // Rejects a non-loadable SAML signing certificate at the SAML/Add endpoint (#206), which persists
    // through MutateConfiguration and so bypasses the config-page save-time validation in
    // ProviderConfigValidator.Validate. Without this, a garbage certificate set via the Add API would be
    // persisted and then throw a CryptographicException on every callback (an unhandled 500). Blank is
    // valid (a half-configured provider).
    internal static void RejectInvalidSamlCertificate(string certificateStr)
    {
        if (SamlCertificate.IsInvalid(certificateStr))
        {
            throw new ArgumentException("The SAML signing certificate must be a Base64-encoded (DER) X.509 certificate, or left blank.");
        }
    }

    // Rejects a null provider body at the Add endpoints (#350). ASP.NET model binding hands a null
    // [FromBody] object for an empty or literal "null" JSON payload; storing it would put a null entry
    // in the config map that then NREs the config-page save (ServerManagedFields.Preserve). Reject at
    // the door so the store never holds a null provider — the same fail-closed posture as the other
    // Add-endpoint gates.
    internal static void RejectNullProviderBody(object config)
    {
        if (config is null)
        {
            throw new ArgumentException("The provider configuration body must not be empty.");
        }
    }

    // Rejects a provider name containing URI-reserved or control characters when it would register a NEW
    // provider (#336, #360): the name is appended raw to the callback URLs handed to the identity provider
    // (SsoUrlBuilder), so '%' breaks route decoding, '/' dead-ends the IdP redirect on a path no route
    // matches, control characters do not round-trip at all, and the other RFC 3986 delimiters invite
    // proxy/IdP misinterpretation. Updating an
    // EXISTING name stays allowed: its URL bytes are already registered at the IdP, and blocking the
    // update would strand the deployment behind a rename (encoding the built URLs instead is pinned
    // off by SsoUrlBuilderTests).
    internal static void RejectInvalidNewProviderName(string provider, bool providerExists)
    {
        if (!providerExists && ProviderNameValidator.IsInvalid(provider))
        {
            throw new ArgumentException("A new provider name must not contain control characters, a backslash, or any of % : / ? # [ ] @ ! $ & ' ( ) * + , ; = because the name becomes part of the callback URL registered with the identity provider.");
        }
    }

    /// <summary>
    /// Adds an OpenID auth configuration. Requires administrator privileges. If the provider already exists, it will be removed and readded.
    /// </summary>
    /// <param name="provider">The name of the provider to add.</param>
    /// <param name="config">The OID configuration (deserialized from a JSON post).</param>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("OID/Add/{provider}")]
    public void OidAdd(string provider, [FromBody] OidConfig config)
    {
        RejectNullProviderBody(config);
        RejectInvalidBaseUrlOverride(config.BaseUrlOverride);
        SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            // The name guard needs the under-lock existence check (#336) and runs before any mutation,
            // so a throw leaves the live configuration untouched and nothing is persisted.
            var providerExists = configuration.OidConfigs.TryGetValue(provider, out var existing);
            RejectInvalidNewProviderName(provider, providerExists);

            // Re-inject the server-managed fields this API cannot carry — CanonicalLinks ([JsonIgnore],
            // #157) and the write-only secret's blank-means-keep rule (#189) — through the one shared
            // ServerManagedFields.Preserve the config-page save also uses, so every write path agrees.
            if (providerExists)
            {
                ServerManagedFields.Preserve(config, existing);
            }

            configuration.OidConfigs[provider] = config;
        });
        SsoAudit.ProviderConfigured(_logger, OpenIdProtocol, provider);

        // Audit any disabled security check (#140), so enabling an escape hatch (DisableHttps,
        // DoNotValidateIssuerName, DoNotValidateEndpoints) via this API leaves a trace too.
        var insecure = OidcInsecureToggles.Enabled(config);
        if (insecure.Count > 0)
        {
            SsoAudit.InsecureOptionsEnabled(_logger, OpenIdProtocol, provider, insecure);
        }
    }

    /// <summary>
    /// Deletes an OpenID provider.
    /// </summary>
    /// <param name="provider">Name of provider to delete.</param>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Del/{provider}")]
    public void OidDel(string provider)
    {
        var removed = SSOPlugin.Instance.MutateConfiguration(configuration => configuration.OidConfigs.Remove(provider));
        if (removed)
        {
            SsoAudit.ProviderRemoved(_logger, OpenIdProtocol, provider);
        }
    }

    /// <summary>
    /// Lists the OpenID providers configured. Requires administrator privileges.
    /// </summary>
    /// <returns>The list of OpenID configurations.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Get")]
    public ActionResult OidProviders()
    {
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => SnapshotConfigs(c.OidConfigs)));
    }

    /// <summary>
    /// Lists the OpenID providers names only.
    /// </summary>
    /// <returns>The list of OpenID configurations.</returns>
    [HttpGet("OID/GetNames")]
    public ActionResult OidProviderNames()
    {
        // Materialize the keys under the lock (#157/F-10): returning the live KeyCollection lets the
        // JSON formatter enumerate it outside the lock, tearing against a concurrent provider add/remove.
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.Keys.ToList()));
    }

    /// <summary>
    /// Lists the SAML providers names only.
    /// </summary>
    /// <returns>The list of SAML provider names.</returns>
    [HttpGet("SAML/GetNames")]
    public ActionResult SamlProviderNames()
    {
        // Materialize under the lock (#157/F-10), as OID/GetNames does.
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs.Keys.ToList()));
    }

    /// <summary>
    /// This is a debug endpoint to list all running OpenID flows. Requires administrator privileges.
    /// </summary>
    /// <returns>The list of OpenID flows in progress.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/States")]
    public ActionResult OidStates()
    {
        // Non-secret summaries only — the redaction rationale lives on OidcStateStore.Summaries.
        return Ok(StateStore.Summaries());
    }

    /// <summary>
    /// This endpoint accepts JSON and will authorize the user from the device values passed from the client.
    /// </summary>
    /// <param name="provider">Name of provider to authenticate against.</param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    [HttpPost("OID/Auth/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> OidAuth(string provider, [FromBody] AuthResponse response)
    {
        if (RateLimitCheck("auth") is { } throttled)
        {
            return throttled;
        }

        if (string.IsNullOrEmpty(response?.Data))
        {
            return BadRequest("Missing data");
        }

        // Unknown and disabled providers share one rejection so neither can be probed apart — this
        // unifies the previously JSON unknown-provider body and the disabled provider's 500 into the
        // one uniform 400, and a disabled provider does not consume the state (the guard precedes the
        // redeem, as before).
        var config = FindOidConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        // One-time atomic claim — details on OidcStateStore.TryRedeem. A miss (unknown, expired,
        // provider-mismatched, already-redeemed, or from a different browser than started the flow, #326)
        // is a client-caused rejection, not a server fault: one uniform body, so a replay is
        // indistinguishable from an expiry and replay stays hidden. A binding mismatch does not consume
        // the state (the check precedes the atomic remove), so it cannot burn a legitimate user's state.
        if (StateStore.TryRedeem(response.Data, provider, DateTime.Now, Request.Cookies[AuthorizeStateBinding.CookieName]) is not { } redeemed)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.InvalidState));
        }

        Guid userId;
        try
        {
            userId = await _canonicalLinks.ResolveOrCreateAsync(
                "oid",
                provider,
                redeemed.Subject,
                redeemed.Username,
                config.AllowExistingAccountLink,
                new AdoptionGate(config.RequireVerifiedEmailForAdoption, redeemed.EmailVerified)).ConfigureAwait(false);
        }
        catch (AccountLinkForbiddenException)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AccountLinkForbidden));
        }

        var sessionParameters = new SessionParameters
        {
            UserId = userId,
            IsAdmin = redeemed.Admin,
            EnableAuthorization = config.EnableAuthorization,
            EnableAllFolders = config.EnableAllFolders,
            EnabledFolders = redeemed.Folders.ToArray(),
            EnableLiveTv = redeemed.EnableLiveTv,
            EnableLiveTvManagement = redeemed.EnableLiveTvManagement,
            AuthResponse = response,
            DefaultProvider = config.DefaultProvider?.Trim(),
            AvatarUrl = redeemed.AvatarUrl,
        };
        var authenticationResult = await Authenticate(
            sessionParameters,
            () => _canonicalLinks.IsIdentityStillLinked("oid", provider, redeemed.Subject, userId)).ConfigureAwait(false);
        SsoAudit.LoginSucceeded(_logger, OpenIdProtocol, provider, redeemed.Username, redeemed.Admin);
        return LoginStatusMapper.ToActionResult(new LoginOutcome.Success(authenticationResult));
    }

    /// <summary>
    /// This is the callback for the SAML flow. This creates a webpage to complete auth.
    /// </summary>
    /// <param name="provider">The provider that is calling back.</param>
    /// <param name="relayState">
    ///    RelayState given in the original saml request. If it is equal to "linking",
    ///    We consider this to be a linking request.
    /// </param>
    /// <param name="formSamlResponse">
    ///    The SAMLResponse form field, model-bound so a non-form POST binds null (and is rejected)
    ///    instead of making Request.Form throw an unhandled 500 (#206).
    /// </param>
    /// <returns>A webpage that will complete the client-side flow.</returns>
    [HttpPost("SAML/p/{provider}")]
    [HttpPost("SAML/post/{provider}")]
    public ActionResult SamlPost(string provider, [FromQuery] string relayState = null, [FromForm(Name = "SAMLResponse")] string formSamlResponse = null)
    {
        if (RateLimitCheck("callback") is { } throttled)
        {
            return throttled;
        }

        // Unknown and disabled providers share one rejection so neither can be probed apart — this
        // retires the unique "No active providers found" wording that distinguished the disabled case
        // (a disabled provider now short-circuits before the relayState log line).
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        bool isLinking = string.Equals(relayState, "linking", StringComparison.Ordinal);

        // relayState is attacker-controllable; strip line endings inline at the log call to prevent
        // log forging (structured logging alone does not sanitize a newline-bearing value).
        _logger.LogInformation(
            "SAML request has relayState of {RelayState}",
            relayState?.ReplaceLineEndings(string.Empty));

        // Bind SAMLResponse via [FromForm] rather than reading Request.Form directly: a non-form
        // content-type binds null (the form value provider is skipped, so Request.Form is never
        // touched and cannot throw the InvalidOperationException that escaped as a 500, #206), and a
        // null body is rejected the same way as any other malformed response — a clean 400.
        if (!SamlResponseLoader.TryParse(config.SamlCertificate, formSamlResponse, out var samlResponse)
            || !IsSamlResponseValid(samlResponse, config, provider))
        {
            // A malformed response (non-base64, malformed XML, prohibited DOCTYPE) fails TryLoad and
            // is rejected the same way an invalid one is — a clean 4xx, never an unhandled 500 (#199).
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        if (SamlLoginPolicy.IsLoginAllowed(samlResponse.GetCustomAttributes("Role"), config.Roles))
        {
            return HtmlAuthPage(nonce =>
                WebResponse.Generator(
                    data: Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(samlResponse.Xml)),
                    provider: provider,
                    baseUrl: GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride),
                    mode: "SAML",
                    nonce: nonce,
                    isLinking: isLinking));
        }

        _logger.LogWarning(
            "SAML user: {UserId} has insufficient roles: {@Roles}. Expected any one of: {@ExpectedRoles}",
            samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty),
            samlResponse.GetCustomAttributes("Role").Select(r => r?.ReplaceLineEndings(string.Empty)),
            config.Roles);
        return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
    }

    /// <summary>
    /// Initializes the SAML flow. This will redirect the user to the SAML provider.
    /// </summary>
    /// <param name="provider">The provider to being the flow with.</param>
    /// <param name="isLinking">Whether this flow intends to link an account, or initiate auth.</param>
    /// <returns>A redirect to the SAML provider's auth page.</returns>
    [HttpGet("SAML/p/{provider}")]
    [HttpGet("SAML/start/{provider}")]
    public ActionResult SamlChallenge(string provider, [FromQuery] bool isLinking = false)
    {
        if (RateLimitCheck("challenge") is { } throttled)
        {
            return throttled;
        }

        // Unknown and disabled providers share one rejection so neither can be probed apart, and the
        // answer no longer depends on host middleware mapping a thrown ArgumentException (#318).
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        bool newPath = ResolveChallengeNewPath(config.NewPath, isLinking, value => config.NewPath = value);

        string redirectUri = SsoUrlBuilder.SamlAcsUrl(GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride), newPath, provider);
        string relayState = null;
        if (isLinking)
        {
            relayState = "linking";
        }

        var request = new SamlAuthnRequest(
            config.SamlClientId.Trim(),
            redirectUri);

        // Bind this login to the initiating browser (#415): mint a binding id, set it as a cookie, and
        // record it against the request id so the session-mint endpoint (SamlAuth) can require the
        // response's browser to be the one that started the flow — closing the SP-initiated forced-login
        // / session-fixation vector, the SAML analogue of #326. Only for login flows: the linking
        // callback (SamlLink) is a separate flow that does not consume the outstanding request, so a
        // linking registration would only leave an id to expire unused. Registration now happens for
        // every login challenge (not only under ValidateInResponseTo), so the binding is enforced for
        // every SOLICITED login this plugin initiated — the case ValidateInResponseTo alone left open.
        // It does NOT bind an unsolicited (IdP-initiated) response, which carries no matching request;
        // fully closing forced login for an IdP that issues unsolicited responses additionally requires
        // ValidateInResponseTo (which refuses them). Because the cookie is __Host-/Secure, the browser
        // only returns it over HTTPS — SP-initiated SAML now needs HTTPS at the browser edge, as OIDC
        // already does.
        if (!isLinking)
        {
            var bindingId = AuthorizeStateBinding.NewId();

            // The client key bounds how much of the request cache one source can occupy (#327); a
            // proxy/private source normalizes to null and is exempt.
            var clientKey = SsoRateLimiter.NormalizeClientKey(HttpContext.Connection.RemoteIpAddress);
            if (!SamlRequests.Register(
                    ProviderScopedKey.For(provider, request.Id),
                    bindingId,
                    DateTime.UtcNow + SamlRequestLifetime,
                    DateTime.UtcNow,
                    clientKey,
                    out var shouldWarnCapacity))
            {
                // The per-client sub-cap or the global cap refused this login's outstanding-request
                // entry (#327). Fail closed HERE rather than redirect to the IdP for a login that could
                // then only be refused at the callback (no correlation entry). The store throttles the
                // capacity warning to one signal per interval so a flood cannot amplify into log volume
                // (CWE-400) — parity with the OpenID challenge refusal.
                if (shouldWarnCapacity)
                {
                    _logger.LogWarning("SAML request refused for provider {Provider}: the per-client sub-cap or the outstanding-request cache is at capacity (warning throttled).", provider?.ReplaceLineEndings(string.Empty));
                }

                return ReturnError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
            }

            Response.Cookies.Append(
                AuthorizeStateBinding.SamlCookieName,
                bindingId,
                AuthorizeStateBinding.CookieOptions(SamlRequestLifetime));
        }

        return Redirect(request.GetRedirectUrl(config.SamlEndpoint.Trim(), relayState));
    }

    /// <summary>
    /// Adds a SAML configuration. If the provider already exists, overwrite it.
    /// </summary>
    /// <param name="provider">The provider name to add.</param>
    /// <param name="newConfig">The SAML configuration object (deserialized) from JSON.</param>
    /// <returns>The success result.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SAML/Add/{provider}")]
    public OkResult SamlAdd(string provider, [FromBody] SamlConfig newConfig)
    {
        RejectNullProviderBody(newConfig);
        RejectInvalidBaseUrlOverride(newConfig.BaseUrlOverride);
        RejectInvalidSamlCertificate(newConfig.SamlCertificate);
        SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            // The name guard needs the under-lock existence check (#336) and runs before any mutation,
            // so a throw leaves the live configuration untouched and nothing is persisted.
            var providerExists = configuration.SamlConfigs.TryGetValue(provider, out var existing);
            RejectInvalidNewProviderName(provider, providerExists);

            // Preserve the server-managed canonical links (#157), as OidAdd does, through the shared
            // ServerManagedFields.Preserve: the posted config never carries them ([JsonIgnore]), so
            // re-inject the live map before the wholesale replace so an API save cannot wipe links.
            if (providerExists)
            {
                ServerManagedFields.Preserve(newConfig, existing);
            }

            configuration.SamlConfigs[provider] = newConfig;
        });
        SsoAudit.ProviderConfigured(_logger, SamlProtocol, provider);
        return Ok();
    }

    /// <summary>
    /// Deletes a provider from the configuration with a given ID.
    /// </summary>
    /// <param name="provider">The ID of the provider to delete.</param>
    /// <returns>The success result.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SAML/Del/{provider}")]
    public OkResult SamlDel(string provider)
    {
        var removed = SSOPlugin.Instance.MutateConfiguration(configuration => configuration.SamlConfigs.Remove(provider));
        if (removed)
        {
            SsoAudit.ProviderRemoved(_logger, SamlProtocol, provider);
        }

        return Ok();
    }

    /// <summary>
    /// Returns a list of all SAML providers configured. Requires administrator privileges.
    /// </summary>
    /// <returns>A list of all of the Saml providers available.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SAML/Get")]
    public ActionResult SamlProviders()
    {
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => SnapshotConfigs(c.SamlConfigs)));
    }

    /// <summary>
    /// This endpoint accepts JSON and will authorize the user from the device values passed from the client.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    [HttpPost("SAML/Auth/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> SamlAuth(string provider, [FromBody] AuthResponse response)
    {
        if (RateLimitCheck("auth") is { } throttled)
        {
            return throttled;
        }

        // Unknown and disabled providers share one rejection so neither can be probed apart — this
        // unifies the previously JSON unknown-provider body and the disabled provider's 500.
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        if (!SamlResponseLoader.TryParse(config.SamlCertificate, response?.Data, out var samlResponse)
            || !IsSamlResponseValid(samlResponse, config, provider))
        {
            // Malformed input is rejected the same way an invalid response is — clean 4xx, not 500 (#199).
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // Correlate the response to an AuthnRequest this server issued (#156, #415), and enforce the
        // browser binding for a solicited login. A NON-EMPTY InResponseTo means the response claims to
        // answer a request this server issued, so it must actually correlate to a live outstanding
        // request AND carry that request's binding cookie — anything less fails closed. Crucially, a
        // non-empty InResponseTo whose entry is gone (expired past the 15-minute window, evicted at the
        // cap, lost to a restart or a non-sticky multi-node hop) is a LOST correlation, not an
        // unsolicited response: treating it as unsolicited would let a signature-valid response mint a
        // session with no binding check when ValidateInResponseTo is off, which is exactly the
        // forced-login bypass the binding exists to close (login validity must never default to true).
        //
        // The binding is checked AFTER the atomic claim (unlike the OpenID state, #326) and that is safe:
        // the response already passed signature validation above and the InResponseTo is read from that
        // validated document, so an attacker cannot mint a signature-valid response carrying a victim's
        // request id to burn their outstanding entry. The cookie is checked here (the same-origin auth
        // endpoint), not at the cross-site ACS POST which would not carry a SameSite=Lax cookie.
        var inResponseTo = samlResponse.GetInResponseTo();
        if (!string.IsNullOrEmpty(inResponseTo))
        {
            var requestKey = ProviderScopedKey.For(provider, inResponseTo);
            if (!SamlRequests.TryConsume(requestKey, DateTime.UtcNow, out var storedBindingId)
                || !AuthorizeStateBinding.Matches(storedBindingId, Request.Cookies[AuthorizeStateBinding.SamlCookieName]))
            {
                _logger.LogWarning("SAML login denied: a solicited response did not correlate to a live outstanding request from the initiating browser (binding mismatch, expiry, or lost correlation).");
                return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
            }
        }
        else if (config.ValidateInResponseTo)
        {
            // No InResponseTo at all: a genuinely unsolicited (IdP-initiated) response. It is refused
            // only when the opt-in solicited-only mode is on; otherwise it proceeds — unchanged and
            // non-breaking for IdP-initiated deployments. The rejection is a client-caused 400 in the
            // uniform SAML body, never a 500, and the diagnosis stays in the warning log.
            _logger.LogWarning("SAML login denied: the response was not solicited by this server (no InResponseTo).");
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // Enforce the login allow-list here too, not only at the assertion-consumer page: a caller
        // can POST an assertion straight to this session-minting endpoint and skip the page, so
        // checking it only there would be fail-open.
        if (!SamlLoginPolicy.IsLoginAllowed(samlResponse.GetCustomAttributes("Role"), config.Roles))
        {
            _logger.LogWarning(
                "SAML user: {UserId} has insufficient roles at the session-minting endpoint; login denied.",
                samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty));
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
        }

        // Enforce one-time use so a captured assertion cannot be replayed to mint another session.
        // Enforced only here (the session-minting endpoint), not at the SAML/post ACS which merely
        // renders the intermediate page, so the two-step post-then-auth flow consumes the id once. A
        // replay is a client-caused 400 in the uniform SAML body — it no longer discloses the replay
        // cache to the attacker who replayed, and the log-side diagnosis is unchanged.
        if (!TryConsumeSamlReplay(samlResponse, provider))
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // Derive the authorize-state privileges (admin, Live TV, Live TV management, folders) from
        // the assertion's roles and the provider configuration. Login validity was already decided
        // above by SamlLoginPolicy and the username is the assertion's NameID, so neither is derived
        // here.
        var derived = SamlAuthorizeStateBuilder.Build(samlResponse.GetCustomAttributes("Role"), config);

        // Fail closed (#95): an assertion without a usable NameID carries no identity to log in —
        // reject it as an invalid login instead of failing downstream on a null canonical name.
        // Whitespace-only counts as unresolved (Jellyfin's username validation rejects it anyway).
        var nameId = samlResponse.GetNameID();
        if (string.IsNullOrWhiteSpace(nameId))
        {
            _logger.LogWarning("SAML login denied: the assertion resolved no NameID.");
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
        }

        Guid userId;
        try
        {
            // SAML keys the link directly on the NameID, which is already the stable subject
            // identifier — key and account name are the same value (no migration path needed). SAML has
            // no email_verified claim, so the verified-email gate is not applicable (AdoptionGate.None);
            // the resolver's unconditional admin-adoption refusal (#218) still applies.
            userId = await _canonicalLinks.ResolveOrCreateAsync("saml", provider, nameId, nameId, config.AllowExistingAccountLink, AdoptionGate.None).ConfigureAwait(false);
        }
        catch (AccountLinkForbiddenException)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AccountLinkForbidden));
        }

        var sessionParameters = new SessionParameters
        {
            UserId = userId,
            IsAdmin = derived.Admin,
            EnableAuthorization = config.EnableAuthorization,
            EnableAllFolders = config.EnableAllFolders,
            EnabledFolders = derived.Folders.ToArray(),
            EnableLiveTv = derived.EnableLiveTv,
            EnableLiveTvManagement = derived.EnableLiveTvManagement,
            AuthResponse = response,
            DefaultProvider = config.DefaultProvider?.Trim(),
            AvatarUrl = null,
        };
        var authenticationResult = await Authenticate(
            sessionParameters,
            () => _canonicalLinks.IsIdentityStillLinked("saml", provider, nameId, userId)).ConfigureAwait(false);
        SsoAudit.LoginSucceeded(_logger, SamlProtocol, provider, nameId, derived.Admin);
        return LoginStatusMapper.ToActionResult(new LoginOutcome.Success(authenticationResult));
    }

    /// <summary>
    /// Removes a user from SSO auth and switches it back to another auth provider. Requires administrator privileges.
    /// </summary>
    /// <param name="username">The username to switch to the new provider.</param>
    /// <param name="provider">The new provider to switch to.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("Unregister/{username}")]
    public async Task<ActionResult> Unregister(string username, [FromBody] string provider)
    {
        var user = _userManager.GetUserByName(username);
        if (user is null)
        {
            return NotFound();
        }

        // SSO login resolves through the per-provider CanonicalLinks maps, not AuthenticationProviderId,
        // so revoking SSO means removing this user's canonical links from every provider — otherwise the
        // account would still sign in via SSO (#213). Done under the config lock. NOTE: with a provider's
        // AllowExistingAccountLink enabled, the same-named account can be re-adopted on the next SSO login,
        // so a hard revoke there also needs the local account disabled or renamed; with the fail-closed
        // default (adoption off) the revoke is durable.
        var revoked = _canonicalLinks.RemoveUserEverywhere(user.Id);

        // Switch the account back to the requested auth provider and PERSIST it — the previous version set
        // this in memory only and never called UpdateUserAsync, so the switch was silently discarded.
        user.AuthenticationProviderId = provider;
        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        _logger.LogInformation("Unregistered SSO for user {UserId}: removed {Count} canonical link(s).", user.Id, revoked);

        return Ok();
    }

    /// <summary>
    /// Create a canonical link for a given user. Must be performed by the user being changed, or admin.
    /// </summary>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="provider">The name of the provider to link to a jellyfin account.</param>
    /// <param name="jellyfinUserId">The user ID within jellyfin to link to the provider.</param>
    /// <param name="authResponse">The client information to authenticate the user with.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize]
    [HttpPost("{mode}/Link/{provider}/{jellyfinUserId}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> AddCanonicalLink([FromRoute] string mode, [FromRoute] string provider, [FromRoute] Guid jellyfinUserId, [FromBody] AuthResponse authResponse)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "User is not allowed to link SSO providers.");
        }

        switch (mode.ToLower())
        {
            case "saml":
                return SamlLink(provider, jellyfinUserId, authResponse);
            case "oid":
                return OidLink(provider, jellyfinUserId, authResponse);
            default:
                throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'");
        }
    }

    /// <summary>
    /// Unregisters a given mapping from id within provider to user.
    /// </summary>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="provider">The name of the provider from which the link should be removed.</param>
    /// <param name="jellyfinUserId">The user ID within jellyfin to unlink from the provider.</param>
    /// <param name="canonicalName">The provider-side canonical name (the identity's stable subject for OpenID, or the SAML NameID) whose link to the Jellyfin user should be removed.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize]
    [HttpDelete("{mode}/Link/{provider}/{jellyfinUserId}/{canonicalName}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> DeleteCanonicalLink([FromRoute] string mode, [FromRoute] string provider, [FromRoute] Guid jellyfinUserId, [FromRoute] string canonicalName)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Current user is not allowed to unlink SSO providers for user ID.");
        }

        var removeResult = _canonicalLinks.TryRemoveLink(mode, provider, canonicalName, jellyfinUserId);
        return removeResult switch
        {
            CanonicalLinkRemoveResult.Removed => Ok(),
            CanonicalLinkRemoveResult.NotFound => NotFound("No SSO link is registered for that canonical name."),
            CanonicalLinkRemoveResult.Mismatch => StatusCode(StatusCodes.Status409Conflict, "jellyfin UID does not match id registered to that canonical name."),
            CanonicalLinkRemoveResult.UnknownProvider => BadRequest(NoMatchingProviderMessage),
            _ => throw new InvalidOperationException($"Unhandled canonical-link remove result: {removeResult}"),
        };
    }

    /// <summary>
    /// Gets all the saml links for a user.
    /// </summary>
    /// <param name="jellyfinUserId">The user ID within jellyfin for which to return the links.</param>
    /// <returns>A dictionary of provider : link mappings.</returns>
    [Authorize]
    [HttpGet("saml/links/{jellyfinUserId}")]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult<SerializableDictionary<string, IEnumerable<string>>>> GetSamlLinksByUser(Guid jellyfinUserId)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Non-admin is not allowed to query other user's mappings.");
        }

        return _canonicalLinks.LinksByUser("saml", jellyfinUserId);
    }

    /// <summary>
    /// Gets all the oid links for a user.
    /// </summary>
    /// <param name="jellyfinUserId">The user ID within jellyfin for which to return the links.</param>
    /// <returns>A dictionary of provider : link mappings.</returns>
    [Authorize]
    [HttpGet("oid/links/{jellyfinUserId}")]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult<SerializableDictionary<string, IEnumerable<string>>>> GetOidLinksByUser(Guid jellyfinUserId)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Non-admin is not allowed to query other user's mappings.");
        }

        return _canonicalLinks.LinksByUser("oid", jellyfinUserId);
    }

    // A shallow copy of a provider map, taken under the config lock so the admin list endpoints
    // serialize a detached snapshot rather than the live dictionary (#157/F-10): a concurrent
    // provider add/remove cannot then modify the collection mid-serialization. The provider objects
    // are shared, but their CanonicalLinks are [JsonIgnore] (never serialized), and the only other
    // in-place write on the hot path is the NewPath bool flipped by a challenge — a scalar write that
    // cannot tear a JSON serialization or throw "collection modified".
    private static SerializableDictionary<string, TValue> SnapshotConfigs<TValue>(SerializableDictionary<string, TValue> source)
    {
        var copy = new SerializableDictionary<string, TValue>();
        foreach (var kvp in source)
        {
            copy[kvp.Key] = kvp.Value;
        }

        return copy;
    }

    /// <summary>
    /// Validate a saml link request and create the link if it is valid.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="jellyfinUserId">
    ///   The ID of the account to be linked to the provider.
    ///   Must be performed by this user, or an admin.
    /// </param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    // No [Consumes]/[Produces]: ASP.NET Core honors content-negotiation filters only on public action
    // methods, and this is a private helper invoked directly from AddCanonicalLink, which carries its
    // own. The attributes were inert metadata here (#393).
    private ActionResult SamlLink(string provider, Guid jellyfinUserId, AuthResponse response)
    {
        // A disabled provider must neither create a link nor consume the assertion's one-time-use ID
        // (#343): an administrator disabling a provider takes effect immediately for linking, and the
        // unknown and disabled cases share one response so neither can be probed apart.
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        if (!SamlResponseLoader.TryParse(config.SamlCertificate, response?.Data, out var samlResponse)
            || !IsSamlResponseValid(samlResponse, config, provider))
        {
            // Malformed input is rejected the same way an invalid response is — clean 4xx, not 500 (#199).
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // Enforce one-time use here too (#219): without it, a captured, still-valid assertion could be
        // replayed to bind its NameID to the caller's account. The linking flow issues no AuthnRequest,
        // so InResponseTo is not correlated here — the replay cache is the applicable one-time-use
        // control. A replay is a client-caused 400 in the uniform SAML body, never a 500, and no longer
        // discloses the replay cache to the attacker who replayed.
        if (!TryConsumeSamlReplay(samlResponse, provider))
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        string providerUserId = samlResponse.GetNameID();

        return MapWrite(_canonicalLinks.TryCreateLink("saml", provider, providerUserId, jellyfinUserId));
    }

    /// <summary>
    /// Validate an OIDC link request and create the link if it is valid.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="jellyfinUserId">
    ///   The ID of the account to be linked to the provider.
    ///   Must be performed by this user, or an admin.
    /// </param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    // No [Consumes]/[Produces]: inert on a private helper (see SamlLink) — AddCanonicalLink owns the
    // content negotiation (#393).
    private ActionResult OidLink(string provider, Guid jellyfinUserId, AuthResponse response)
    {
        if (string.IsNullOrEmpty(response?.Data))
        {
            return BadRequest("Missing data");
        }

        // A disabled provider must neither create a link nor consume the state (#343), mirroring
        // OidAuth's short-circuit order: an administrator disabling a provider takes effect for
        // in-flight linking states immediately, not after their 15-minute lifetime. The unknown and
        // disabled cases share one response, so neither can be probed apart (no enumeration oracle).
        if (FindOidConfig(provider) is not { Enabled: true })
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        // One-time atomic claim (see OidcStateStore.TryRedeem): consume the state so one verified
        // identity cannot be linked repeatedly and cannot then be reused to mint a session. A miss
        // (unknown, expired, provider-mismatched, already-redeemed, or from a different browser than
        // started the flow, #326) is a client-caused 400 in the same uniform body as the login path,
        // not a 500. The linking challenge sets the same binding cookie, carried on this same-origin POST.
        if (StateStore.TryRedeem(response.Data, provider, DateTime.Now, Request.Cookies[AuthorizeStateBinding.CookieName]) is not { } redeemed)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.InvalidState));
        }

        // Manual linking keys on the stable subject (#155), matching the auto-login path, so a
        // later provider-side rename does not orphan the link the user just created.
        return MapWrite(_canonicalLinks.TryCreateLink("oid", provider, redeemed.Subject, jellyfinUserId));
    }

    // The HTTP boundary for a manual link creation: maps the service's closed write result to a response.
    // The empty-key and unknown-provider refusals keep distinct bodies (the service checks the empty key
    // first), and an unhandled result throws rather than silently returning a wrong status.
    private ActionResult MapWrite(CanonicalLinkWriteResult result) => result switch
    {
        CanonicalLinkWriteResult.Created => NoContent(),
        CanonicalLinkWriteResult.EmptyKey => BadRequest("The SSO login did not resolve an identity."),
        CanonicalLinkWriteResult.UnknownProvider => BadRequest(NoMatchingProviderMessage),
        _ => throw new InvalidOperationException($"Unhandled canonical-link write result: {result}"),
    };

    // The HTTP boundary for session minting: hand the resolved parameters and a resolver for the client's
    // normalized remote IP (#177 — Jellyfin's own GetNormalizedRemoteIP, so the plugin adds no proxy-trust
    // logic of its own) to the SessionMinter flow. The resolver is passed rather than the value so the
    // flow evaluates it at the exact original point (after avatar/persistence, and NOT at all on the
    // fail-closed deleted-user path) — the pre-extraction Authenticate read it inline there.
    private Task<AuthenticationResult> Authenticate(SessionParameters parameters, Func<bool> identityStillLinked) =>
        _sessionMinter.MintAsync(parameters, () => HttpContext.GetNormalizedRemoteIP().ToString(), identityStillLinked);

    // Applies the opt-in per-client rate limit (#128) on an anonymous flow endpoint: null when the
    // request may proceed, else a 429 carrying Retry-After. Reads the settings under the config
    // lock; an unattributable or non-public client is never throttled (fail open, availability
    // over throttling). Keys on RemoteIpAddress only — proxy attribution is the host's job
    // (Jellyfin's "Known proxies" setting resolves the real client into it); see
    // SsoRateLimiter.NormalizeClientKey. The endpoint class (challenge/callback/auth) is part of
    // the key so one login — which hits all three — gets the full budget at each stage rather
    // than a third of it, keeping the default generous for shared egress addresses (NAT/CGNAT).
    private ContentResult RateLimitCheck(string endpointClass)
    {
        var (enabled, maxAttempts, windowSeconds) = SSOPlugin.Instance.ReadConfiguration(
            c => (c.EnableRateLimit, c.RateLimitMaxAttempts, c.RateLimitWindowSeconds));
        if (!enabled || windowSeconds < 1)
        {
            // maxAttempts < 1 is handled inside IsAllowed (it disables the limiter there).
            return null;
        }

        var key = SsoRateLimiter.NormalizeClientKey(HttpContext.Connection.RemoteIpAddress);
        if (key != null)
        {
            key = endpointClass + ":" + key;
        }

        var now = DateTime.UtcNow;
        if (RateLimiter.IsAllowed(key, maxAttempts, TimeSpan.FromSeconds(windowSeconds), now, out var retryAfterSeconds))
        {
            return null;
        }

        // Bounded observability signal (#195): so an operator can notice a sustained brute-force or a
        // reverse proxy misconfigured to pool every client into one bucket, without the notice itself
        // becoming a log/CPU amplifier. The limiter emits at most one line per interval, carrying only
        // an aggregate count (no client key — nothing to sanitize or forge); a returned 0 stays silent.
        var throttledCount = RateLimiter.RecordThrottledHit(now);
        if (throttledCount > 0)
        {
            _logger.LogWarning("SSO rate limit engaged on the anonymous login endpoints: {Count} request(s) throttled since the last notice; further notices are suppressed for at least a minute.", throttledCount);
        }

        // A human-readable body, not a bare status: the challenge/callback endpoints are navigated
        // directly in the browser, so a blank 429 would look like a broken login (the XHR auth page
        // reads the status, not this body). Retry-After carries the machine-readable delay.
        Response.Headers.RetryAfter = retryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return ReturnError(StatusCodes.Status429TooManyRequests, "Too many login attempts. Please wait a moment and try again.");
    }

    // Consumes the SAML assertion's ID against the provider-scoped replay cache for one-time use.
    // Returns false when the assertion was already used (or carries no ID — a missing ID stays empty,
    // so TryConsume fails closed). The key is scoped by provider so two IdPs emitting the same assertion
    // ID cannot block each other. Shared by SamlAuth (session mint) and SamlLink (account linking, #219).
    private bool TryConsumeSamlReplay(SamlResponse samlResponse, string provider)
    {
        var samlNow = DateTime.UtcNow;
        var replayRetention = SamlReplayCache.ComputeRetention(samlNow, samlResponse.GetNotOnOrAfter());
        var assertionId = samlResponse.GetAssertionId();
        var replayKey = ProviderScopedKey.For(provider, assertionId);
        return SamlReplays.TryConsume(replayKey, replayRetention, samlNow);
    }

    // Validates the SAML response and, on failure, logs the declared signature algorithm plus the
    // weak-algorithm remediation hint. This lets an operator tell a rejected SHA-1 signature - the
    // expected post-upgrade lockout of a legacy IdP - apart from a bad certificate, an expired
    // assertion, or an audience mismatch, all of which otherwise surface as the same opaque error.
    private bool IsSamlResponseValid(SamlResponse samlResponse, SamlConfig config, string provider)
    {
        if (!ValidateSaml(samlResponse, config))
        {
            // The algorithm URI is identity-provider-controlled; strip line endings inline at the log
            // call to prevent log forging (a helper-boundary sanitizer is not recognized by CodeQL).
            _logger.LogWarning(
                "SAML response validation failed (signature algorithm: {Algorithm}). SHA-1 is rejected; if that is the identity provider's algorithm, reconfigure it to sign with RSA/ECDSA-SHA-256 or stronger.",
                samlResponse.GetSignatureAlgorithm()?.ReplaceLineEndings(string.Empty));
            return false;
        }

        // Endpoint binding (#156, opt-in): the signed assertion must be addressed to this service
        // provider's assertion-consumer URL, so an assertion minted for a different endpoint (or a
        // different SP sharing the identity provider) cannot be presented here.
        if (config.ValidateRecipient
            && !SamlRecipientValidator.IsBound(samlResponse.GetRecipient(), samlResponse.GetDestination(), ExpectedAcsUrls(config, provider)))
        {
            _logger.LogWarning("SAML response rejected: the assertion Recipient or Response Destination does not match this server's assertion-consumer URL.");
            return false;
        }

        return true;
    }

    // The assertion-consumer URLs this service provider advertises for the provider — the same value
    // SamlChallenge puts in the AuthnRequest's AssertionConsumerServiceURL, so a signed Recipient (or
    // Destination) must equal one. Both the new ("post") and legacy ("p") path spellings are returned:
    // config.NewPath is process-wide mutable state a concurrent challenge can flip, and the Recipient
    // reflects whichever the AuthnRequest advertised at challenge time, so accepting either avoids
    // rejecting a valid login on a path-form flip; both are this provider's own ACS URLs.
    //
    // The host comes from GetRequestBase. With BaseUrlOverride set (#139) it is the pinned canonical
    // host, so this binding is exact regardless of the request Host. Without it the host is the request
    // Host, so the binding is only as strong as host resolution: behind a reverse proxy, configure
    // Jellyfin's Known/Trusted Proxies (or set BaseUrlOverride) so the Host cannot be spoofed, or an
    // attacker controlling the Host can make the expected URL match a captured assertion's Recipient
    // (defense-in-depth, not a hard guarantee).
    private string[] ExpectedAcsUrls(SamlConfig config, string provider) =>
        SsoUrlBuilder.SamlExpectedAcsUrls(GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride), provider);

    // Validates a SAML response: signature + time bounds always, plus AudienceRestriction binding to
    // this SP unless explicitly opted out. Expected audience is the configured SamlAudience, falling
    // back to the SamlClientId (SP entity id). Both are trimmed so the comparison matches the trimmed
    // Issuer sent in the AuthnRequest, and an empty SamlAudience falls through to the client id.
    internal static bool ValidateSaml(SamlResponse samlResponse, SamlConfig config)
    {
        if (config.DoNotValidateAudience)
        {
            return samlResponse.IsValid();
        }

        var expected = config.SamlAudience?.Trim();
        if (string.IsNullOrEmpty(expected))
        {
            expected = config.SamlClientId?.Trim();
        }

        return samlResponse.IsValid(expected);
    }

    // Thin wrapper feeding the live request values into the pure CanonicalBaseUrl.Resolve decision (#242).
    private string GetRequestBase(string schemeOverride = null, int? portOverride = null, string baseUrlOverride = null) =>
        CanonicalBaseUrl.Resolve(baseUrlOverride, Request.Scheme, Request.Host.Host, Request.Host.Port, Request.PathBase, schemeOverride, portOverride);

    private static ContentResult ReturnError(int code, string message)
    {
        var errorResult = new ContentResult();
        errorResult.Content = message;
        errorResult.ContentType = MediaTypeNames.Text.Plain;
        errorResult.StatusCode = code;
        return errorResult;
    }

    // Returns the rendered auth page as HTML with defensive response headers. The page carries the
    // one-time state token / signed assertion and completes the login from an inline script, so it
    // must not be framed (clickjacking), MIME-sniffed, cached, or leak its URL via Referer. A strict
    // Content-Security-Policy locks it to a single nonce'd inline script and style and same-origin
    // fetch/frame; the same per-response nonce is threaded into the rendered page via the delegate.
    private ContentResult HtmlAuthPage(Func<string, string> render)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        Response.Headers.ContentSecurityPolicy = AuthPageCsp.Build(nonce);
        Response.Headers["X-Frame-Options"] = "DENY";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers.CacheControl = "no-store";
        return Content(render(nonce), MediaTypeNames.Text.Html);
    }

    // The two discovery-document facts the challenge reads in one fetch: PKCE-S256 support (#141) — true
    // when advertised, false when the document was read but does not advertise it, null when it could not
    // be fetched/read — and whether the AS advertises the RFC 9207 response-`iss` parameter (#210), which
    // is tolerant (false) whenever the document could not be read so an unreadable flag never locks out a
    // provider that omits `iss`.
    private readonly record struct DiscoveryFacts(bool? PkceS256, bool ResponseIssuerAdvertised);
}

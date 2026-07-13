using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Mime;
using System.Net.Sockets;
using System.Reflection;
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
    // Client-facing error messages: unresolved provider names, and the generic denial for any
    // rejected login (deliberately uniform so the response does not reveal why it was rejected).
    private const string NoMatchingProviderMessage = "No matching provider found";
    private const string ProviderDoesNotExistMessage = "Provider does not exist";
    private const string PermissionDeniedMessage = "Error. Check permissions.";

    // Display names for the audit log (the internal link-map mode tokens are the lowercase "oid"/"saml").
    private const string OpenIdProtocol = "OpenID";
    private const string SamlProtocol = "SAML";

    // An approximate ceiling on outstanding OpenID authorize states, so an anonymous challenge flood cannot
    // grow the store without bound (mirrors SamlRequestCache); at the cap a fresh challenge is refused rather
    // than evicting an in-flight state, and rate-limiting at the edge (#128) is the primary defense (#246).
    private const int MaxStateEntries = 100_000;

    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly IAuthorizationContext _authContext;
    private readonly ILogger<SSOController> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly IProviderManager _providerManager;
    private readonly IServerConfigurationManager _serverConfigurationManager;
    private readonly IHttpClientFactory _httpClientFactory;
    // Concurrent requests add to, enumerate, and prune this map (OidChallenge / OidAuth /
    // OidLink / Invalidate); a plain Dictionary corrupts or throws under that interleaving.
    private static readonly ConcurrentDictionary<string, TimedAuthorizeState> StateManager = new ConcurrentDictionary<string, TimedAuthorizeState>();

    // How long an in-flight OpenID authorize state may live before it is rejected/pruned. This now
    // bounds the whole interactive leg (OidChallenge -> IdP login/MFA/consent -> callback -> mint),
    // so it must accommodate a real user completing MFA, not just a fast round trip.
    private static readonly TimeSpan StateLifetime = TimeSpan.FromMinutes(15);

    // The expired-state sweep (Invalidate) is an O(n) scan; throttling it to at most once per this interval
    // stops an anonymous challenge flood from amplifying into CPU load (mirrors SamlRequestCache). This only
    // defers memory reclamation — IsCurrentFor/IsRedeemableBy reject an expired state independently, so a
    // not-yet-swept entry never grants a login (#246).
    private static readonly TimeSpan StatePruneInterval = TimeSpan.FromMinutes(1);

    // Throttles that sweep to one run per StatePruneInterval; the gate owns the atomic cursor. See Invalidate.
    private static readonly IntervalGate StatePruneGate = new(StatePruneInterval);

    // One-time-use tracking for consumed SAML assertion IDs (replay protection).
    private static readonly SamlReplayCache SamlReplays = new SamlReplayCache();

    // Outstanding SAML AuthnRequest IDs, for InResponseTo correlation of solicited responses (#156).
    private static readonly SamlRequestCache SamlRequests = new SamlRequestCache();

    // Cache of per-discovery-URL PKCE-S256 support (#141), so a login does not fetch discovery every time
    // (the document changes rarely). Only definitive results are cached; a fetch failure is not cached, so
    // it retries on the next login. The short TTL bounds how long a provider's changed support is stale.
    private static readonly ConcurrentDictionary<string, (bool Supported, DateTime FetchedAt)> PkceSupportCache = new();
    private static readonly TimeSpan PkceSupportCacheTtl = TimeSpan.FromMinutes(15);

    // How long an issued SAML AuthnRequest ID stays valid for correlation — the interactive leg
    // (challenge -> IdP login/MFA -> POST back -> mint), matching the OpenID StateLifetime.
    private static readonly TimeSpan SamlRequestLifetime = TimeSpan.FromMinutes(15);

    // Opt-in per-client rate limiter over the anonymous SSO flow endpoints (#128).
    private static readonly SsoRateLimiter RateLimiter = new SsoRateLimiter();

    // Single canonical User-Agent for the plugin's outbound HTTP (discovery, avatar fetch),
    // computed once since the assembly version does not change at runtime.
    private static readonly string UserAgentString =
        $"Jellyfin-Plugin-SSO-Auth +{System.Diagnostics.FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).FileVersion} (https://github.com/iderex/jellyfin-plugin-sso)";

    // Atomic cursor for throttling the capacity-full warning (#246, CWE-400): under a flood every refused
    // challenge would otherwise emit a warning, amplifying the flood into unbounded log volume. Warn at
    // most once per StatePruneInterval.
    private static long _lastCapWarnTicks = DateTime.MinValue.Ticks;

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
        _sessionManager = sessionManager;
        _userManager = userManager;
        _authContext = authContext;
        _cryptoProvider = cryptoProvider;
        _logger = logger;
        _loggerFactory = loggerFactory;
        _providerManager = providerManager;
        _serverConfigurationManager = serverConfigurationManager;
        _httpClientFactory = httpClientFactory;
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

        var config = FindOidConfig(provider);
        if (config is null)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        if (config.Enabled)
        {
            if (string.IsNullOrEmpty(state))
            {
                return BadRequest("Missing state");
            }

            if (!StateManager.TryGetValue(state, out var timedState)
                || !AuthStateStore.IsCurrentFor(timedState, provider, DateTime.Now, StateLifetime))
            {
                // Unknown, expired, or minted for a different provider — reject so a state issued
                // for one provider cannot be validated on another's callback. (No removal: the value
                // is an unguessable CSPRNG token, and expiry pruning is handled by the sweep.)
                return BadRequest("Invalid or expired state");
            }

            var oidcClient = CreateCallbackOidcClient(config, provider);
            var currentState = timedState.State;
            var result = await oidcClient.ProcessResponseAsync(Request.QueryString.Value, currentState).ConfigureAwait(false);

            if (result.IsError)
            {
                return ReturnError(StatusCodes.Status400BadRequest, $"Error logging in: {result.Error} - {result.ErrorDescription}");
            }

            // RFC 9207 (#125): the library parses the authorization-response `iss` but never checks it.
            // When present it must name the same issuer as the redeemed id_token (which OidcIdTokenValidator
            // already validated against the discovery issuer); a mismatch means the response came from a
            // different authorization server than the one we hold a token for — a mix-up — so reject.
            if (!config.DoNotValidateResponseIssuer
                && OidcResponseIssuer.IsMismatch(Request.Query["iss"], result.IdentityToken))
            {
                _logger.LogWarning("OpenID login denied for provider {Provider}: the authorization-response issuer did not match the id_token issuer (RFC 9207 mix-up check).", provider?.ReplaceLineEndings(string.Empty));
                return ReturnError(StatusCodes.Status400BadRequest, "SSO response validation failed");
            }

            // Derive the authorize-state values (username, validity, admin, Live TV, folders, avatar)
            // from the verified login's claims and the provider configuration, then apply them to the
            // fresh authorize state (its derivation fields are still at their defaults at this point).
            var derived = OidcAuthorizeStateBuilder.Build(result.User.Claims, config);

            // Fail closed (#155): a valid OpenID login must resolve a stable subject to key the account
            // link on. sub is an OIDC Core MUST and (post-#134) the id_token validator has verified the
            // token, so a missing sub means a non-conformant provider — reject rather than fall back to
            // keying on the mutable username.
            if (derived.Valid && string.IsNullOrWhiteSpace(derived.Subject))
            {
                _logger.LogWarning("OpenID login denied for provider {Provider}: the id_token carried no 'sub' claim to key the account link on.", provider?.ReplaceLineEndings(string.Empty));
                return ReturnError(StatusCodes.Status401Unauthorized, PermissionDeniedMessage);
            }

            timedState.Username = derived.Username;
            timedState.Subject = derived.Subject;
            timedState.Valid = derived.Valid;
            timedState.Admin = derived.Admin;
            timedState.EnableLiveTv = derived.EnableLiveTv;
            timedState.EnableLiveTvManagement = derived.EnableLiveTvManagement;
            timedState.Folders = derived.Folders;
            timedState.AvatarURL = derived.AvatarUrl;

            bool isLinking = timedState.IsLinking;

            if (timedState.Valid)
            {
                _logger.LogInformation("Is request linking: {IsLinking}", isLinking);
                return HtmlAuthPage(nonce => WebResponse.Generator(data: state, provider: provider, baseUrl: GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride), mode: "OID", nonce: nonce, isLinking: isLinking));
            }
            else
            {
                _logger.LogWarning(
                    "OpenID login denied for {Username}: no role matched the allow-list, or the login resolved no username. Claims: {@Claims}. Roles expected (any one of): {@ExpectedClaims}",
                    timedState.Username?.ReplaceLineEndings(string.Empty),
                    result.User.Claims.Select(o => new { Type = o.Type?.ReplaceLineEndings(string.Empty), Value = o.Value?.ReplaceLineEndings(string.Empty) }),
                    config.Roles);

                return ReturnError(StatusCodes.Status401Unauthorized, PermissionDeniedMessage);
            }
        }

        // If the config doesn't have an active provider matching the request, show an error
        return BadRequest(NoMatchingProviderMessage);
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

        Invalidate();
        var config = FindOidConfig(provider) ?? throw new ArgumentException(ProviderDoesNotExistMessage);

        if (config.Enabled)
        {
            // RFC 9700 §2.1.1: confirm the authorization server advertises PKCE (S256) before relying on
            // it. OidcClient sends code_challenge unconditionally but never checks this, so a server that
            // ignores PKCE would silently downgrade authorization-code-injection protection (#141). Fail
            // closed when the provider is marked RequirePkce; otherwise emit an audit warning and proceed.
            var pkceSupported = await ProviderAdvertisesPkceS256Async(config, provider).ConfigureAwait(false);
            if (pkceSupported == false)
            {
                if (config.RequirePkce)
                {
                    _logger.LogWarning("OpenID login refused for provider {Provider}: RequirePkce is set but the authorization server does not advertise PKCE (S256).", provider?.ReplaceLineEndings(string.Empty));
                    return ReturnError(StatusCodes.Status400BadRequest, "The identity provider does not advertise the required PKCE (S256) support.");
                }

                SsoAudit.PkceNotAdvertised(_logger, provider);
            }
            else if (pkceSupported is null && config.RequirePkce)
            {
                _logger.LogWarning("OpenID login refused for provider {Provider}: RequirePkce is set but the discovery document could not be read to confirm PKCE (S256).", provider?.ReplaceLineEndings(string.Empty));
                return ReturnError(StatusCodes.Status400BadRequest, "The identity provider's PKCE (S256) support could not be verified.");
            }

            bool newPath = ResolveChallengeNewPath(config.NewPath, isLinking, value => config.NewPath = value);

            string redirectUri = GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride) + $"/sso/OID/{(newPath ? "redirect" : "r")}/" + provider;

            var oidcClient = CreateOidcClient(config, redirectUri, string.Join(" ", config.OidScopes.Prepend("openid profile")));
            var state = await oidcClient.PrepareLoginAsync().ConfigureAwait(false);

            if (state.IsError)
            {
                return ReturnError(StatusCodes.Status400BadRequest, $"Error preparing login: {state.Error} - {state.ErrorDescription}");
            }

            // IsLinking tracks whether this is a linking request rather than a login. The state value
            // is a fresh CSPRNG token, so a collision is effectively impossible; log if it ever occurs
            // instead of silently proceeding to a callback that would then fail with "invalid state".
            if (!AuthStateStore.TryAdd(StateManager, state.State, new TimedAuthorizeState(state, DateTime.Now) { IsLinking = isLinking, Provider = provider }, MaxStateEntries))
            {
                // The state value is a CSPRNG token, so a collision is effectively impossible; a refusal
                // here is almost always the capacity backstop under a flood. Throttle the warning to at
                // most once per interval so the flood cannot amplify into unbounded log volume (#246).
                var warnNow = DateTime.Now.Ticks;
                var lastWarn = Interlocked.Read(ref _lastCapWarnTicks);
                if (warnNow >= lastWarn
                    && warnNow - lastWarn >= StatePruneInterval.Ticks
                    && Interlocked.CompareExchange(ref _lastCapWarnTicks, warnNow, lastWarn) == lastWarn)
                {
                    _logger.LogWarning("OpenID authorize state refused for provider {Provider}: a CSPRNG-token collision (effectively impossible) or the store is at capacity (warning throttled).", provider?.ReplaceLineEndings(string.Empty));
                }

                return ReturnError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
            }

            return Redirect(state.StartUrl);
        }

        throw new ArgumentException(ProviderDoesNotExistMessage);
    }

    // Test-only reset of the process-wide OpenID caches this controller keeps as private statics: the
    // in-flight authorize-state store and the PKCE-discovery cache. A test that drives the login flow
    // mutates these, so without a reset the state leaks into a sibling test in the same non-parallel
    // collection. The other static caches are deliberately not cleared here: the SAML replay/request
    // caches key on random IDs and the rate limiter is isolated by per-test client IP, so they cannot
    // bleed between tests. Internal and reachable only through InternalsVisibleTo; it is never wired to
    // an endpoint or DI, so it adds no runtime or security surface. Callback/challenge coverage relies
    // on it for isolation (#289).
    internal static void ResetOidStateForTests()
    {
        StateManager.Clear();
        PkceSupportCache.Clear();
    }

    // Test-only seed of a single authorize-state entry so a test can exercise the OidAuth callback
    // (which consumes an already-validated state that the browser redirect leg normally populates)
    // without standing up the full token-exchange flow. Same test-only surface as ResetOidStateForTests
    // (internal, InternalsVisibleTo, no endpoint/DI) — never reachable in production.
    internal static void SeedOidStateForTests(string token, TimedAuthorizeState state)
    {
        StateManager[token] = state;
    }

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

        var newPath = Request.Path.Value.Contains("/start/", StringComparison.InvariantCultureIgnoreCase);
        record(newPath);
        return newPath;
    }

    // Builds the OidcClient that both the challenge and the callback use. Pure mechanical assembly:
    // the redirect URI and the scope string are the only two inputs the endpoints derive differently,
    // so the caller supplies them. Constructed in the same order as before the extraction, so a null
    // OidEndpoint still fails at the same point (the Uri constructor, after the options object).
    private OidcClient CreateOidcClient(OidConfig config, string redirectUri, string scope)
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
            HttpClientFactory = o =>
            {
                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgentString);
                return client;
            }
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
        return new OidcClient(options);
    }

    // Fetches the provider's OpenID discovery document and reports whether it advertises PKCE S256 (#141):
    // true when advertised, false when the document was read but does not advertise it, null when it could
    // not be fetched/read. The discovery URL is the admin-configured authority + the well-known path (the
    // same document OidcClient uses); the fetch is bounded by a timeout and never throws — a transient
    // failure returns null so the caller decides (fail closed only under RequirePkce). Best-effort: this
    // does not replace OidcClient's own discovery, which fails the login if the provider is truly down.
    private async Task<bool?> ProviderAdvertisesPkceS256Async(OidConfig config, string provider)
    {
        var authority = config.OidEndpoint?.Trim();
        if (string.IsNullOrEmpty(authority) || !Uri.TryCreate(authority, UriKind.Absolute, out _))
        {
            return null;
        }

        // OidEndpoint is usually the issuer/authority, but some providers (e.g. PocketID) configure the
        // full .well-known URL; append the discovery path only when it is not already present, matching how
        // OidcClient resolves the same document.
        var trimmed = authority.TrimEnd('/');
        var discoveryUrl = trimmed.EndsWith("/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase)
            ? trimmed
            : trimmed + "/.well-known/openid-configuration";

        if (PkceSupportCache.TryGetValue(discoveryUrl, out var cached) && DateTime.UtcNow - cached.FetchedAt < PkceSupportCacheTtl)
        {
            return cached.Supported;
        }

        try
        {
            using var client = _httpClientFactory.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(10);
            client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgentString);
            var json = await client.GetStringAsync(discoveryUrl).ConfigureAwait(false);
            var supported = PkceDiscovery.SupportsS256(json);
            PkceSupportCache[discoveryUrl] = (supported, DateTime.UtcNow);
            return supported;
        }
        catch (Exception e)
        {
            _logger.LogWarning(
                e,
                "Could not fetch the OpenID discovery document for provider {Provider} to verify PKCE support; proceeding unless RequirePkce is set.",
                provider?.ReplaceLineEndings(string.Empty));
            return null;
        }
    }

    // Callback-side client: the redirect URI is rebuilt from the callback's own route (the IdP calls
    // back on exactly the route the authorization request advertised), so the token request's
    // redirect_uri matches the authorization request's as RFC 6749 requires (#98). A null scopes
    // array is tolerated here but not on the challenge side — a pre-existing asymmetry deliberately
    // preserved.
    private OidcClient CreateCallbackOidcClient(OidConfig config, string provider)
    {
        var scopes = config.OidScopes == null ? new string[2] : config.OidScopes;
        var redirectUri = GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride) + $"/sso/OID/{OidcCallbackPath.RedirectSegment(Request.Path.Value)}/" + provider;
        return CreateOidcClient(config, redirectUri, string.Join(" ", scopes.Prepend("openid profile")));
    }

    // Rejects a malformed canonical base-URL override (#139) at the OID/SAML Add endpoints. These persist
    // through MutateConfiguration, which passes the live configuration object, so they bypass the
    // config-page save-time validation in SSOPlugin.UpdateConfiguration (which only runs for a fresh
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
    // SSOPlugin.ValidateSamlCertificates. Without this, a garbage certificate set via the Add API would be
    // persisted and then throw a CryptographicException on every callback (an unhandled 500). Blank is
    // valid (a half-configured provider).
    internal static void RejectInvalidSamlCertificate(string certificateStr)
    {
        if (SamlCertificate.IsInvalid(certificateStr))
        {
            throw new ArgumentException("The SAML signing certificate must be a Base64-encoded (DER) X.509 certificate, or left blank.");
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
        RejectInvalidBaseUrlOverride(config?.BaseUrlOverride);
        SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            // Re-inject the server-managed fields this API cannot carry: CanonicalLinks is
            // [JsonIgnore] so the posted config never has them (#157), and the write-only secret
            // follows the same blank-means-keep rule as the config-page save (#189), centralized in
            // ResolveUpdatedSecret so both paths agree on rotation and identity-change behavior.
            if (config != null && configuration.OidConfigs.TryGetValue(provider, out var existing))
            {
                config.CanonicalLinks = existing.CanonicalLinks;
                config.OidSecret = SSOPlugin.ResolveUpdatedSecret(config, existing);
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
        // Project to a non-secret summary. The raw store holds the authorize-state token and the
        // PKCE code_verifier / nonce; those must never be serialized out, even to an admin.
        var summary = StateManager.Values.Select(s => new
        {
            s.Provider,
            s.Created,
            s.Valid,
            s.IsLinking,
        });
        return Ok(summary);
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

        var config = FindOidConfig(provider);
        if (config is null)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        // The store is keyed by the authorize-state token, which is exactly response.Data, so look it
        // up directly (O(1), no full-store scan) and atomically claim it with TryRemove(KeyValuePair):
        // only the request that wins the removal proceeds, so one state mints at most one session even
        // under concurrent posts.
        if (config.Enabled
            && StateManager.TryGetValue(response.Data, out var timedState)
            && AuthStateStore.IsRedeemableBy(timedState, response.Data, provider, DateTime.Now, StateLifetime)
            && StateManager.TryRemove(new KeyValuePair<string, TimedAuthorizeState>(response.Data, timedState)))
        {
            Guid userId;
            try
            {
                userId = await CreateCanonicalLinkAndUserIfNotExist("oid", provider, timedState.Subject, timedState.Username, config.AllowExistingAccountLink).ConfigureAwait(false);
            }
            catch (AccountLinkForbiddenException)
            {
                return StatusCode(StatusCodes.Status403Forbidden, "SSO login is not permitted for this account.");
            }

            var authenticationResult = await Authenticate(new SessionParameters
            {
                UserId = userId,
                IsAdmin = timedState.Admin,
                EnableAuthorization = config.EnableAuthorization,
                EnableAllFolders = config.EnableAllFolders,
                EnabledFolders = timedState.Folders.ToArray(),
                EnableLiveTv = timedState.EnableLiveTv,
                EnableLiveTvManagement = timedState.EnableLiveTvManagement,
                AuthResponse = response,
                DefaultProvider = config.DefaultProvider?.Trim(),
                AvatarUrl = timedState.AvatarURL,
            }).ConfigureAwait(false);
            SsoAudit.LoginSucceeded(_logger, OpenIdProtocol, provider, timedState.Username, timedState.Admin);
            return Ok(authenticationResult);
        }

        return Problem("Something went wrong");
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

        var config = FindSamlConfig(provider);
        if (config is null)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        bool isLinking = string.Equals(relayState, "linking", StringComparison.Ordinal);

        // relayState is attacker-controllable; strip line endings inline at the log call to prevent
        // log forging (structured logging alone does not sanitize a newline-bearing value).
        _logger.LogInformation(
            "SAML request has relayState of {RelayState}",
            relayState?.ReplaceLineEndings(string.Empty));

        if (config.Enabled)
        {
            // Bind SAMLResponse via [FromForm] rather than reading Request.Form directly: a non-form
            // content-type binds null (the form value provider is skipped, so Request.Form is never
            // touched and cannot throw the InvalidOperationException that escaped as a 500, #206), and a
            // null body is rejected the same way as any other malformed response — a clean 400.
            if (!SamlResponseLoader.TryParse(config.SamlCertificate, formSamlResponse, out var samlResponse)
                || !IsSamlResponseValid(samlResponse, config, provider))
            {
                // A malformed response (non-base64, malformed XML, prohibited DOCTYPE) fails TryLoad and
                // is rejected the same way an invalid one is — a clean 4xx, never an unhandled 500 (#199).
                return ReturnError(StatusCodes.Status400BadRequest, "SAML response validation failed");
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
            return ReturnError(StatusCodes.Status401Unauthorized, PermissionDeniedMessage);
        }

        return ReturnError(StatusCodes.Status400BadRequest, "No active providers found");
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

        var config = FindSamlConfig(provider) ?? throw new ArgumentException(ProviderDoesNotExistMessage);

        if (config.Enabled)
        {
            bool newPath = ResolveChallengeNewPath(config.NewPath, isLinking, value => config.NewPath = value);

            string redirectUri = GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride) + $"/sso/SAML/{(newPath ? "post" : "p")}/" + provider;
            string relayState = null;
            if (isLinking)
            {
                relayState = "linking";
            }

            var request = new SamlAuthnRequest(
                config.SamlClientId.Trim(),
                redirectUri);

            // Solicited-only mode (#156): remember the request ID so the callback can require the
            // response's InResponseTo to match a request we actually issued. Scoped by provider so
            // two providers' request IDs cannot satisfy each other's correlation. Only for login
            // flows — the linking callback (SamlLink) does not consume InResponseTo, so registering a
            // linking request would only leave an id to expire unused.
            if (config.ValidateInResponseTo && !isLinking)
            {
                SamlRequests.Register(ProviderScopedKey.For(provider, request.Id), DateTime.UtcNow + SamlRequestLifetime, DateTime.UtcNow);
            }

            return Redirect(request.GetRedirectUrl(config.SamlEndpoint.Trim(), relayState));
        }

        throw new ArgumentException(ProviderDoesNotExistMessage);
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
        RejectInvalidBaseUrlOverride(newConfig?.BaseUrlOverride);
        RejectInvalidSamlCertificate(newConfig?.SamlCertificate);
        SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            // Preserve the server-managed canonical links (#157), as OidAdd does: the posted config
            // never carries them ([JsonIgnore]), so re-inject the live map before the wholesale
            // replace so an API save cannot wipe existing account links.
            if (newConfig != null && configuration.SamlConfigs.TryGetValue(provider, out var existing))
            {
                newConfig.CanonicalLinks = existing.CanonicalLinks;
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

        var config = FindSamlConfig(provider);
        if (config is null)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        if (config.Enabled)
        {
            if (!SamlResponseLoader.TryParse(config.SamlCertificate, response?.Data, out var samlResponse)
                || !IsSamlResponseValid(samlResponse, config, provider))
            {
                // Malformed input is rejected the same way an invalid response is — clean 4xx, not 500 (#199).
                return ReturnError(StatusCodes.Status400BadRequest, "SAML response validation failed");
            }

            // Solicited-only correlation (#156, opt-in): consume the response's InResponseTo against
            // an AuthnRequest this server issued. Enforced here (the session-minting endpoint), like
            // the replay check, so the id is claimed once. An unsolicited (IdP-initiated) response
            // carries no InResponseTo and is refused; a matching id is one-time-use.
            if (config.ValidateInResponseTo)
            {
                var inResponseTo = samlResponse.GetInResponseTo();
                var requestKey = ProviderScopedKey.For(provider, inResponseTo);
                if (!SamlRequests.TryConsume(requestKey, DateTime.UtcNow))
                {
                    _logger.LogWarning("SAML login denied: the response was not solicited by this server (unknown, expired, or already-used InResponseTo).");
                    return Problem("SAML response was not solicited by this server");
                }
            }

            // Enforce the login allow-list here too, not only at the assertion-consumer page: a caller
            // can POST an assertion straight to this session-minting endpoint and skip the page, so
            // checking it only there would be fail-open.
            if (!SamlLoginPolicy.IsLoginAllowed(samlResponse.GetCustomAttributes("Role"), config.Roles))
            {
                _logger.LogWarning(
                    "SAML user: {UserId} has insufficient roles at the session-minting endpoint; login denied.",
                    samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty));
                return ReturnError(StatusCodes.Status401Unauthorized, PermissionDeniedMessage);
            }

            // Enforce one-time use so a captured assertion cannot be replayed to mint another session.
            // Enforced only here (the session-minting endpoint), not at the SAML/post ACS which merely
            // renders the intermediate page, so the two-step post-then-auth flow consumes the id once.
            if (!TryConsumeSamlReplay(samlResponse, provider))
            {
                return Problem("SAML assertion has already been used");
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
                return ReturnError(StatusCodes.Status401Unauthorized, PermissionDeniedMessage);
            }

            Guid userId;
            try
            {
                // SAML keys the link directly on the NameID, which is already the stable subject
                // identifier — key and account name are the same value (no migration path needed).
                userId = await CreateCanonicalLinkAndUserIfNotExist("saml", provider, nameId, nameId, config.AllowExistingAccountLink).ConfigureAwait(false);
            }
            catch (AccountLinkForbiddenException)
            {
                return StatusCode(StatusCodes.Status403Forbidden, "SSO login is not permitted for this account.");
            }

            var authenticationResult = await Authenticate(new SessionParameters
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
            }).ConfigureAwait(false);
            SsoAudit.LoginSucceeded(_logger, SamlProtocol, provider, nameId, derived.Admin);
            return Ok(authenticationResult);
        }

        return Problem("Something went wrong");
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
        var revoked = RemoveCanonicalLinksForUser(user.Id);

        // Switch the account back to the requested auth provider and PERSIST it — the previous version set
        // this in memory only and never called UpdateUserAsync, so the switch was silently discarded.
        user.AuthenticationProviderId = provider;
        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        _logger.LogInformation("Unregistered SSO for user {UserId}: removed {Count} canonical link(s).", user.Id, revoked);

        return Ok();
    }

    // Removes every canonical link pointing at the given user across all SAML and OpenID providers, so an
    // SSO login no longer resolves to the account. Runs under the config lock and returns the number of
    // links removed.
    private static int RemoveCanonicalLinksForUser(Guid userId)
    {
        return SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            int removed = 0;
            foreach (var config in configuration.SamlConfigs.Values)
            {
                removed += CanonicalLinkRevoker.RemoveUser(config.CanonicalLinks, userId);
            }

            foreach (var config in configuration.OidConfigs.Values)
            {
                removed += CanonicalLinkRevoker.RemoveUser(config.CanonicalLinks, userId);
            }

            return removed;
        });
    }

    // Applies a mutation to a provider's canonical-links map on the LIVE configuration. The map is
    // self-healing (CanonicalLinks lazily creates and stores it), so mutating the returned map persists
    // directly. Runs inside MutateConfiguration, so the read-modify-write is serialized and concurrent
    // first-logins cannot lose each other's links.
    private static void MutateLinks(PluginConfiguration configuration, string mode, string provider, Action<SerializableDictionary<string, Guid>> mutate)
    {
        mutate(GetLinks(configuration, mode, provider));
    }

    // The provider's canonical-links map; callers must hold the config lock (ReadConfiguration /
    // MutateConfiguration) while touching it.
    private static SerializableDictionary<string, Guid> GetLinks(PluginConfiguration configuration, string mode, string provider)
    {
        return mode.ToLowerInvariant() switch
        {
            "saml" => configuration.SamlConfigs[provider].CanonicalLinks,
            "oid" => configuration.OidConfigs[provider].CanonicalLinks,
            _ => throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'"),
        };
    }

    private async Task<Guid> CreateCanonicalLinkAndUserIfNotExist(string mode, string provider, string canonicalKey, string username, bool allowExistingAccountLink)
    {
        // Defense in depth (#95, #155): a login that resolved no stable identity key (OpenID sub /
        // SAML NameID) or no username must never create, adopt, or look up an account. Both callbacks
        // reject such logins before calling here; this belt keeps the invariant if a caller forgets.
        if (string.IsNullOrWhiteSpace(canonicalKey) || string.IsNullOrWhiteSpace(username))
        {
            throw new AccountLinkForbiddenException("The SSO login did not resolve an identity; refusing to create or link an account.");
        }

        // The link is keyed on the stable identity. A legacy OpenID link (#155) was keyed on the
        // mutable username instead; when no subject-keyed link exists yet but a legacy one resolves,
        // adopt and re-key it — the one login that migrates reuses the exact decision the old
        // name-keyed lookup would have made, then locks it to the subject so a later provider-side
        // rename cannot detach it. Only OpenID differs key from name; SAML passes key == name.
        // Both candidates are read in ONE pass under the config lock: with separate reads, a
        // concurrent login's migration could commit between them, so this login would see the subject
        // key before the re-key and the legacy key after it, resolve neither, and bounce a legitimate
        // user off the adoption gate with a spurious 403. A link whose target user was deleted counts
        // as absent (dangling links are dead, not identities).
        var (subjectLink, legacyLink) = SSOPlugin.Instance.ReadConfiguration(configuration =>
        {
            var links = GetLinks(configuration, mode, provider);
            Guid? bySubject = links.TryGetValue(canonicalKey, out var s) && _userManager.GetUserById(s) != null
                ? s : null;
            Guid? byName = bySubject is null
                && !string.Equals(canonicalKey, username, StringComparison.Ordinal)
                && links.TryGetValue(username, out var n) && _userManager.GetUserById(n) != null
                ? n : (Guid?)null;
            return (bySubject, byName);
        });

        var (linkedUserId, migrateLegacy) = AccountLinkResolver.ResolveCanonicalLink(subjectLink, legacyLink);
        if (migrateLegacy)
        {
            MigrateCanonicalLinkKey(mode, provider, username, canonicalKey);
            _logger.LogInformation(
                "Migrated {Mode}/{Provider} canonical link from the legacy username key to the stable subject key.",
                mode,
                provider?.ReplaceLineEndings(string.Empty));
        }

        // Adoption of a pre-existing unlinked account still matches on the display name.
        Guid? existingAccountUserId = _userManager.GetUserByName(username)?.Id;

        var decision = AccountLinkResolver.Resolve(linkedUserId, existingAccountUserId, allowExistingAccountLink);
        switch (decision.Action)
        {
            case AccountLinkAction.UseExistingLink:
                return decision.UserId;

            case AccountLinkAction.AdoptExistingAccount:
            {
                // Atomic check-then-link (#133): if a concurrent first-login already linked this
                // identity, that winner is used and no second write or duplicate audit occurs.
                var (adoptedUserId, wrote) = LinkCanonicalIfAbsent(mode, provider, canonicalKey, decision.UserId);
                if (wrote)
                {
                    SsoAudit.AccountAdopted(_logger, string.Equals(mode, "oid", StringComparison.Ordinal) ? OpenIdProtocol : SamlProtocol, provider, username);
                }

                return adoptedUserId;
            }

            case AccountLinkAction.CreateNewAccount:
            {
                _logger.LogInformation("SSO user {Name} doesn't exist, creating...", username.ReplaceLineEndings(string.Empty));
                var user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
                user.AuthenticationProviderId = GetType().FullName;
                // https://jonathancrozier.com/blog/how-to-generate-a-cryptographically-secure-random-string-in-dot-net-with-c-sharp
                user.Password = _cryptoProvider.CreatePasswordHash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))).ToString();

                // Atomic check-then-link (#133): if a concurrent first-login for the same identity
                // linked meanwhile, use its account — this freshly created user is left unlinked rather
                // than overwriting the winner's link (a rare, benign orphan, not a duplicate login).
                var (effectiveUserId, _) = LinkCanonicalIfAbsent(mode, provider, canonicalKey, user.Id);
                return effectiveUserId;
            }

            case AccountLinkAction.RejectNameTaken:
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: a pre-existing unlinked Jellyfin account exists and AllowExistingAccountLink is disabled for this provider.",
                    username.ReplaceLineEndings(string.Empty),
                    mode,
                    provider?.ReplaceLineEndings(string.Empty));
                throw new AccountLinkForbiddenException();

            default:
                throw new InvalidOperationException($"Unhandled account-link action: {decision.Action}");
        }
    }

    // Atomically links canonicalKey to candidateUserId unless a live link already exists for it (#133).
    // The existence check and the write are ONE MutateConfiguration read-modify-write, so two concurrent
    // first-logins for the same identity cannot both write or both adopt: the loser observes the
    // winner's link and reports WroteLink=false (so the caller does not re-emit the adoption audit).
    // The link write goes straight into the config (no discarded ActionResult), so a failure to persist
    // propagates rather than falling through as a successful adoption.
    private (Guid EffectiveUserId, bool WroteLink) LinkCanonicalIfAbsent(string mode, string provider, string canonicalKey, Guid candidateUserId)
    {
        return SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            var links = GetLinks(configuration, mode, provider);
            Guid? existing = links.TryGetValue(canonicalKey, out var current) && _userManager.GetUserById(current) != null
                ? current
                : (Guid?)null;

            var (effectiveUserId, wroteLink) = AccountLinkResolver.ResolveLinkWrite(existing, candidateUserId);
            if (wroteLink)
            {
                links[canonicalKey] = effectiveUserId;
            }

            return (effectiveUserId, wroteLink);
        });
    }

    // Re-keys a canonical link from oldKey to newKey inside the config lock (#155 legacy migration).
    // Idempotent under concurrency: if oldKey is already gone (a concurrent login migrated first) the
    // move is a no-op, and a LIVE newKey entry is never overwritten — only a dangling one (its target
    // user deleted), which would otherwise block the hand-off on every subsequent login.
    private void MigrateCanonicalLinkKey(string mode, string provider, string oldKey, string newKey)
    {
        SSOPlugin.Instance.MutateConfiguration(configuration =>
            MutateLinks(configuration, mode, provider, links =>
            {
                if (links.TryGetValue(oldKey, out var userId)
                    && (!links.TryGetValue(newKey, out var existing) || _userManager.GetUserById(existing) == null))
                {
                    links.Remove(oldKey);
                    links[newKey] = userId;
                }
            }));
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
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId, true).ConfigureAwait(false))
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
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId, true).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Current user is not allowed to unlink SSO providers for user ID.");
        }

        var mismatch = false;
        var found = false;
        try
        {
            SSOPlugin.Instance.MutateConfiguration(configuration => MutateLinks(configuration, mode, provider, links =>
            {
                if (!links.TryGetValue(canonicalName, out var linkedId))
                {
                    return;
                }

                found = true;
                if (linkedId != jellyfinUserId)
                {
                    mismatch = true;
                    return;
                }

                links.Remove(canonicalName);
            }));
        }
        catch (KeyNotFoundException)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        if (!found)
        {
            return NotFound("No SSO link is registered for that canonical name.");
        }

        if (mismatch)
        {
            return StatusCode(StatusCodes.Status409Conflict, "jellyfin UID does not match id registered to that canonical name.");
        }

        return Ok();
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
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId, true).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Non-admin is not allowed to query other user's mappings.");
        }

        return BuildLinksByUser("saml", jellyfinUserId);
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
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId, true).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Non-admin is not allowed to query other user's mappings.");
        }

        return BuildLinksByUser("oid", jellyfinUserId);
    }

    // Builds the provider -> [link keys for this user] map under the config lock, materializing each
    // provider's matches with ToList (#157/F-10). The previous version assigned a deferred LINQ query
    // that enumerated the live CanonicalLinks during JSON serialization — outside any lock — which
    // could tear against a concurrent login writing a link ("collection modified during enumeration").
    private static SerializableDictionary<string, IEnumerable<string>> BuildLinksByUser(string mode, Guid jellyfinUserId)
    {
        return SSOPlugin.Instance.ReadConfiguration(configuration =>
        {
            var providerList = string.Equals(mode, "saml", StringComparison.Ordinal)
                ? (IEnumerable<KeyValuePair<string, SerializableDictionary<string, Guid>>>)configuration.SamlConfigs.Select(p => new KeyValuePair<string, SerializableDictionary<string, Guid>>(p.Key, p.Value.CanonicalLinks))
                : configuration.OidConfigs.Select(p => new KeyValuePair<string, SerializableDictionary<string, Guid>>(p.Key, p.Value.CanonicalLinks));

            var mappings = new SerializableDictionary<string, IEnumerable<string>>();
            foreach (var provider in providerList)
            {
                mappings[provider.Key] = provider.Value
                    .Where(link => link.Value == jellyfinUserId)
                    .Select(link => link.Key)
                    .ToList();
            }

            return mappings;
        });
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
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    private ActionResult SamlLink(string provider, Guid jellyfinUserId, AuthResponse response)
    {
        var config = FindSamlConfig(provider);
        if (config is null)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        if (!SamlResponseLoader.TryParse(config.SamlCertificate, response?.Data, out var samlResponse)
            || !IsSamlResponseValid(samlResponse, config, provider))
        {
            // Malformed input is rejected the same way an invalid response is — clean 4xx, not 500 (#199).
            return ReturnError(StatusCodes.Status400BadRequest, "SAML response validation failed");
        }

        // Enforce one-time use here too (#219): without it, a captured, still-valid assertion could be
        // replayed to bind its NameID to the caller's account. The linking flow issues no AuthnRequest,
        // so InResponseTo is not correlated here — the replay cache is the applicable one-time-use control.
        if (!TryConsumeSamlReplay(samlResponse, provider))
        {
            return Problem("SAML assertion has already been used");
        }

        string providerUserId = samlResponse.GetNameID();

        return CreateCanonicalLink("saml", provider, jellyfinUserId, providerUserId);
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
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    private ActionResult OidLink(string provider, Guid jellyfinUserId, AuthResponse response)
    {
        if (string.IsNullOrEmpty(response?.Data))
        {
            return BadRequest("Missing data");
        }

        if (FindOidConfig(provider) is null)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        // Keyed O(1) lookup + atomic claim (see OidAuth): consume the state so one verified identity
        // cannot be linked repeatedly and cannot then be reused to mint a session.
        if (StateManager.TryGetValue(response.Data, out var timedState)
            && AuthStateStore.IsRedeemableBy(timedState, response.Data, provider, DateTime.Now, StateLifetime)
            && StateManager.TryRemove(new KeyValuePair<string, TimedAuthorizeState>(response.Data, timedState)))
        {
            // Manual linking keys on the stable subject (#155), matching the auto-login path, so a
            // later provider-side rename does not orphan the link the user just created.
            return CreateCanonicalLink("oid", provider, jellyfinUserId, timedState.Subject);
        }

        return Problem("Something went wrong!");
    }

    private ActionResult CreateCanonicalLink(string mode, string provider, Guid jellyfinUserId, string providerUserId)
    {
        // Fail closed (#95), linking-side choke point: an SSO identity that did not resolve must not
        // create a link — a null key would throw inside the config mutation (500), and an empty or
        // whitespace key would persist a dead link no login can ever redeem.
        if (string.IsNullOrWhiteSpace(providerUserId))
        {
            return BadRequest("The SSO login did not resolve an identity.");
        }

        try
        {
            SSOPlugin.Instance.MutateConfiguration(configuration =>
                MutateLinks(configuration, mode, provider, links => links[providerUserId] = jellyfinUserId));
        }
        catch (KeyNotFoundException)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        return NoContent();
    }

    /// <summary>
    /// Mints a Jellyfin session for a resolved SSO login: applies the granted permissions and the
    /// optional avatar/default-provider updates to the user, then authenticates the client.
    /// </summary>
    /// <param name="parameters">The resolved user, granted privileges, and client identity.</param>
    private async Task<AuthenticationResult> Authenticate(SessionParameters parameters)
    {
        User user = _userManager.GetUserById(parameters.UserId);
        if (user is null)
        {
            // Fail closed: the account resolved for this SSO login no longer exists (e.g. it was
            // deleted between resolution and this call), so no session may be minted for it.
            throw new AuthenticationException("SSO authentication aborted: the target user does not exist.");
        }

        if (parameters.EnableAuthorization)
        {
            user.SetPermission(PermissionKind.IsAdministrator, parameters.IsAdmin);
            user.SetPermission(PermissionKind.EnableAllFolders, parameters.EnableAllFolders);
            if (!parameters.EnableAllFolders)
            {
                user.SetPreference(PreferenceKind.EnabledFolders, parameters.EnabledFolders);
            }

            // Live TV access/management are role-derived grants too, so they must respect the same
            // EnableAuthorization master switch. Applied unconditionally they let a provider grant (or
            // silently toggle) Live TV on every login even when the admin turned SSO permission
            // management off (#215).
            user.SetPermission(PermissionKind.EnableLiveTvAccess, parameters.EnableLiveTv);
            user.SetPermission(PermissionKind.EnableLiveTvManagement, parameters.EnableLiveTvManagement);
        }

        await TrySetUserAvatarAsync(user, parameters.AvatarUrl).ConfigureAwait(false);

        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        var authRequest = new AuthenticationRequest();
        authRequest.UserId = user.Id;
        authRequest.Username = user.Username;
        authRequest.App = parameters.AuthResponse.AppName;
        authRequest.AppVersion = parameters.AuthResponse.AppVersion;
        authRequest.DeviceId = parameters.AuthResponse.DeviceID;
        authRequest.DeviceName = parameters.AuthResponse.DeviceName;

        // Record the client IP so the SSO login shows a source address in Jellyfin's activity log,
        // exactly as password logins do (#177): use Jellyfin's own GetNormalizedRemoteIP, the very
        // helper its built-in login path uses. It reads the already-resolved connection address (so
        // the plugin adds no proxy-trust logic of its own — the server's "Known proxies" setting
        // governs it) and normalizes it the same way (IPv4-mapped IPv6 collapsed to IPv4), so the
        // SSO entry's source address matches a password entry's for the same client byte-for-byte.
        authRequest.RemoteEndPoint = HttpContext.GetNormalizedRemoteIP().ToString();
        _logger.LogInformation("Auth request created...");
        if (!string.IsNullOrEmpty(parameters.DefaultProvider))
        {
            user.AuthenticationProviderId = parameters.DefaultProvider;
            await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
            _logger.LogInformation("Set default login provider to {DefaultProvider}", parameters.DefaultProvider);
        }

        return await _sessionManager.AuthenticateDirect(authRequest).ConfigureAwait(false);
    }

    // Fetches the avatar and sets it as the user's profile image. Best-effort by design: any fetch or
    // save failure is logged and the login proceeds without the avatar; only the URL guard and the
    // SSRF-safe transport are security-relevant, and they fail closed (no fetch).
    private async Task TrySetUserAvatarAsync(User user, string avatarUrl)
    {
        if (avatarUrl is null)
        {
            return;
        }

        if (!AvatarUrlValidator.IsAllowedUrl(avatarUrl, out var avatarUri))
        {
            _logger.LogWarning("Refusing to fetch avatar from disallowed URL: {AvatarUrl}", avatarUrl.ReplaceLineEndings(string.Empty));
            return;
        }

        try
        {
            // Route every connection (including redirect targets) through a callback that rejects
            // private/loopback addresses, closing the SSRF and DNS-rebinding vectors. Redirects stay
            // enabled (many avatar URLs redirect) but are bounded, each hop is IP-validated, and both
            // the request and the download are bounded.
            using var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 5,
                ConnectCallback = AvatarConnectCallback,

                // A system proxy would be the connection target, so the ConnectCallback would
                // validate the proxy's address rather than the avatar host's - bypassing the guard.
                UseProxy = false,
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgentString);

            // One deadline for the whole fetch: with ResponseHeadersRead the client Timeout stops
            // applying once the headers arrive, so a malicious endpoint could send headers immediately
            // then trickle the body forever. A single 10s token passed into GetAsync AND every body
            // ReadAsync bounds the header wait and the streamed read together, while keeping the
            // streaming size cap (#220).
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            // ResponseHeadersRead so the body is streamed, not fully buffered, before ReadCappedAsync
            // enforces the size limit; otherwise the cap runs only after the whole download is in memory.
            using var avatarResponse = await client.GetAsync(avatarUri, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            avatarResponse.EnsureSuccessStatusCode();

            // Media types are case-insensitive (RFC 7231); use the parsed type with parameters stripped.
            var mediaType = avatarResponse.Content.Headers.ContentType?.MediaType;

            // Allow only raster image types and derive the stored extension from that allow-list, never
            // from the raw subtype — image/svg+xml is rejected because a stored SVG can carry script (#217).
            if (!AvatarContentType.TryResolveExtension(mediaType, out var extension))
            {
                // Log the rejected type sanitized inline at the log call (mediaType is server-controlled),
                // and keep the thrown/caught exception message generic so no untrusted text reaches the
                // logged exception — mirrors the disallowed-URL warning above.
                _logger.LogWarning("Refusing avatar with disallowed content type: {MediaType}", (mediaType ?? "(none)").ReplaceLineEndings(string.Empty));
                throw new InvalidOperationException("Avatar content type is not an allowed raster image.");
            }

            const long MaxAvatarBytes = 10 * 1024 * 1024;
            if (avatarResponse.Content.Headers.ContentLength > MaxAvatarBytes)
            {
                throw new InvalidOperationException("Avatar exceeds the maximum allowed size.");
            }

            using var stream = await ReadCappedAsync(avatarResponse, MaxAvatarBytes, timeout.Token).ConfigureAwait(false);

            var userDataPath =
                Path.Combine(
                    _serverConfigurationManager.ApplicationPaths.UserConfigurationDirectoryPath,
                    user.Username);
            if (user.ProfileImage is not null)
            {
                await _userManager.ClearProfileImageAsync(user).ConfigureAwait(false);
            }

            user.ProfileImage = new ImageInfo(Path.Combine(userDataPath, "profile" + extension));

            await _providerManager.SaveImage(stream, mediaType, user.ProfileImage.Path)
                .ConfigureAwait(false);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Failed to fetch or save the SSO avatar.");
        }
    }

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

    private static void Invalidate()
    {
        // Throttle the O(n) expired-state sweep to at most once per StatePruneInterval so an anonymous
        // challenge flood does not amplify into CPU load; the gate lets exactly one thread per interval
        // run it (#246). AuthStateStore.InvalidateExpired stays pure/unthrottled — the throttle lives here,
        // at its sole call site. The same captured 'now' drives both the gate and the sweep.
        var now = DateTime.Now;
        if (StatePruneGate.TryEnter(now))
        {
            AuthStateStore.InvalidateExpired(StateManager, now, StateLifetime);
        }
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
    private string[] ExpectedAcsUrls(SamlConfig config, string provider)
    {
        var baseUrl = GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride) + "/sso/SAML/";
        return new[] { baseUrl + "post/" + provider, baseUrl + "p/" + provider };
    }

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

    // Resolves the target host and connects only to a non-blocked (public) address, so a hostname that
    // resolves to an internal address - including via DNS rebinding on a redirect hop - cannot be reached.
    private static async ValueTask<Stream> AvatarConnectCallback(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);

        // Try every non-blocked address in turn (a per-address connect fallback for dual-stack /
        // multi-record hosts, since supplying a ConnectCallback replaces the handler's built-in one),
        // connecting to the validated IP rather than the hostname so a DNS rebind cannot redirect the
        // connection to an internal address.
        Exception lastError = null;
        var attempted = false;
        foreach (var address in addresses)
        {
            if (AvatarUrlValidator.IsBlockedAddress(address))
            {
                continue;
            }

            attempted = true;
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            var connected = false;
            try
            {
                await socket.ConnectAsync(address, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false);
                connected = true;
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                lastError = ex;
            }
            finally
            {
                // Dispose unless ownership passed to the returned NetworkStream. Runs on the
                // cancellation path too, where the catch filter is skipped and the socket would leak.
                if (!connected)
                {
                    socket.Dispose();
                }
            }
        }

        if (attempted)
        {
            throw new HttpRequestException("Could not connect to any allowed address for the avatar host.", lastError);
        }

        throw new HttpRequestException("Avatar host resolves only to blocked addresses.");
    }

    // Copies the response body into memory, aborting if it exceeds the cap, so a hostile endpoint cannot
    // exhaust resources with an unbounded (or Content-Length-lying) download.
    private static async ValueTask<MemoryStream> ReadCappedAsync(HttpResponseMessage response, long maxBytes, CancellationToken cancellationToken)
    {
        var buffer = new MemoryStream();
        var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (source.ConfigureAwait(false))
        {
            var chunk = new byte[81920];
            long total = 0;
            int read;
            while ((read = await source.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
            {
                total += read;
                if (total > maxBytes)
                {
                    await buffer.DisposeAsync().ConfigureAwait(false);
                    throw new InvalidOperationException("Avatar exceeds the maximum allowed size.");
                }

                await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }

        buffer.Position = 0;
        return buffer;
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
}

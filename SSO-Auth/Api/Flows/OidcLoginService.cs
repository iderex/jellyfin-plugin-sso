using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Providers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Flows;

/// <summary>
/// The OpenID login flow, extracted whole off <see cref="SSOController"/> (#160, #318 step 12): the
/// challenge (redirect the browser to the authorization server), the redirect callback (exchange the code,
/// validate the id_token, render the intermediate auth page), the session-minting authenticate leg, and the
/// manual link redeem. The controller's OpenID endpoints are now thin adapters — they apply the shared
/// rate-limit gate and hand the request to this service — so the OpenID-specific protocol logic lives in one
/// flow-tier collaborator rather than inline on the controller.
/// </summary>
/// <remarks>
/// The two OpenID-specific process-wide caches live here as <c>static readonly</c> fields, one instance for
/// the whole process exactly as they were on the controller (a fresh per-request controller reconstructs the
/// service, so an instance field would lose the in-flight state between the challenge and its callback):
/// <list type="bullet">
/// <item>the in-flight authorize-state store (<see cref="OidcStateStore"/>), and</item>
/// <item>the discovery-facts cache (<see cref="OidcDiscoveryCache"/>).</item>
/// </list>
/// The shared per-client rate limiter is deliberately NOT here — it also fronts the SAML flow, so it lives in
/// the shared <see cref="SsoRateLimitGate"/> (Api/Shared) that the controller's endpoints front this service
/// with, rather than as a per-flow static (#160). Because the challenge and
/// callback are irreducibly HTTP (cookies, query string, redirect, the intermediate page), those two methods
/// take the request/response and, for the two response shapes the controller still owns (the security-headered
/// auth page and the manual-link write mapping), a delegate the controller binds — rather than duplicating the
/// controller's <c>ControllerBase</c> result construction here. The mint tail stays HttpContext-free like
/// <see cref="LoginCompletionService"/>: the authenticate leg takes only the redeemed model, the presented
/// binding cookie value, and the remote-endpoint resolver (#177).
/// </remarks>
internal sealed class OidcLoginService
{
    // The in-flight OpenID authorize-state store (cap, lifetime, throttled sweep and capacity signal all
    // live inside; see OidcStateStore). One process-wide instance, like the discovery cache below and the
    // SAML caches the controller keeps.
    private static readonly OidcStateStore StateStore = new();

    // The per-discovery-URL cache of the two facts the challenge reads in one fetch — PKCE-S256 support
    // (#141) and whether the AS advertises the RFC 9207 response-`iss` parameter (#210) — plus the
    // fetch/parse that populates it. One process-wide instance; the TTL, bounding rationale, and tolerant
    // fail-open-only-under-RequirePkce behaviour all live inside OidcDiscoveryCache (#449).
    private static readonly OidcDiscoveryCache DiscoveryCache = new();

    // The shared login-completion tail (#160): resolve/adopt the link, build the session parameters, mint
    // under the revocation gate, audit, map to a LoginOutcome. Both protocols funnel their verified identity
    // into it, so it is a shared collaborator this service holds a reference to rather than owning.
    private readonly LoginCompletionService _loginCompletion;

    // The account-linking workflow (resolve/adopt/create, legacy re-key, revoke). Used here only by the OID
    // manual-link redeem; the controller keeps the authz guards and the HTTP mapping around it (#318).
    private readonly CanonicalLinkService _canonicalLinks;

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger _logger;

    internal OidcLoginService(
        LoginCompletionService loginCompletion,
        CanonicalLinkService canonicalLinks,
        IHttpClientFactory httpClientFactory,
        ILoggerFactory loggerFactory,
        ILogger logger)
    {
        _loginCompletion = loginCompletion ?? throw new ArgumentNullException(nameof(loginCompletion));
        _canonicalLinks = canonicalLinks ?? throw new ArgumentNullException(nameof(canonicalLinks));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>Projects the in-flight authorize states to non-secret summaries for the admin debug endpoint.</summary>
    /// <returns>One redacted summary per in-flight state.</returns>
    internal IEnumerable<OidcStateStore.Summary> StateSummaries() => StateStore.Summaries();

    // Test-only reset of the process-wide OpenID caches this service keeps as statics: the in-flight
    // authorize-state store and the discovery-facts cache. A test that drives the login flow mutates these,
    // so without a reset the state leaks into a sibling test in the same non-parallel collection. Internal
    // and reachable only through InternalsVisibleTo; it is never wired to an endpoint or DI, so it adds no
    // runtime or security surface. Moved here with the statics from the controller (#160, #289).
    internal static void ResetOidStateForTests()
    {
        StateStore.Clear();
        DiscoveryCache.Clear();
    }

    // Test-only seed of a single authorize-state entry so a test can exercise the callback/authenticate legs
    // (which consume an already-validated state that the browser redirect leg normally populates) without
    // standing up the full token-exchange flow. Same test-only surface as ResetOidStateForTests (internal,
    // InternalsVisibleTo, no endpoint/DI) — never reachable in production. Moved here with the statics (#160).
    internal static void SeedOidStateForTests(string token, AuthorizeSession state) => StateStore.Seed(token, state);

    /// <summary>
    /// Initiates the OpenID login flow: prepares the authorization request, registers the in-flight authorize
    /// state, binds it to the initiating browser, and redirects to the identity provider. The controller
    /// applies the shared rate-limit gate before delegating here.
    /// </summary>
    /// <param name="provider">The provider name from the route.</param>
    /// <param name="isLinking">Whether this challenge intends to link an account rather than authenticate.</param>
    /// <param name="request">The current request; read for the base URL, the challenge route spelling, and the client IP.</param>
    /// <param name="response">The response the browser-binding cookie is appended to on a successful registration.</param>
    /// <returns>A redirect to the authorization server, or a fail-closed rejection/error.</returns>
    internal async Task<ActionResult> ChallengeAsync(string provider, bool isLinking, HttpRequest request, HttpResponse response)
    {
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
        var discoveryFacts = await DiscoveryCache.ReadFactsAsync(config, provider, _httpClientFactory, _logger).ConfigureAwait(false);
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

        var newPath = ResolveChallengeNewPath(config, isLinking, request);

        string redirectUri = SsoUrlBuilder.OidRedirectUri(RequestBaseUrl(request, config), newPath, provider);

        var oidcClient = CreateOidcClient(config, redirectUri, BuildScopeString(config));
        var state = await oidcClient.PrepareLoginAsync().ConfigureAwait(false);

        if (state.IsError)
        {
            return FlowResponses.PlainTextError(StatusCodes.Status400BadRequest, $"Error preparing login: {state.Error} - {state.ErrorDescription}");
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
        var clientKey = SsoRateLimiter.NormalizeClientKey(request.HttpContext.Connection.RemoteIpAddress);

        // Build the challenge's authorize state complete — the discovery metadata PrepareLoginAsync just
        // fetched and validated against this provider's DiscoveryPolicy (reused at the callback so
        // ProcessResponseAsync skips a second discovery + JWKS, #247), and whether that discovery
        // advertised the RFC 9207 response-`iss` parameter (so the callback requires `iss`, its absence
        // being a downgrade, #210). Folded in at construction so registration is one atomic insert and the
        // stored Pending is never mutated after it enters the store (#341).
        var pending = new AuthorizeSession.Pending(state, provider, isLinking, DateTime.Now, bindingId, clientKey, oidcClient.Options.ProviderInformation, discoveryFacts.ResponseIssuerAdvertised);
        if (!StateStore.TryAdd(pending, out var shouldWarnCapacity))
        {
            if (shouldWarnCapacity)
            {
                _logger.LogWarning("OpenID authorize state refused for provider {Provider}: a CSPRNG-token collision (effectively impossible) or the store is at capacity (warning throttled).", provider?.ReplaceLineEndings(string.Empty));
            }

            return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
        }

        // Set the cookie only after the state is registered, so a refused challenge leaves no cookie.
        response.Cookies.Append(AuthorizeStateBinding.CookieName, bindingId, AuthorizeStateBinding.CookieOptions(OidcStateStore.DefaultLifetime));

        return new RedirectResult(state.StartUrl);
    }

    /// <summary>
    /// The OpenID redirect callback (a GET; named for consistency with the SAML sibling): validates the
    /// browser-bound authorize state, exchanges the authorization code, validates the id_token and the RFC
    /// 9207 response issuer, applies the role gate, promotes the state to redeemable, and renders the
    /// intermediate auth page. The controller applies the shared rate-limit gate before delegating here.
    /// </summary>
    /// <param name="provider">The provider name from the route.</param>
    /// <param name="state">The authorize-state token the callback presented (also the auth-page data).</param>
    /// <param name="request">The current request; read for the base URL, the callback route, the code-exchange query string, the response `iss`, and the binding cookie.</param>
    /// <param name="response">The response the auth page's defensive headers are written to.</param>
    /// <returns>The rendered auth page on success, or a fail-closed rejection.</returns>
    internal async Task<ActionResult> CallbackAsync(string provider, string state, HttpRequest request, HttpResponse response)
    {
        // Unknown and disabled providers share one rejection so neither can be probed apart, matching
        // the guard-clause form the SAML sibling (SamlPost) already uses.
        var config = FindOidConfig(provider);
        if (config is not { Enabled: true })
        {
            return new BadRequestObjectResult(LoginStatusMapper.NoMatchingProviderMessage);
        }

        if (string.IsNullOrEmpty(state))
        {
            return new BadRequestObjectResult("Missing state");
        }

        if (StateStore.PeekCurrent(state, provider, DateTime.Now, request.Cookies[AuthorizeStateBinding.CookieName]) is not { } pending)
        {
            // Unknown, expired, minted for a different provider, or from a different browser than the
            // one that started the flow (#326) — reject (details on PeekCurrent / AuthorizeStateBinding).
            return new BadRequestObjectResult("Invalid or expired state");
        }

        var oidcClient = CreateCallbackOidcClient(config, provider, request, pending.ProviderInformation);
        var result = await oidcClient.ProcessResponseAsync(request.QueryString.Value, pending.OidcState).ConfigureAwait(false);

        if (result.IsError)
        {
            return FlowResponses.PlainTextError(StatusCodes.Status400BadRequest, $"Error logging in: {result.Error} - {result.ErrorDescription}");
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
            && OidcResponseIssuer.IsRejected(request.Query["iss"], oidcClient.Options.ProviderInformation?.IssuerName, result.IdentityToken, pending.ResponseIssuerRequired))
        {
            _logger.LogWarning("OpenID login denied for provider {Provider}: the authorization-response issuer was absent-but-required or matched neither the discovery issuer nor the id_token issuer (RFC 9207 mix-up check).", provider?.ReplaceLineEndings(string.Empty));
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SsoResponseInvalid));
        }

        // Derive the authorize-state values (username, validity, admin, Live TV, folders, avatar)
        // from the verified login's claims and the provider configuration.
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

        if (!derived.Valid)
        {
            // The role gate did not pass: leave the Pending unpromoted (never redeemable — the redeem
            // requires a Ready) so it simply expires. Checked before Promote so no Ready is ever created
            // for a denied login.
            _logger.LogWarning(
                "OpenID login denied for {Username}: no role matched the allow-list, or the login resolved no username. Claims: {@Claims}. Roles expected (any one of): {@ExpectedClaims}",
                derived.Username?.ReplaceLineEndings(string.Empty),
                result.User.Claims.Select(o => new { Type = o.Type?.ReplaceLineEndings(string.Empty), Value = o.Value?.ReplaceLineEndings(string.Empty) }),
                config.Roles);

            return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
        }

        // Atomically swap the peeked Pending for a redeemable Ready (#341). A false return means a
        // concurrent callback already promoted it, or it expired/was pruned since the peek — either way
        // the browser's redeem is the real gate, which consumes the single Ready once (or cleanly rejects
        // a state that is gone), so the auth page is returned regardless.
        StateStore.Promote(pending, derived);

        _logger.LogInformation("Is request linking: {IsLinking}", pending.IsLinking);
        return FlowResponses.AuthPage(response, nonce => WebResponse.Generator(data: state, provider: provider, baseUrl: RequestBaseUrl(request, config), mode: "OID", nonce: nonce, isLinking: pending.IsLinking));
    }

    /// <summary>
    /// The session-minting authenticate leg: redeems the browser-bound authorize state once, then hands the
    /// verified identity to the shared completion tail. The controller applies the shared rate-limit gate
    /// before delegating and supplies the binding cookie and remote-endpoint resolver.
    /// </summary>
    /// <param name="provider">The provider name from the route.</param>
    /// <param name="response">The client's auth request context (app/device) plus the state token in <c>Data</c>.</param>
    /// <param name="bindingCookie">The browser-binding cookie value the redeem presented (#326).</param>
    /// <param name="remoteEndPointResolver">Resolves the normalized client IP for the activity log (#177).</param>
    /// <returns>The minted session, or a fail-closed rejection.</returns>
    internal async Task<ActionResult> AuthenticateAsync(string provider, AuthResponse response, string bindingCookie, Func<string> remoteEndPointResolver)
    {
        if (string.IsNullOrEmpty(response?.Data))
        {
            return new BadRequestObjectResult("Missing data");
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
        if (StateStore.TryRedeem(response.Data, provider, DateTime.Now, bindingCookie) is not { } redeemed)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.InvalidState));
        }

        // The redeemed state carries the fully-verified identity (#473); the OpenID adoption gate applies
        // the provider's verified-email requirement (#218). From here the OpenID and SAML paths are one.
        return await _loginCompletion.CompleteAsync(
            redeemed.Identity,
            response,
            config,
            new AdoptionGate(config.RequireVerifiedEmailForAdoption, redeemed.Identity.EmailVerified),
            remoteEndPointResolver).ConfigureAwait(false);
    }

    /// <summary>
    /// The OpenID manual-link redeem: consumes the browser-bound authorize state once and creates the
    /// canonical link on the redeemed identity's stable subject. The controller applies the caller-authz
    /// guard before delegating and supplies the write-result-to-HTTP mapping.
    /// </summary>
    /// <param name="provider">The provider to link against.</param>
    /// <param name="jellyfinUserId">The Jellyfin account to link (already authorized by the controller).</param>
    /// <param name="response">The client information carrying the state token in <c>Data</c>.</param>
    /// <param name="bindingCookie">The browser-binding cookie value the redeem presented (#326).</param>
    /// <returns>The link-creation result, or a fail-closed rejection.</returns>
    internal ActionResult Link(string provider, Guid jellyfinUserId, AuthResponse response, string bindingCookie)
    {
        if (string.IsNullOrEmpty(response?.Data))
        {
            return new BadRequestObjectResult("Missing data");
        }

        // A disabled provider must neither create a link nor consume the state (#343), mirroring
        // AuthenticateAsync's short-circuit order: an administrator disabling a provider takes effect for
        // in-flight linking states immediately, not after their 15-minute lifetime. The unknown and
        // disabled cases share one response, so neither can be probed apart (no enumeration oracle).
        if (FindOidConfig(provider) is not { Enabled: true })
        {
            return new BadRequestObjectResult(LoginStatusMapper.NoMatchingProviderMessage);
        }

        // One-time atomic claim (see OidcStateStore.TryRedeem): consume the state so one verified
        // identity cannot be linked repeatedly and cannot then be reused to mint a session. A miss
        // (unknown, expired, provider-mismatched, already-redeemed, or from a different browser than
        // started the flow, #326) is a client-caused 400 in the same uniform body as the login path,
        // not a 500. The linking challenge sets the same binding cookie, carried on this same-origin POST.
        if (StateStore.TryRedeem(response.Data, provider, DateTime.Now, bindingCookie) is not { } redeemed)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.InvalidState));
        }

        // Manual linking keys on the stable subject (#155), matching the auto-login path, so a
        // later provider-side rename does not orphan the link the user just created.
        return FlowResponses.MapCanonicalLinkWrite(_canonicalLinks.TryCreateLink("oid", provider, redeemed.Identity.Subject, jellyfinUserId));
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

    // Reads a provider's config under the config lock, so an anonymous login-path lookup does not race an
    // admin Add/Del mutating the live provider dictionary in place — a Dictionary read-during-write is
    // undefined behaviour in .NET (throw, misread, or a spin on a corrupted chain during a resize) (#252).
    // Returns null for an unknown provider so call sites branch on a null check instead of catching
    // KeyNotFoundException as control flow (#241). An uncontended lock is nanoseconds; it is only held long
    // during a first-login/admin persist, which is exactly when a consistent read matters.
    private static OidConfig FindOidConfig(string provider) =>
        SSOPlugin.Instance.ReadConfiguration(configuration => configuration.OidConfigs.TryGetValue(provider, out var config) ? config : null);

    // Resolves whether this challenge uses the "new", more descriptive redirect path, and records that as
    // server-managed runtime state on the provider config. A non-linking challenge derives the spelling
    // from the request path (a `.../start/...` route means the new path) and stores it, so a later linking
    // flow — which cannot know which redirect path the identity provider has registered — reuses the last
    // login's spelling. A linking challenge only reads the stored value. (See ExpectedAcsUrls for the same
    // reason this value is remembered across requests.) The SAML sibling keeps its own generic resolver on
    // the controller because OidConfig and SamlConfig share no base with a NewPath setter; here the type is
    // known, so the record is a direct assignment.
    private static bool ResolveChallengeNewPath(OidConfig config, bool isLinking, HttpRequest request)
    {
        if (isLinking)
        {
            return config.NewPath;
        }

        var newPath = ChallengePath.IsNewPath(request.Path.Value);
        config.NewPath = newPath;
        return newPath;
    }

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

    // Callback-side client: the redirect URI is rebuilt from the callback's own route (the IdP calls
    // back on exactly the route the authorization request advertised), so the token request's
    // redirect_uri matches the authorization request's as RFC 6749 requires (#98). The scope string
    // is normalized the same way as the challenge side (BuildScopeString) — both tolerate a null
    // OidScopes identically (#368).
    private OidcClient CreateCallbackOidcClient(OidConfig config, string provider, HttpRequest request, ProviderInformation providerInformation)
    {
        var redirectUri = SsoUrlBuilder.OidCallbackRedirectUri(RequestBaseUrl(request, config), request.Path.Value, provider);
        return CreateOidcClient(config, redirectUri, BuildScopeString(config), providerInformation);
    }

    // Resolves the canonical base URL from the live request and the provider's overrides — the same pure
    // CanonicalBaseUrl.Resolve decision (#242) SamlLoginService.GetRequestBase feeds for SAML. Kept as a
    // thin local read so this flow tier is self-contained.
    private static string RequestBaseUrl(HttpRequest request, OidConfig config) =>
        CanonicalBaseUrl.Resolve(config.BaseUrlOverride, request.Scheme, request.Host.Host, request.Host.Port, request.PathBase, config.SchemeOverride, config.PortOverride);
}

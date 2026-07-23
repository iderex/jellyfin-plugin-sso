// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Providers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Flows;

/// <summary>
/// The OpenID login flow, extracted whole off <c>SSOController</c> (#160, #318 step 12): the
/// challenge (redirect the browser to the authorization server), the redirect callback (exchange the code,
/// validate the id_token, render the intermediate auth page), the session-minting authenticate leg, and the
/// manual link redeem. The controller's OpenID endpoints are now thin adapters — they apply the shared
/// rate-limit gate and hand the request to this service — so the OpenID-specific protocol logic lives in one
/// flow-tier collaborator rather than inline on the controller.
/// </summary>
/// <remarks>
/// The in-flight authorize-state store (<see cref="OidcStateStore"/>) lives here as a <c>static readonly</c>
/// field, one instance for the whole process exactly as it was on the controller (a fresh per-request
/// controller reconstructs the service, so an instance field would lose the in-flight state between the
/// challenge and its callback). The discovery read (<see cref="OidcDiscoveryReader"/>) is stateless — the
/// challenge fetches the document once and feeds it to the login, so there is no cache to hold here (#450).
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
    // live inside; see OidcStateStore). One process-wide instance, like the SAML caches the controller keeps.
    private static readonly OidcStateStore StateStore = new();

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

    /// <summary>
    /// Initializes a new instance of the <see cref="OidcLoginService"/> class, wiring the shared login
    /// completion and account-linking collaborators plus the HTTP-client and logger factories the
    /// token-exchange leg needs.
    /// </summary>
    /// <param name="loginCompletion">The shared post-validation login completion pipeline.</param>
    /// <param name="canonicalLinks">The account-linking workflow used by the OID manual-link redeem.</param>
    /// <param name="httpClientFactory">The factory for the token-endpoint client.</param>
    /// <param name="loggerFactory">The factory for the underlying OIDC client's logger.</param>
    /// <param name="logger">The service logger.</param>
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

    // Test-only reset of the process-wide OpenID authorize-state store this service keeps as a static. A
    // test that drives the login flow mutates it, so without a reset the state leaks into a sibling test in
    // the same non-parallel collection. Internal and reachable only through InternalsVisibleTo; it is never
    // wired to an endpoint or DI, so it adds no runtime or security surface. Moved here with the statics from
    // the controller (#160, #289). The discovery read is stateless (#450), so there is nothing else to clear.
    // Also resets the shared NewPath persist-throttle gate (#412 review follow-up, #670): SsoControllerHarness
    // calls this for every test, so a change persisted in one test can never throttle a genuine change in
    // the next one. The gate now lives on the shared ChallengeNewPathResolver, so the reset delegates there.

    /// <summary>
    /// Test-only. Clears the process-wide OpenID authorize-state store and resets the shared NewPath
    /// persist-throttle gate so state does not leak into a sibling test in the same non-parallel collection.
    /// </summary>
    internal static void ResetOidStateForTests()
    {
        StateStore.Clear();
        ChallengeNewPathResolver.ResetForTests();
    }

    // Test-only seed of a single authorize-state entry so a test can exercise the callback/authenticate legs
    // (which consume an already-validated state that the browser redirect leg normally populates) without
    // standing up the full token-exchange flow. Same test-only surface as ResetOidStateForTests (internal,
    // InternalsVisibleTo, no endpoint/DI) — never reachable in production. Moved here with the statics (#160).

    /// <summary>
    /// Test-only. Seeds a single authorize-state entry so a test can exercise the callback/authenticate legs
    /// without standing up the full token-exchange flow.
    /// </summary>
    /// <param name="token">The state token to key the seeded entry under.</param>
    /// <param name="state">The authorize state to store (a Pending or a promoted Ready).</param>
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
        StateStore.PruneExpired(DateTime.UtcNow);
        var config = FindOidConfig(provider);
        if (config is not { Enabled: true })
        {
            // Unknown and disabled providers share one rejection so neither can be probed apart (no
            // enumeration oracle), and the answer no longer depends on host middleware mapping a thrown
            // ArgumentException — the in-process 400 is fail-closed regardless of the deployment (#318).
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        var newPath = ChallengeNewPathResolver.ResolveChallengeNewPath(provider, config, isLinking, request, _logger, c => c.OidConfigs);

        string redirectUri = OidcRedirectUriBuilder.ChallengeRedirectUri(RequestBaseUrl(request, config), newPath, provider);

        // Read the discovery document ONCE, up front, and source both the security facts AND the login's
        // provider metadata from that single response (#450). Before this, the facts came from a separate
        // best-effort probe distinct from the discovery PrepareLoginAsync performed internally, so the two
        // could disagree and a failed/omitted probe silently downgraded the RFC 9207 requirement. The read
        // is IdentityModel's own GetDiscoveryDocumentAsync under this provider's DiscoveryPolicy (RequireHttps
        // / ValidateIssuerName / ValidateEndpoints), so the plugin-owned fetch honours the same channel and
        // endpoint validation the library would.
        // BuildOidcOptions reveals the at-rest client secret (#158); fail closed here if it cannot be
        // decrypted (missing/corrupt key file or a corrupt envelope) rather than letting the throw escape.
        if (TryReveal(() => BuildOidcOptions(config, redirectUri, BuildScopeString(config)), provider, out var options) is { } secretError)
        {
            return secretError;
        }

        var discovery = await OidcDiscoveryReader.ReadAsync(options, provider, _httpClientFactory, _logger).ConfigureAwait(false);
        if (!discovery.Available)
        {
            // Fail closed (#450): the discovery document the login itself needs could not be read, so there
            // is no authoritative source for the PKCE-S256 (#141) and RFC 9207 response-`iss` (#210) facts —
            // and no metadata to build the authorization request from. Reject rather than fall back to a
            // second, divergent fetch or a silent tolerant default. This is not a new lockout: without
            // discovery, PrepareLoginAsync could not build the authorize redirect either.
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID login refused for provider {Provider}: the authorization server's discovery document could not be read.", provider?.ReplaceLineEndings(string.Empty));
            }

            return FlowResponses.PlainTextError(StatusCodes.Status400BadRequest, "Error preparing login: the authorization server's discovery document could not be read.");
        }

        // RFC 9700 §2.1.1: confirm the authorization server advertises PKCE (S256) before relying on it.
        // OidcClient sends code_challenge unconditionally but never checks this, so a server that ignores
        // PKCE would silently downgrade authorization-code-injection protection (#141). The fact is now
        // definite (the document was read); fail closed when the provider is marked RequirePkce, otherwise
        // emit an audit warning and proceed.
        if (!discovery.Facts.PkceS256)
        {
            if (config.RequirePkce)
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning("OpenID login refused for provider {Provider}: RequirePkce is set but the authorization server does not advertise PKCE (S256).", provider?.ReplaceLineEndings(string.Empty));
                }

                return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.PkceNotSupported));
            }

            SsoAudit.PkceNotAdvertised(_logger, provider);
        }

        // Feed the ONE discovery response the facts came from to the login: assigning ProviderInformation
        // before constructing the client sets its internal use-discovery flag false, so PrepareLoginAsync
        // reuses this metadata instead of performing its own second discovery (#450). The metadata is
        // reused again at the callback (#247), so the challenge, the facts, and the callback all agree.
        options.ProviderInformation = discovery.ProviderInformation;
        var oidcClient = new OidcClient(options);

        // Step-up / MFA passthrough (#757): add the provider's acr_values / prompt / max_age as front-channel
        // parameters on the authorization request, each only when set. An unconfigured provider gets null, so
        // the request is byte-identical to before — upgrade-safe.
        var state = await oidcClient.PrepareLoginAsync(OidcFrontChannelParameters.FromConfig(config)).ConfigureAwait(false);

        if (state.IsError)
        {
            // Keep the library's error detail out of the browser-navigated page (#708): log it server-side
            // for the operator, return a fixed generic message. This challenge-side detail is plugin-local
            // (PrepareLoginAsync builds the authorize request), not attacker-reflected, but the callback
            // sibling below IS reflected — genericize both so no IdP/library error string ever renders on
            // the user-facing error page. Sanitized against log forging. Fail-closed is unchanged (400).
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID login refused for provider {Provider}: preparing the authorization request failed ({Error} - {ErrorDescription}).", provider?.ReplaceLineEndings(string.Empty), state.Error?.ReplaceLineEndings(string.Empty), state.ErrorDescription?.ReplaceLineEndings(string.Empty));
            }

            return FlowResponses.PlainTextError(StatusCodes.Status400BadRequest, "Error preparing login.");
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

        // Build the challenge's authorize state complete — the discovery metadata the single read above
        // fetched and validated against this provider's DiscoveryPolicy (reused at the callback so
        // ProcessResponseAsync skips a second discovery + JWKS, #247), and whether that same discovery
        // advertised the RFC 9207 response-`iss` parameter (so the callback requires `iss`, its absence
        // being a downgrade, #210). Both come from the one response (#450). Folded in at construction so
        // registration is one atomic insert and the stored Pending is never mutated after it enters the
        // store (#341). The Created instant — and every expiry comparison the store makes against it
        // (PruneExpired / PeekCurrent / TryRedeem) — is UTC, not machine-local wall-clock, so a DST
        // transition or a clock step cannot expire an in-flight authorize state early or shift its window
        // and spuriously fail a login; this matches the UTC basis the SAML flow already keeps (#676).
        var pending = new AuthorizeSession.Pending(state, provider, isLinking, DateTime.UtcNow, bindingId, clientKey, discovery.ProviderInformation, discovery.Facts.ResponseIssuerAdvertised);
        if (!StateStore.TryAdd(pending, out var shouldWarnCapacity))
        {
            if (shouldWarnCapacity)
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning("OpenID authorize state refused for provider {Provider}: a CSPRNG-token collision (effectively impossible) or the store is at capacity (warning throttled).", provider?.ReplaceLineEndings(string.Empty));
                }
            }

            return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
        }

        // Set the cookie only after the state is registered, so a refused challenge leaves no cookie.
        response.Cookies.Append(AuthorizeStateBinding.CookieName, bindingId, AuthorizeStateBinding.CookieOptions(OidcStateStore.DefaultLifetime));

        return new RedirectResult(state.StartUrl);
    }

    /// <summary>
    /// The OpenID redirect callback (a GET, despite the HTTP verb the route methods below share with the SAML
    /// callback): validates the browser-bound authorize state, exchanges the authorization code, validates the
    /// id_token and the RFC 9207 response issuer, applies the role gate, promotes the state to redeemable, and
    /// renders the intermediate auth page. The controller applies the shared rate-limit gate before delegating
    /// here.
    /// </summary>
    /// <param name="provider">The provider name from the route.</param>
    /// <param name="state">The authorize-state token the callback presented (also the auth-page data).</param>
    /// <param name="request">The current request; read for the base URL, the callback route, the code-exchange query string, the response `iss`, and the binding cookie.</param>
    /// <param name="response">The response the auth page's defensive headers are written to.</param>
    /// <returns>The rendered auth page on success, or a fail-closed rejection.</returns>
    internal async Task<ActionResult> CallbackAsync(string provider, string state, HttpRequest request, HttpResponse response)
    {
        // Unknown and disabled providers share one rejection so neither can be probed apart, matching
        // the guard-clause form the SAML sibling (SamlLoginService.Callback) already uses.
        var config = FindOidConfig(provider);
        if (config is not { Enabled: true })
        {
            return new BadRequestObjectResult(LoginStatusMapper.NoMatchingProviderMessage);
        }

        if (string.IsNullOrEmpty(state))
        {
            return new BadRequestObjectResult("Missing state");
        }

        if (StateStore.PeekCurrent(state, provider, DateTime.UtcNow, request.Cookies[AuthorizeStateBinding.CookieName]) is not { } pending)
        {
            // Unknown, expired, minted for a different provider, or from a different browser than the
            // one that started the flow (#326) — reject (details on PeekCurrent / AuthorizeStateBinding).
            return new BadRequestObjectResult("Invalid or expired state");
        }

        if (TryReveal(() => CreateCallbackOidcClient(config, provider, request, pending.ProviderInformation), provider, out var oidcClient) is { } secretError)
        {
            return secretError;
        }

        var result = await oidcClient.ProcessResponseAsync(request.QueryString.Value, pending.OidcState).ConfigureAwait(false);

        if (result.IsError)
        {
            // result.Error / result.ErrorDescription are parsed from the callback query — an authorization
            // server returns them on an error redirect, so they are attacker-controllable via a crafted
            // callback URL. Echoing them into this browser-navigated page is a content-spoofing primitive
            // (the on-brand error page would display attacker-chosen text). Log the detail server-side for
            // troubleshooting, return a fixed generic message (#708). Sanitized against log forging;
            // fail-closed is unchanged (400, no session minted).
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID login refused for provider {Provider}: the authorization-response processing failed ({Error} - {ErrorDescription}).", provider?.ReplaceLineEndings(string.Empty), result.Error?.ReplaceLineEndings(string.Empty), result.ErrorDescription?.ReplaceLineEndings(string.Empty));
            }

            return FlowResponses.PlainTextError(StatusCodes.Status400BadRequest, "Error logging in.");
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
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID login denied for provider {Provider}: the authorization-response issuer was absent-but-required or matched neither the discovery issuer nor the id_token issuer (RFC 9207 mix-up check).", provider?.ReplaceLineEndings(string.Empty));
            }

            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SsoResponseInvalid));
        }

        // Derive the authorize-state values (username, validity, admin, Live TV, folders, avatar)
        // from the verified login's claims and the provider configuration. The issuer the account link is
        // bound to (#186) is read from the RAW id_token, not result.User: OidcClient filters the standard
        // protocol claims (iss, aud, exp, …) out of the redeemed principal, so the claim list carries no
        // `iss` — the same reason the RFC 9207 check above re-reads it from result.IdentityToken.
        var derived = OidcAuthorizeStateBuilder.Build(result.User.Claims, config, OidcResponseIssuer.IdTokenIssuer(result.IdentityToken));

        // Capture the logout material (#727, SLO-1b) onto the in-flight state so it rides the one-time Ready
        // to the mint: the raw id_token (the later RP-initiated logout's id_token_hint) and the OpenID sid
        // (the IdP session id used for logout matching). Held only in memory here; it is persisted — and
        // encrypted — only at the mint, and only when Single Logout is enabled. The sid is read from the
        // signature-verified id_token (OidcIdTokenSid), NOT result.User: with LoadProfile on the principal
        // carries the unsigned UserInfo merge, so — as with acr (OidcIdTokenAcr) and iss (OidcResponseIssuer)
        // — only the id_token's own sid is trustworthy for a value that later keys a logout.
        var sid = OidcIdTokenSid.Read(result.IdentityToken);
        derived = derived with
        {
            IdToken = result.IdentityToken,
            SessionIndex = sid,
            // The end_session_endpoint from the SAME discovery that fed this login (#727, SLO-2), stored so a
            // later RP-initiated logout needs no rediscovery; null when the OP advertises none.
            EndSessionEndpoint = pending.ProviderInformation?.EndSessionEndpoint,
        };

        // Fail closed (#155): a valid OpenID login must resolve a stable subject to key the account
        // link on. sub is an OIDC Core MUST and (post-#134) the id_token validator has verified the
        // token, so a missing sub means a non-conformant provider — reject rather than fall back to
        // keying on the mutable username.
        if (derived.Valid && string.IsNullOrWhiteSpace(derived.Subject))
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID login denied for provider {Provider}: the id_token carried no 'sub' claim to key the account link on.", provider?.ReplaceLineEndings(string.Empty));
            }

            return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
        }

        if (!derived.Valid)
        {
            // The role gate did not pass: leave the Pending unpromoted (never redeemable — the redeem
            // requires a Ready) so it simply expires. Checked before Promote so no Ready is ever created
            // for a denied login.
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "OpenID login denied for {Username}: no role matched the allow-list, or the login resolved no username. Claims: {@Claims}. Roles expected (any one of): {@ExpectedClaims}",
                    derived.Username?.ReplaceLineEndings(string.Empty),
                    result.User.Claims.Select(o => new { Type = o.Type?.ReplaceLineEndings(string.Empty), Value = o.Value?.ReplaceLineEndings(string.Empty) }),
                    config.Roles);
            }

            return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
        }

        // Step-up / MFA enforcement (#757): when the provider requires an authentication-context class, the
        // acr claim must be one of the configured acr_values. Read from the RAW, signature-verified id_token
        // (OidcIdTokenAcr), NOT result.User — with LoadProfile on (the default) OidcClient merges the unsigned
        // UserInfo response into result.User, so only the id_token's own acr is trustworthy (the same reason
        // the RFC 9207 iss check above re-reads iss from result.IdentityToken). Checked here before Promote so
        // a login lacking the required context never becomes a redeemable Ready — which also covers the
        // manual-link redeem. Off by default; fail closed when on (an absent or non-listed acr is refused). A
        // save with RequireAcr on but no acr_values is rejected by the config validator, so this never lands
        // on an empty allow-list.
        if (config.RequireAcr)
        {
            var acr = OidcIdTokenAcr.Read(result.IdentityToken);
            if (!AcrPolicy.IsSatisfied(acr, config.AcrValues))
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning("OpenID login denied for provider {Provider}: RequireAcr is set but the id_token's acr claim was absent or outside the configured acr_values allow-list.", provider?.ReplaceLineEndings(string.Empty));
                }

                return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AcrNotSatisfied));
            }
        }

        // max_age freshness (#961): when the provider configures MaxAge, the authorize request carried
        // max_age (OidcFrontChannelParameters), so per OIDC Core §3.1.2.1 the id_token MUST carry auth_time
        // and the user must have authenticated within the window. Read auth_time from the RAW,
        // signature-verified id_token (OidcIdTokenAuthTime), NOT result.User — same reason as the acr gate.
        // Fail closed: a MISSING auth_time (a provider that ignored max_age) or a stale one is refused, so a
        // forced re-authentication cannot be silently satisfied by an old session. Checked here before
        // Promote so a too-old login never becomes a redeemable Ready. A negative MaxAge is treated as unset
        // (OidcFrontChannelParameters sends nothing), so it correctly enforces nothing.
        if (config.MaxAge is int maxAge && maxAge >= 0)
        {
            var authTime = OidcIdTokenAuthTime.Read(result.IdentityToken);
            if (!MaxAgePolicy.IsFresh(authTime, maxAge, DateTimeOffset.UtcNow))
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning("OpenID login denied for provider {Provider}: max_age is configured but the id_token's auth_time was absent or older than the allowed window (the user authenticated too long ago).", provider?.ReplaceLineEndings(string.Empty));
                }

                return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AuthTooOld));
            }
        }

        // Atomically swap the peeked Pending for a redeemable Ready (#341). A false return means a
        // concurrent callback already promoted it, or it expired/was pruned since the peek — either way
        // the browser's redeem is the real gate, which consumes the single Ready once (or cleanly rejects
        // a state that is gone), so the auth page is returned regardless.
        StateStore.Promote(pending, derived);

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation("Is request linking: {IsLinking}", pending.IsLinking);
        }

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
    public async Task<ActionResult> AuthenticateAsync(string provider, AuthResponse response, string? bindingCookie, Func<string> remoteEndPointResolver)
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
        if (StateStore.TryRedeem(response.Data, provider, DateTime.UtcNow, bindingCookie) is not { } redeemed)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.InvalidState));
        }

        // Verified-email login gate (#166): when the provider opts in, an OpenID login must carry
        // email_verified == true. Absent, false, or unparseable all fail this check — fail closed — reusing
        // the single value OidcAuthorizeStateBuilder already parsed and carried on the verified identity, so
        // there is no second, divergent parse. Off by default, so a deployment that does not set it (or an
        // IdP that omits the claim) is unaffected. Distinct from the adoption gate below (#218), which only
        // guards same-name account adoption; this gates every login for the provider. Needs the email scope.
        if (config.RequireVerifiedEmailForLogin && redeemed.Identity.EmailVerified != true)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID login denied for provider {Provider}: RequireVerifiedEmailForLogin is set but the login did not carry email_verified == true (absent, false, or unparseable).", provider?.ReplaceLineEndings(string.Empty));
            }

            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.EmailNotVerified));
        }

        // The redeemed state carries the fully-verified identity (#473); the OpenID adoption gate applies
        // the provider's verified-email requirement (#218). From here the OpenID and SAML paths are one.
        return await _loginCompletion.CompleteAsync(
            redeemed.Identity,
            response,
            config,
            new AdoptionGate(config.RequireVerifiedEmailForAdoption, redeemed.Identity.EmailVerified),
            remoteEndPointResolver,
            redeemed.LogoutContext).ConfigureAwait(false);
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
    internal ActionResult Link(string provider, Guid jellyfinUserId, AuthResponse response, string? bindingCookie)
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
        if (StateStore.TryRedeem(response.Data, provider, DateTime.UtcNow, bindingCookie) is not { } redeemed)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.InvalidState));
        }

        // Manual linking keys on the stable subject (#155), matching the auto-login path, so a
        // later provider-side rename does not orphan the link the user just created. The redeemed
        // identity's issuer stamps the link (#186), so a manual link is issuer-bound like an auto-login one.
        return FlowResponses.MapCanonicalLinkWrite(_canonicalLinks.TryCreateLink(ProviderMode.Oid, provider, redeemed.Identity.Subject, jellyfinUserId, redeemed.Identity.Issuer));
    }

    // Builds the space-delimited OpenID scope string, always leading with the base "openid profile".
    // OidScopes is null when a provider was stored without scopes (#368, e.g. via the OID/Add API) —
    // normalize to empty so neither the challenge nor the callback throws (an unhandled 500 on the
    // anonymous challenge endpoint) or pads the scope string with null entries. Blank elements inside a
    // non-null array are dropped too, so a persisted null/empty/whitespace scope cannot inject a
    // doubled or trailing separator (#407). Shared by both sites.

    /// <summary>
    /// Builds the space-delimited OpenID scope string, always leading with the base "openid profile" and
    /// dropping null/empty/whitespace entries so a persisted bad scope cannot inject a doubled or trailing
    /// separator (#407) or throw on a provider stored without scopes (#368).
    /// </summary>
    /// <param name="config">The provider configuration whose <c>OidScopes</c> are appended.</param>
    /// <returns>The normalized scope string.</returns>
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
    private static OidConfig? FindOidConfig(string provider) =>
        SSOPlugin.Instance.ReadConfiguration(configuration => configuration.OidConfigs.TryGetValue(provider, out var config) ? config : null);

    // Runs an options/client build step that reveals the at-rest client secret (#158), failing closed if
    // it cannot be decrypted. Secrets.Reveal (inside BuildOidcOptions) surfaces a missing or corrupt at-rest
    // key file, or a corrupt envelope, as a CryptographicException/FormatException; this catches it and
    // returns a clean 500 rather than letting it escape as an unhandled framework error — never proceeding
    // with an empty or wrong secret. No key material or secret is logged (the message names only the key
    // file). Mirrors the SAML challenge's signing-key fail-closed 500. Generic over the built value because
    // the challenge builds the options (revealing the secret up front, before the discovery read) while the
    // callback builds the whole client. Returns null on success (the built value is set); otherwise the
    // fail-closed result to return.
    private ContentResult? TryReveal<T>(Func<T> build, string provider, out T built)
    {
        try
        {
            built = build();
            return null;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            // Only read by the caller on the success path (return null); the fail-closed path returns a
            // non-null result, so this default is never observed.
            built = default!;
            if (_logger.IsEnabled(LogLevel.Error))
            {
                _logger.LogError("OpenID login refused for provider {Provider}: the stored client secret could not be decrypted ({Reason}); the at-rest key file is missing or corrupt.", provider?.ReplaceLineEndings(string.Empty), ex.Message?.ReplaceLineEndings(string.Empty));
            }

            return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not process login; the OpenID client secret could not be decrypted.");
        }
    }

    // Builds the OidcClient options both sites share — Authority, client credentials, redirect URI, scope,
    // the discovery policy (RequireHttps / ValidateIssuerName / ValidateEndpoints + the additional base
    // address for providers whose endpoints sit off the authority), and the required id_token signature
    // validator (#134) — but WITHOUT ProviderInformation. Kept separate from the client construction so the
    // challenge can configure the policy, read discovery ONCE under it, and only then construct the client
    // with the resulting metadata pre-assigned (#450); the constructor's internal use-discovery flag is
    // decided from whether ProviderInformation is set at construction, so the assignment must happen before
    // `new OidcClient(options)`, not after. A null OidEndpoint still fails at the same point it did before
    // (the Uri constructor, after the options object).

    /// <summary>
    /// Validates an inbound back-channel <c>logout_token</c> for a provider (#962): reads the provider's
    /// discovery document for its JWKS + issuer, builds the SAME hardened validation parameters the id_token
    /// uses, and runs <see cref="OidcLogoutTokenValidator"/>. No client secret is revealed — verifying a
    /// signature needs no credential, so the back-channel path never touches the secret at rest. Every
    /// failure (a malformed endpoint, an unreadable discovery document, or any §2.6 rule) is fail-closed and
    /// carries a fixed reason code for the caller to audit; the caller performs the revocation.
    /// </summary>
    /// <param name="config">The provider configuration.</param>
    /// <param name="provider">The provider name (route input, used only for the SSRF-guarded discovery read).</param>
    /// <param name="logoutToken">The raw <c>logout_token</c> from the anonymous POST body.</param>
    /// <returns>The validation outcome — on success, the (sub, sid) the caller keys its revocation lookup on.</returns>
    internal async Task<OidcLogoutTokenValidator.Result> ValidateBackChannelLogoutAsync(OidConfig config, string provider, string? logoutToken)
    {
        OidcClientOptions options;
        try
        {
            // Validation-only options: Authority + discovery policy + client id, under the ONE shared
            // discovery posture (RequireHttps / ValidateIssuerName / ValidateEndpoints). A malformed/absent
            // endpoint throws here — caught as a fail-closed reject rather than a 500.
            options = OidcDiscoveryOptions.Build(config);
        }
        catch (Exception ex) when (ex is UriFormatException or ArgumentException)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID back-channel logout refused for provider {Provider}: the configured endpoint is not a usable URL.", provider?.ReplaceLineEndings(string.Empty));
            }

            return new OidcLogoutTokenValidator.Result(false, null, null, "discovery_unavailable");
        }

        options.ClientId = config.OidClientId?.Trim();
        options.LoggerFactory = _loggerFactory;
        options.HttpClientFactory = _ => SsoHttp.CreateClient(_httpClientFactory);

        var discovery = await OidcDiscoveryReader.ReadAsync(options, provider, _httpClientFactory, _logger).ConfigureAwait(false);
        if (!discovery.Available)
        {
            return new OidcLogoutTokenValidator.Result(false, null, null, "discovery_unavailable");
        }

        options.ProviderInformation = discovery.ProviderInformation;

        var ephemeralKeys = new List<IDisposable>();
        try
        {
            // requireExpiration:false — OIDC Back-Channel Logout 1.0 §2.4 does not mandate exp on a
            // logout_token; replay is bounded by the jti one-time-use, not by exp. Requiring it would
            // silently reject (and thus no-op the logout for) a spec-compliant exp-less IdP (#962).
            var parameters = OidcSignatureKeys.BuildValidationParameters(options, ephemeralKeys, requireExpiration: false);
            return await new OidcLogoutTokenValidator().ValidateAsync(logoutToken, parameters, options.ClockSkew, DateTime.UtcNow).ConfigureAwait(false);
        }
        finally
        {
            foreach (var key in ephemeralKeys)
            {
                key.Dispose();
            }
        }
    }

    private OidcClientOptions BuildOidcOptions(OidConfig config, string redirectUri, string scope)
    {
        // Authority and the discovery policy (RequireHttps / ValidateIssuerName / ValidateEndpoints + the
        // additional base address) come from the one shared builder (#163), so the login and the admin
        // Test-connection probe read discovery under an identical SSRF/TLS posture — the policy cannot drift
        // between them. A null/invalid OidEndpoint still throws here (inside the caller's secret-reveal
        // guard) exactly as before, so the challenge fails closed at the same point.
        var options = OidcDiscoveryOptions.Build(config);
        options.ClientId = config.OidClientId?.Trim();
        // The client secret is stored encrypted at rest (#158); reveal it at the point of use. A legacy
        // plaintext value passes through unchanged (transparent migration); a missing/corrupt key throws
        // (CryptographicException) rather than returning a wrong or empty secret — the login then fails
        // closed rather than silently attempting an unauthenticated token exchange.
        options.ClientSecret = SSOPlugin.Instance.Secrets.Reveal(config.OidSecret)?.Trim();
        options.RedirectUri = redirectUri;
        options.Scope = scope;
        options.DisablePushedAuthorization = config.DisablePushedAuthorization;
        options.LoggerFactory = _loggerFactory;
        options.LoadProfile = !config.DoNotLoadProfile;
        options.HttpClientFactory = o => SsoHttp.CreateClient(_httpClientFactory);

        // OidcClient 7.x validates nothing about the id_token unless a validator is supplied (its
        // fallback only base64-decodes the payload). Signature validation is required and has no
        // config toggle: an unvalidated id_token is a forgeable login (#134).
        options.Policy.RequireIdentityTokenSignature = true;
        options.IdentityTokenValidator = new OidcIdTokenValidator();

        return options;
    }

    // Callback-side client: the redirect URI is rebuilt from the callback's own route (the IdP calls
    // back on exactly the route the authorization request advertised), so the token request's
    // redirect_uri matches the authorization request's as RFC 6749 requires (#98). The scope string
    // is normalized the same way as the challenge side (BuildScopeString) — both tolerate a null
    // OidScopes identically (#368). The challenge leg builds its own client inline (BuildOidcOptions +
    // new OidcClient with the discovery metadata pre-assigned, #450), so this is the sole client-assembly
    // site left; the former CreateOidcClient wrapper folded in here (#695).
    private OidcClient CreateCallbackOidcClient(OidConfig config, string provider, HttpRequest request, ProviderInformation providerInformation)
    {
        var redirectUri = OidcRedirectUriBuilder.CallbackRedirectUri(RequestBaseUrl(request, config), request.Path.Value, provider);
        var options = BuildOidcOptions(config, redirectUri, BuildScopeString(config));

        // Reuse an already-fetched, policy-validated discovery metadata when the caller supplies it — the
        // callback feeds the metadata captured at the challenge (#247) so ProcessResponseAsync does not
        // re-run discovery + JWKS. Pre-assigning ProviderInformation sets the client's internal
        // _useDiscovery = false, which also disables the library's invalid_signature JWKS-refresh-and-retry.
        // Two directions of key change, both bounded by the authorize state's ~15-minute lifetime: a key
        // rotated IN during the window (the id_token signed by a key the challenge did not capture) fails
        // this callback closed and self-heals on retry (the next challenge fetches fresh keys); a key rotated
        // OUT / revoked during the window stays accepted until the state expires, since the callback validates
        // against the captured set — a far tighter exposure than the platform-default 24-hour JWKS cache, and
        // never wider than the state lifetime. Populated only from a validated fetch (never hand-filled), so
        // the DiscoveryPolicy (RequireHttps / ValidateIssuerName / ValidateEndpoints) is not bypassed. The
        // conditional is kept as-is (behaviour-preserving) though the sole caller always supplies non-null.
        if (providerInformation is not null)
        {
            options.ProviderInformation = providerInformation;
        }

        return new OidcClient(options);
    }

    // Resolves the canonical base URL from the live request and the provider's overrides — the same pure
    // CanonicalBaseUrl.Resolve decision (#242) SamlLoginService.GetRequestBase feeds for SAML. Kept as a
    // thin local read so this flow tier is self-contained.
    private static string RequestBaseUrl(HttpRequest request, OidConfig config) =>
        CanonicalBaseUrl.Resolve(config.BaseUrlOverride, request.Scheme, request.Host.Host, request.Host.Port, request.PathBase, config.SchemeOverride, config.PortOverride);
}

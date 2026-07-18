using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Flows;

/// <summary>
/// The SAML login flow, extracted whole off <see cref="SSOController"/> (#160, #318 step 13), symmetric to
/// <see cref="OidcLoginService"/>: the challenge (redirect the browser to the identity provider with an
/// optionally-signed AuthnRequest, #167), the assertion-consumer callback (validate the signed response and
/// render the intermediate auth page), the session-minting authenticate leg, and the manual link redeem. The
/// controller's SAML endpoints are now thin adapters — they apply the shared rate-limit gate and hand the
/// request to this service — so the SAML-specific protocol logic lives in one flow-tier collaborator rather
/// than inline on the controller.
/// </summary>
/// <remarks>
/// The two SAML-specific process-wide caches live here as <c>static readonly</c> fields, one instance for the
/// whole process exactly as they were on the controller (a fresh per-request controller reconstructs the
/// service, so an instance field would lose the in-flight state between the challenge and its callback):
/// <list type="bullet">
/// <item>the one-time-use replay cache of consumed assertion IDs (<see cref="SamlReplayCache"/>), and</item>
/// <item>the outstanding-AuthnRequest cache for InResponseTo correlation and the browser binding (<see cref="SamlRequestCache"/>, #156/#415).</item>
/// </list>
/// The shared per-client rate limiter is deliberately NOT here — it also fronts the OpenID flow, so it lives
/// in the shared <see cref="SsoRateLimitGate"/> (Api/Shared) that the controller's endpoints front this
/// service with, rather than as a per-flow static (#160). The methods take the
/// request/response because SAML is irreducibly HTTP (the redirect, the ACS POST form, the binding cookie, the
/// security-headered page, and the request-host-derived assertion-consumer URL the Recipient is bound to); the
/// two response shapes both flows share — the security-headered auth page and the manual-link write mapping —
/// are rendered from the shared <see cref="FlowResponses"/> home rather than a controller delegate (#160).
/// </remarks>
internal sealed class SamlLoginService
{
    // One-time-use tracking for consumed SAML assertion IDs (replay protection). One process-wide instance,
    // like the outstanding-request cache below and the OpenID caches the sibling flow service keeps.
    private static readonly SamlReplayCache SamlReplays = new SamlReplayCache();

    // Outstanding SAML AuthnRequest IDs, for InResponseTo correlation of solicited responses (#156) and the
    // browser binding (#415). One process-wide instance.
    private static readonly SamlRequestCache SamlRequests = new SamlRequestCache();

    // How long an issued SAML AuthnRequest ID stays valid for correlation — the interactive leg
    // (challenge -> IdP login/MFA -> POST back -> mint), matching the OpenID authorize-state lifetime the
    // sibling flow service keeps.
    private static readonly TimeSpan SamlRequestLifetime = TimeSpan.FromMinutes(15);

    // The shared login-completion tail (#160): resolve/adopt the link, build the session parameters, mint
    // under the revocation gate, audit, map to a LoginOutcome. Both protocols funnel their verified identity
    // into it, so it is a shared collaborator this service holds a reference to rather than owning.
    private readonly LoginCompletionService _loginCompletion;

    // The account-linking workflow (resolve/adopt/create, legacy re-key, revoke). Used here only by the SAML
    // manual-link redeem; the controller keeps the caller-authz guard and the one-time-use consume around it.
    private readonly CanonicalLinkService _canonicalLinks;

    private readonly ILogger _logger;

    internal SamlLoginService(
        LoginCompletionService loginCompletion,
        CanonicalLinkService canonicalLinks,
        ILogger logger)
    {
        _loginCompletion = loginCompletion ?? throw new ArgumentNullException(nameof(loginCompletion));
        _canonicalLinks = canonicalLinks ?? throw new ArgumentNullException(nameof(canonicalLinks));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // Test-only: clears the outstanding-SAML-request cache so a prior test's seeded or in-flight entry
    // (e.g. one left behind by a signature-failing response that returns before the consume) cannot leak
    // into the next test. Same test-only surface as OidcLoginService.ResetOidStateForTests (internal,
    // InternalsVisibleTo, no endpoint/DI). Moved here with the statics from the controller (#160).
    internal static void ResetSamlRequestsForTests() => SamlRequests.Clear();

    // Test-only seed of an outstanding SAML AuthnRequest so a test can exercise SamlAuth's browser
    // binding (#415) — normally populated by the challenge redirect leg — without deriving the random
    // request id from the emitted AuthnRequest. Same test-only surface as SeedOidStateForTests
    // (internal, InternalsVisibleTo, no endpoint/DI); never reachable in production. Moved here (#160).
    internal static void SeedSamlRequestForTests(string provider, string requestId, string bindingId, DateTime expiryUtc) =>
        SamlRequests.Register(ProviderScopedKey.For(provider, requestId), bindingId, expiryUtc, DateTime.UtcNow, clientKey: null, out _);

    /// <summary>
    /// The SAML assertion-consumer callback: validates the signed response and, on a passing role gate,
    /// renders the intermediate auth page. The controller applies the shared rate-limit gate before
    /// delegating here.
    /// </summary>
    /// <param name="provider">The provider that is calling back.</param>
    /// <param name="relayState">The RelayState from the original SAML request; "linking" marks a link request.</param>
    /// <param name="formSamlResponse">The SAMLResponse form field (model-bound, so a non-form POST binds null and is rejected).</param>
    /// <param name="request">The current request; read for the assertion-consumer base URL.</param>
    /// <param name="response">The response the auth page's defensive headers are written to.</param>
    /// <returns>The rendered auth page on success, or a fail-closed rejection.</returns>
    internal ActionResult Post(string provider, string relayState, string formSamlResponse, HttpRequest request, HttpResponse response)
    {
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
            || !IsSamlResponseValid(request, samlResponse, config, provider))
        {
            // A malformed response (non-base64, malformed XML, prohibited DOCTYPE) fails TryLoad and
            // is rejected the same way an invalid one is — a clean 4xx, never an unhandled 500 (#199).
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        if (SamlLoginPolicy.IsLoginAllowed(samlResponse.GetCustomAttributes("Role"), config.Roles))
        {
            return FlowResponses.AuthPage(response, nonce =>
                WebResponse.Generator(
                    data: Convert.ToBase64String(Encoding.UTF8.GetBytes(samlResponse.Xml)),
                    provider: provider,
                    baseUrl: GetRequestBase(request, config.SchemeOverride, config.PortOverride, config.BaseUrlOverride),
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
    /// Initiates the SAML login flow: builds the AuthnRequest, binds it to the initiating browser, and
    /// redirects to the identity provider (signing the request when the provider opts in, #167). The
    /// controller applies the shared rate-limit gate before delegating here.
    /// </summary>
    /// <param name="provider">The provider to begin the flow with.</param>
    /// <param name="isLinking">Whether this flow intends to link an account rather than authenticate.</param>
    /// <param name="request">The current request; read for the assertion-consumer base URL, the challenge route spelling, and the client IP.</param>
    /// <param name="response">The response the browser-binding cookie is appended to on a login challenge.</param>
    /// <returns>A redirect to the SAML provider's auth page, or a fail-closed rejection/error.</returns>
    internal ActionResult Challenge(string provider, bool isLinking, HttpRequest request, HttpResponse response)
    {
        // Unknown and disabled providers share one rejection so neither can be probed apart, and the
        // answer no longer depends on host middleware mapping a thrown ArgumentException (#318).
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        bool newPath = ResolveChallengeNewPath(config, isLinking, request);

        string redirectUri = SsoUrlBuilder.SamlAcsUrl(GetRequestBase(request, config.SchemeOverride, config.PortOverride, config.BaseUrlOverride), newPath, provider);
        string relayState = null;
        if (isLinking)
        {
            relayState = "linking";
        }

        var samlRequest = new SamlAuthnRequest(
            config.SamlClientId.Trim(),
            redirectUri);

        // Bind this login to the initiating browser (#415): mint a binding id, set it as a cookie, and
        // record it against the request id so the session-mint endpoint (Authenticate) can require the
        // response's browser to be the one that started the flow — closing the SP-initiated forced-login
        // / session-fixation vector, the SAML analogue of #326. Only for login flows: the linking
        // callback (Link) is a separate flow that does not consume the outstanding request, so a
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
            var clientKey = SsoRateLimiter.NormalizeClientKey(request.HttpContext.Connection.RemoteIpAddress);
            if (!SamlRequests.Register(
                    ProviderScopedKey.For(provider, samlRequest.Id),
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

                return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
            }

            response.Cookies.Append(
                AuthorizeStateBinding.SamlCookieName,
                bindingId,
                AuthorizeStateBinding.CookieOptions(SamlRequestLifetime));
        }

        string redirectUrl;
        try
        {
            redirectUrl = BuildChallengeRedirectUrl(config, samlRequest, relayState);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or CryptographicException)
        {
            // Signing is enabled for this provider but the request could not be signed: the key is
            // missing/unusable (InvalidOperationException), the endpoint is empty (ArgumentException from
            // the signer), or the platform key store refused the signing operation (CryptographicException).
            // ANY of these fails closed with a clean 500 — never a silent unsigned request — rather than
            // escaping as a raw host 500. The key material is not part of the message, so nothing sensitive
            // is logged.
            _logger.LogError("SAML challenge for provider {Provider} could not sign the AuthnRequest: {Reason}", provider?.ReplaceLineEndings(string.Empty), ex.Message);
            return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; the SAML request signing key is misconfigured.");
        }

        return new RedirectResult(redirectUrl);
    }

    /// <summary>
    /// The SAML session-minting authenticate leg: validates the signed response, correlates it to an
    /// AuthnRequest this server issued (browser binding, #156/#415), enforces the login allow-list and
    /// one-time replay consume, then hands the fully-verified identity to the shared completion tail. The
    /// controller applies the shared rate-limit gate before delegating and supplies the binding cookie and
    /// remote-endpoint resolver.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="response">The client's auth request context (app/device) plus the SAML response in <c>Data</c>.</param>
    /// <param name="bindingCookie">The browser-binding cookie value the redeem presented (#415).</param>
    /// <param name="request">The current request; read for the assertion-consumer base URL (recipient binding).</param>
    /// <param name="remoteEndPointResolver">Resolves the normalized client IP for the activity log (#177).</param>
    /// <returns>The minted session, or a fail-closed rejection.</returns>
    internal async Task<ActionResult> AuthenticateAsync(string provider, AuthResponse response, string bindingCookie, HttpRequest request, Func<string> remoteEndPointResolver)
    {
        // Unknown and disabled providers share one rejection so neither can be probed apart — this
        // unifies the previously JSON unknown-provider body and the disabled provider's 500.
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        if (!SamlResponseLoader.TryParse(config.SamlCertificate, response?.Data, out var samlResponse)
            || !IsSamlResponseValid(request, samlResponse, config, provider))
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
                || !AuthorizeStateBinding.Matches(storedBindingId, bindingCookie))
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

        // All SAML validation has now passed — signature, time bounds, audience, recipient, InResponseTo
        // correlation, the login allow-list, replay one-time-use, and the non-empty-NameID guard — so this
        // is the point at which the response becomes a fully-verified SAML identity (#473). SAML keys the
        // link directly on the NameID (subject and username are the same value; no migration path needed)
        // and carries no email_verified claim, so the verified-email gate is not applicable
        // (AdoptionGate.None); the resolver's unconditional admin-adoption refusal (#218) still applies.
        // From here the SAML and OpenID paths are one.
        return await _loginCompletion.CompleteAsync(
            VerifiedIdentity.FromValidatedSaml(provider, nameId, derived),
            response,
            config,
            AdoptionGate.None,
            remoteEndPointResolver).ConfigureAwait(false);
    }

    /// <summary>
    /// The SAML manual-link redeem: validates the signed response, consumes its one-time-use assertion id,
    /// and creates the canonical link on the assertion's NameID. The controller applies the caller-authz
    /// guard before delegating.
    /// </summary>
    /// <param name="provider">The provider to link against.</param>
    /// <param name="jellyfinUserId">The Jellyfin account to link (already authorized by the controller).</param>
    /// <param name="response">The client information carrying the SAML response in <c>Data</c>.</param>
    /// <param name="request">The current request; read for the assertion-consumer base URL (recipient binding).</param>
    /// <returns>The link-creation result, or a fail-closed rejection.</returns>
    internal ActionResult Link(string provider, Guid jellyfinUserId, AuthResponse response, HttpRequest request)
    {
        // A disabled provider must neither create a link nor consume the assertion's one-time-use ID
        // (#343): an administrator disabling a provider takes effect immediately for linking, and the
        // unknown and disabled cases share one response so neither can be probed apart.
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return new BadRequestObjectResult(LoginStatusMapper.NoMatchingProviderMessage);
        }

        if (!SamlResponseLoader.TryParse(config.SamlCertificate, response?.Data, out var samlResponse)
            || !IsSamlResponseValid(request, samlResponse, config, provider))
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

        return FlowResponses.MapCanonicalLinkWrite(_canonicalLinks.TryCreateLink(ProviderMode.Saml, provider, providerUserId, jellyfinUserId));
    }

    // Reads a provider's config under the config lock, so an anonymous login-path lookup does not race an
    // admin Add/Del mutating the live provider dictionary in place — a Dictionary read-during-write is
    // undefined behaviour in .NET (throw, misread, or a spin on a corrupted chain during a resize) (#252).
    // Returns null for an unknown provider so call sites branch on a null check instead of catching
    // KeyNotFoundException as control flow (#241). An uncontended lock is nanoseconds; it is only held long
    // during a first-login/admin persist, which is exactly when a consistent read matters. Moved off the
    // controller with the SAML flow (#160); the OpenID twin lives on OidcLoginService.
    private static SamlConfig FindSamlConfig(string provider) =>
        SSOPlugin.Instance.ReadConfiguration(configuration => configuration.SamlConfigs.TryGetValue(provider, out var config) ? config : null);

    // Resolves whether this challenge uses the "new", more descriptive redirect path, and records that as
    // server-managed runtime state on the provider config. A non-linking challenge derives the spelling
    // from the request path (a `.../start/...` route means the new path) and stores it, so a later linking
    // flow — which cannot know which redirect path the identity provider has registered — reuses the last
    // login's spelling. A linking challenge only reads the stored value. (See ExpectedAcsUrls for the same
    // reason this value is remembered across requests.) Mirrors OidcLoginService.ResolveChallengeNewPath —
    // the type is known here, so the record is a direct assignment.
    private static bool ResolveChallengeNewPath(SamlConfig config, bool isLinking, HttpRequest request)
    {
        if (isLinking)
        {
            return config.NewPath;
        }

        var newPath = ChallengePath.IsNewPath(request.Path.Value);
        config.NewPath = newPath;
        return newPath;
    }

    // Builds the redirect URL to the identity provider, signing the outgoing AuthnRequest when the provider
    // opts in (#167). Fail-closed: signing enabled but the signing key missing/unloadable throws, so the
    // caller returns an error rather than silently sending an unsigned request — an operator who turned
    // signing on never gets a silent downgrade. Default off is byte-for-byte the previous unsigned URL.
    private static string BuildChallengeRedirectUrl(SamlConfig config, SamlAuthnRequest request, string relayState)
    {
        var endpoint = config.SamlEndpoint.Trim();
        if (!config.SignAuthnRequests)
        {
            return request.GetRedirectUrl(endpoint, relayState);
        }

        if (!SamlSigningKey.TryLoad(config.SamlSigningKeyPfx, out var signingCertificate))
        {
            throw new InvalidOperationException("Outgoing SAML request signing is enabled but the signing key could not be loaded.");
        }

        using (signingCertificate)
        using (var signingKey = signingCertificate.GetRSAPrivateKey())
        {
            if (signingKey is null)
            {
                throw new InvalidOperationException("Outgoing SAML request signing is enabled but the signing key has no RSA private key.");
            }

            return request.GetSignedRedirectUrl(endpoint, relayState, signingKey);
        }
    }

    // Consumes the SAML assertion's ID against the provider-scoped replay cache for one-time use.
    // Returns false when the assertion was already used (or carries no ID — a missing ID stays empty,
    // so TryConsume fails closed). The key is scoped by provider so two IdPs emitting the same assertion
    // ID cannot block each other. Shared by the session mint and the account linking (#219).
    private static bool TryConsumeSamlReplay(SamlResponse samlResponse, string provider)
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
    private bool IsSamlResponseValid(HttpRequest request, SamlResponse samlResponse, SamlConfig config, string provider)
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
            && !SamlRecipientValidator.IsBound(samlResponse.GetRecipient(), samlResponse.GetDestination(), ExpectedAcsUrls(request, config, provider)))
        {
            _logger.LogWarning("SAML response rejected: the assertion Recipient or Response Destination does not match this server's assertion-consumer URL.");
            return false;
        }

        return true;
    }

    // The assertion-consumer URLs this service provider advertises for the provider — the same value
    // Challenge puts in the AuthnRequest's AssertionConsumerServiceURL, so a signed Recipient (or
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
    private static string[] ExpectedAcsUrls(HttpRequest request, SamlConfig config, string provider) =>
        SsoUrlBuilder.SamlExpectedAcsUrls(GetRequestBase(request, config.SchemeOverride, config.PortOverride, config.BaseUrlOverride), provider);

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

    // Thin adapter feeding the live request values into the pure CanonicalBaseUrl.Resolve decision (#242) —
    // the same decision OidcLoginService.RequestBaseUrl feeds for OpenID, kept as a local read so this flow
    // tier is self-contained.
    private static string GetRequestBase(HttpRequest request, string schemeOverride, int? portOverride, string baseUrlOverride) =>
        CanonicalBaseUrl.Resolve(baseUrlOverride, request.Scheme, request.Host.Host, request.Host.Port, request.PathBase, schemeOverride, portOverride);
}

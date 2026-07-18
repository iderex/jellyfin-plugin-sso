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
/// The outstanding-AuthnRequest cache for InResponseTo correlation and the browser binding
/// (<see cref="SamlRequestCache"/>, #156/#415) lives here as a <c>static readonly</c> field, one instance for
/// the whole process exactly as it was on the controller (a fresh per-request controller reconstructs the
/// service, so an instance field would lose the in-flight state between the challenge and its callback). The
/// inbound-assertion validation — signature/time/audience/recipient, the one-time replay cache, and the sole
/// SAML <see cref="VerifiedIdentity"/> construction — moved into the dedicated
/// <see cref="SamlAssertionValidator"/> (#496); this service keeps the InResponseTo correlation because that
/// is request-issued session-fixation correlation, not assertion validation.
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
    // Outstanding SAML AuthnRequest IDs, for InResponseTo correlation of solicited responses (#156) and the
    // browser binding (#415). One process-wide instance.
    private static readonly SamlRequestCache SamlRequests = new SamlRequestCache();

    // The in-flight login-outcome store (#251): the ACS callback validates the assertion ONCE, stores the
    // resulting verified outcome keyed by a CSPRNG token, and hands the intermediate page only that token;
    // the session-mint leg redeems the token instead of re-parsing and re-validating the assertion. One
    // process-wide instance, like the outstanding-request cache above — the callback and the mint leg run
    // across separate per-request flow-service instances.
    private static readonly SamlOutcomeStore Outcomes = new SamlOutcomeStore();

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

    // The dedicated inbound-assertion validator (#496): parse + signature/time/audience/recipient/algorithm
    // validation, the one-time replay consume, the non-empty-NameID guard, and the sole SAML
    // FromValidatedSaml construction site. Constructed per request with this service, but it owns the
    // process-wide replay cache as a static, so replay state survives the two-step post-then-authenticate legs.
    private readonly SamlAssertionValidator _validator;

    private readonly ILogger _logger;

    internal SamlLoginService(
        LoginCompletionService loginCompletion,
        CanonicalLinkService canonicalLinks,
        ILogger logger)
    {
        _loginCompletion = loginCompletion ?? throw new ArgumentNullException(nameof(loginCompletion));
        _canonicalLinks = canonicalLinks ?? throw new ArgumentNullException(nameof(canonicalLinks));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _validator = new SamlAssertionValidator(logger);
    }

    // Test-only: clears the outstanding-SAML-request cache so a prior test's seeded or in-flight entry
    // (e.g. one left behind by a signature-failing response that returns before the consume) cannot leak
    // into the next test. Same test-only surface as OidcLoginService.ResetOidStateForTests (internal,
    // InternalsVisibleTo, no endpoint/DI). Moved here with the statics from the controller (#160).
    internal static void ResetSamlRequestsForTests() => SamlRequests.Clear();

    // Test-only: clears the in-flight login-outcome store (#251) between tests, the same process-wide-static
    // reset reason as ResetSamlRequestsForTests. Internal, InternalsVisibleTo, never wired to an endpoint/DI.
    internal static void ResetSamlOutcomesForTests() => Outcomes.Clear();

    // Test-only: seeds a single login outcome so a test can drive the token-redeem mint leg without first
    // running the callback that normally populates the store. Same test-only surface as the resets above.
    internal static void SeedSamlOutcomeForTests(SamlLoginOutcome outcome) => Outcomes.Seed(outcome);

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
    internal ActionResult Callback(string provider, string relayState, string formSamlResponse, HttpRequest request, HttpResponse response)
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
        var requestBase = GetRequestBase(request, config.SchemeOverride, config.PortOverride, config.BaseUrlOverride);
        if (!_validator.TryValidate(config, provider, requestBase, formSamlResponse, out var samlResponse))
        {
            // A malformed response (non-base64, malformed XML, prohibited DOCTYPE) or a failed
            // signature/time/audience/recipient check is rejected the same way — a clean 4xx, never an
            // unhandled 500 (#199).
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        if (!SamlLoginPolicy.IsLoginAllowed(SamlAssertionValidator.GetAssertionRoles(samlResponse), config.Roles))
        {
            _logger.LogWarning(
                "SAML user: {UserId} has insufficient roles: {@Roles}. Expected any one of: {@ExpectedRoles}",
                samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty),
                SamlAssertionValidator.GetAssertionRoles(samlResponse).Select(r => r?.ReplaceLineEndings(string.Empty)),
                config.Roles);
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
        }

        // Linking keeps the assertion-embedded page (#251 is scoped to the login round-trip): the page JS
        // posts its data to BOTH SAML/Link and SAML/Auth, and the one-time outcome token is single-use, so a
        // token would satisfy only the first of the two posts. The link redeem (SamlLoginService.Link)
        // consumes the assertion's one-time-use id on its own leg, and the follow-on SAML/Auth post then
        // falls to the fully-validating deprecation branch below — byte-for-byte the pre-#251 linking flow.
        if (isLinking)
        {
            return FlowResponses.AuthPage(response, nonce =>
                WebResponse.Generator(
                    data: Convert.ToBase64String(Encoding.UTF8.GetBytes(samlResponse.Xml)),
                    provider: provider,
                    baseUrl: requestBase,
                    mode: "SAML",
                    nonce: nonce,
                    isLinking: true));
        }

        // Login path (#251): validate the assertion exactly ONCE here — the one-time replay consume, the
        // non-empty-NameID guard, and the sole SAML VerifiedIdentity construction — then store the verified
        // outcome server-side keyed by a CSPRNG token and hand the page only that token. The signed XML never
        // crosses to the browser, so SAML/Auth redeems the outcome instead of parsing and validating a second
        // copy. The InResponseTo correlation and browser binding are NOT enforced here: the ACS POST is
        // cross-site and would not carry the SameSite=Lax binding cookie, so that check stays at the
        // same-origin mint leg (below), where the cookie is present — the assertion's InResponseTo is carried
        // in the stored outcome so the mint leg can correlate it without the XML.
        if (!_validator.TryProduceVerifiedIdentity(config, provider, samlResponse, out var identity, out var rejection))
        {
            return LoginStatusMapper.ToActionResult(rejection);
        }

        var clientKey = SsoRateLimiter.NormalizeClientKey(request.HttpContext.Connection.RemoteIpAddress);
        Outcomes.PruneExpired(DateTime.UtcNow);
        var outcome = new SamlLoginOutcome(
            SamlOutcomeStore.NewToken(),
            provider,
            identity,
            samlResponse.GetInResponseTo() ?? string.Empty,
            clientKey,
            DateTime.UtcNow);
        if (!Outcomes.TryAdd(outcome, out var shouldWarnCapacity))
        {
            // A CSPRNG-token collision (effectively impossible) or the store is at capacity — fail closed
            // rather than render a page whose token could never redeem. The store throttles the capacity
            // warning to one signal per interval so a flood cannot amplify into log volume (CWE-400).
            if (shouldWarnCapacity)
            {
                _logger.LogWarning("SAML login outcome refused for provider {Provider}: a CSPRNG-token collision (effectively impossible) or the outcome store is at capacity (warning throttled).", provider?.ReplaceLineEndings(string.Empty));
            }

            return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
        }

        return FlowResponses.AuthPage(response, nonce =>
            WebResponse.Generator(
                data: outcome.Token,
                provider: provider,
                baseUrl: requestBase,
                mode: "SAML",
                nonce: nonce,
                isLinking: false));
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

        // The one-time outcome-token path (#251): the plugin now renders a token (not the assertion) for
        // login flows. Redeem it once — an atomic claim, so a replayed token misses and a token minted for
        // another provider is refused (details on SamlOutcomeStore.TryRedeem). The assertion was already
        // fully validated at the ACS callback (signature, time, audience, recipient, role gate, the one-time
        // replay consume and the verified-identity construction), so NOTHING is re-parsed or re-validated
        // here: only the browser binding remains, checked at this same-origin leg where the SameSite=Lax
        // cookie is sent (the cross-site ACS POST could not carry it). A miss falls through to the
        // deprecation branch below, so an unknown/expired/replayed token is rejected there rather than minting.
        if (Outcomes.TryRedeem(response?.Data, provider, DateTime.UtcNow) is { } outcome)
        {
            if (!CorrelateAndBind(provider, outcome.InResponseTo, bindingCookie, config.ValidateInResponseTo))
            {
                return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
            }

            // From here the SAML and OpenID paths are one: the verified identity flows into the shared
            // completion tail. SAML keys the link on the NameID and carries no email_verified claim, so
            // AdoptionGate.None; the resolver's admin-adoption refusal (#218) still applies.
            return await _loginCompletion.CompleteAsync(
                outcome.Identity,
                response,
                config,
                AdoptionGate.None,
                remoteEndPointResolver).ConfigureAwait(false);
        }

        // DEPRECATION WINDOW (#251, drop scheduled by #528): a page rendered by a PRE-#251
        // plugin still embeds the full base64 assertion and posts it here. For one release SAML/Auth also
        // accepts that legacy shape and FULLY validates it — signature/time/audience/recipient, the
        // InResponseTo correlation + browser binding, the login allow-list, and the one-time replay consume —
        // exactly as before #251, so an admin upgrading mid-login does not break a user's in-flight login.
        // The plugin itself renders only tokens going forward; this branch is removed once the window closes.
        var requestBase = GetRequestBase(request, config.SchemeOverride, config.PortOverride, config.BaseUrlOverride);
        if (!_validator.TryValidate(config, provider, requestBase, response?.Data, out var samlResponse))
        {
            // A malformed body, an unknown/expired/replayed token that reached this fallback, or a failed
            // signature/time/audience/recipient check is rejected the same way — a clean 4xx, never a 500 (#199).
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        if (!CorrelateAndBind(provider, samlResponse.GetInResponseTo(), bindingCookie, config.ValidateInResponseTo))
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // Enforce the login allow-list here too, not only at the assertion-consumer page: a legacy caller
        // can POST an assertion straight to this session-minting endpoint and skip the page, so checking it
        // only there would be fail-open.
        if (!SamlLoginPolicy.IsLoginAllowed(SamlAssertionValidator.GetAssertionRoles(samlResponse), config.Roles))
        {
            _logger.LogWarning(
                "SAML user: {UserId} has insufficient roles at the session-minting endpoint; login denied.",
                samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty));
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
        }

        // Complete the assertion validation in the dedicated validator: the one-time replay consume and the
        // non-empty-NameID guard, then — and only then — the verified identity through FromValidatedSaml
        // (#496). A replay fails as an invalid response and a missing NameID as a denial.
        if (!_validator.TryProduceVerifiedIdentity(config, provider, samlResponse, out var identity, out var rejection))
        {
            return LoginStatusMapper.ToActionResult(rejection);
        }

        return await _loginCompletion.CompleteAsync(
            identity,
            response,
            config,
            AdoptionGate.None,
            remoteEndPointResolver).ConfigureAwait(false);
    }

    // Correlates a response to an AuthnRequest this server issued (#156, #415) and enforces the browser
    // binding for a solicited login. A NON-EMPTY InResponseTo means the response claims to answer a request
    // this server issued, so it must actually correlate to a live outstanding request AND carry that
    // request's binding cookie — anything less fails closed. Crucially, a non-empty InResponseTo whose entry
    // is gone (expired past the 15-minute window, evicted at the cap, lost to a restart or a non-sticky
    // multi-node hop) is a LOST correlation, not an unsolicited response: treating it as unsolicited would
    // let a validated response complete a login with no binding check when ValidateInResponseTo is off, which
    // is exactly the forced-login bypass the binding exists to close (login validity must never default to
    // true). The consume is the atomic claim of the outstanding request; the cookie match is checked at this
    // same-origin auth endpoint, not at the cross-site ACS POST which would not carry a SameSite=Lax cookie.
    // Shared by the token-redeem mint path (on the stored outcome's InResponseTo) and the deprecation branch
    // (on the freshly parsed response), so both enforce the identical correlation.
    private bool CorrelateAndBind(string provider, string inResponseTo, string bindingCookie, bool validateInResponseTo)
    {
        if (!string.IsNullOrEmpty(inResponseTo))
        {
            var requestKey = ProviderScopedKey.For(provider, inResponseTo);
            if (!SamlRequests.TryConsume(requestKey, DateTime.UtcNow, out var storedBindingId)
                || !AuthorizeStateBinding.Matches(storedBindingId, bindingCookie))
            {
                _logger.LogWarning("SAML login denied: a solicited response did not correlate to a live outstanding request from the initiating browser (binding mismatch, expiry, or lost correlation).");
                return false;
            }
        }
        else if (validateInResponseTo)
        {
            // No InResponseTo at all: a genuinely unsolicited (IdP-initiated) response. It is refused only
            // when the opt-in solicited-only mode is on; otherwise it proceeds — unchanged and non-breaking
            // for IdP-initiated deployments.
            _logger.LogWarning("SAML login denied: the response was not solicited by this server (no InResponseTo).");
            return false;
        }

        return true;
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

        var requestBase = GetRequestBase(request, config.SchemeOverride, config.PortOverride, config.BaseUrlOverride);
        if (!_validator.TryValidate(config, provider, requestBase, response?.Data, out var samlResponse))
        {
            // Malformed input is rejected the same way an invalid response is — clean 4xx, not 500 (#199).
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // Enforce one-time use here too (#219): without it, a captured, still-valid assertion could be
        // replayed to bind its NameID to the caller's account. The linking flow issues no AuthnRequest,
        // so InResponseTo is not correlated here — the replay cache is the applicable one-time-use
        // control. A replay is a client-caused 400 in the uniform SAML body, never a 500, and no longer
        // discloses the replay cache to the attacker who replayed.
        if (!_validator.TryConsumeReplay(samlResponse, provider))
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
    // login's spelling. A linking challenge only reads the stored value. (See SamlAssertionValidator's
    // ExpectedAcsUrls for the same reason this value is remembered across requests.) Mirrors
    // OidcLoginService.ResolveChallengeNewPath —
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
        using (var signingKey = SamlSigningKey.GetSigningKey(signingCertificate))
        {
            if (signingKey is null)
            {
                throw new InvalidOperationException("Outgoing SAML request signing is enabled but the signing key has no RSA or ECDSA private key.");
            }

            return request.GetSignedRedirectUrl(endpoint, relayState, signingKey);
        }
    }

    // Thin adapter feeding the live request values into the pure CanonicalBaseUrl.Resolve decision (#242) —
    // the same decision OidcLoginService.RequestBaseUrl feeds for OpenID, kept as a local read so this flow
    // tier is self-contained.
    private static string GetRequestBase(HttpRequest request, string schemeOverride, int? portOverride, string baseUrlOverride) =>
        CanonicalBaseUrl.Resolve(baseUrlOverride, request.Scheme, request.Host.Host, request.Host.Port, request.PathBase, schemeOverride, portOverride);
}

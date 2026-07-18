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

    // How long an issued SAML AuthnRequest ID stays valid for correlation — the interactive leg
    // (challenge -> IdP login/MFA -> POST back -> mint), matching the OpenID authorize-state lifetime the
    // sibling flow service keeps.
    private static readonly TimeSpan SamlRequestLifetime = TimeSpan.FromMinutes(15);

    // The in-flight login-outcome store (#251): the ACS callback validates the assertion ONCE, stores the
    // resulting verified outcome keyed by a CSPRNG token, and hands the intermediate page only that token;
    // the session-mint leg redeems the token instead of re-parsing and re-validating the assertion. One
    // process-wide instance, like the outstanding-request cache above — the callback and the mint leg run
    // across separate per-request flow-service instances. Reassigned only by the test-only reset/swap hooks
    // below (production sets it once); the field is not readonly solely so those hooks can install a
    // small-cap store to exercise the cap path that the production ceiling makes unreachable.
    private static SamlOutcomeStore _outcomes = new SamlOutcomeStore();

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

    // Throttles how often an actual NewPath change is persisted (#412 review follow-up). Both route
    // spellings stay permanently live side by side (ChallengePath/SsoUrlBuilder never retire either one),
    // so a provider used concurrently by clients on both is EXPECTED to flip this value on alternating
    // logins — ExpectedAcsUrls (near ResolveChallengeNewPath below) already treats a flip as routine, not
    // a rare edge case. Without a cap, that ordinary traffic shape would turn every such login into a
    // synchronous config persist under the process-wide config lock, serializing every OID/SAML login on
    // the server (not just this provider's) behind disk I/O. NewPath is only ever consulted by a LATER,
    // separate linking challenge — never this request's own redirect, which always uses its own
    // freshly-derived value regardless of whether a write lands — so bounding this to one persist attempt
    // per interval, process-wide, is harmless: it only delays how soon a flapping spelling's latest value
    // reaches disk. Not readonly, for the same reason as _outcomes above: ResetSamlRequestsForTests
    // installs a fresh gate between tests, so one test's persisted change cannot throttle a later test's.
    private static IntervalGate _newPathPersistGate = new(TimeSpan.FromSeconds(5));

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
    // InternalsVisibleTo, no endpoint/DI). Moved here with the statics from the controller (#160). Also
    // installs a fresh NewPath persist-throttle gate (#412 review follow-up): SsoControllerHarness calls
    // this for every test, so a change persisted in one test can never throttle a genuine change in the
    // next one.
    internal static void ResetSamlRequestsForTests()
    {
        SamlRequests.Clear();
        _newPathPersistGate = new IntervalGate(TimeSpan.FromSeconds(5));
    }

    // Test-only: restores a fresh default in-flight login-outcome store (#251) between tests, the same
    // process-wide-static reset reason as ResetSamlRequestsForTests. Installing a new instance (rather than
    // Clear) also un-swaps any small-cap store a prior test installed via SetSamlOutcomeStoreForTests, so cap
    // state cannot leak across tests. Internal, InternalsVisibleTo, never wired to an endpoint/DI.
    internal static void ResetSamlOutcomesForTests() => _outcomes = new SamlOutcomeStore();

    // Test-only: swaps in a specific outcome store so a test can drive the cap path the production ceiling
    // (100k) makes unreachable — e.g. proving a cap refusal at the ACS callback no longer burns the assertion
    // (#539). Un-swapped by the next ResetSamlOutcomesForTests. Internal, InternalsVisibleTo, no endpoint/DI.
    internal static void SetSamlOutcomeStoreForTests(SamlOutcomeStore store) => _outcomes = store;

    // Test-only: seeds a single login outcome so a test can drive the token-redeem mint leg without first
    // running the callback that normally populates the store. Same test-only surface as the resets above.
    internal static void SeedSamlOutcomeForTests(SamlLoginOutcome outcome) => _outcomes.Seed(outcome);

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
        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation(
                "SAML request has relayState of {RelayState}",
                relayState?.ReplaceLineEndings(string.Empty));
        }

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
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SAML user: {UserId} has insufficient roles: {@Roles}. Expected any one of: {@ExpectedRoles}",
                    samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty),
                    SamlAssertionValidator.GetAssertionRoles(samlResponse).Select(r => r?.ReplaceLineEndings(string.Empty)),
                    config.Roles);
            }

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
        //
        // Reserve the outcome-store slot BEFORE the replay consume (#539). The consume is one-time: an
        // assertion recorded as used can never be presented again. So if the store refused AFTER the consume,
        // a cap refusal would burn the assertion for a login that never completed and permanently lock the
        // legitimate user out even though nothing malicious happened. Reserving first means a capacity refusal
        // fails closed here with the assertion untouched, so the user can retry once the store drains. Replay
        // protection is unchanged: the consume below is still the atomic one-time claim, it now runs only once
        // a slot is secured, and any failure between reserve and commit releases the reservation — so a
        // committed login always consumed the assertion and a consumed assertion always completed (or was a
        // genuine replay/invalid assertion, which still fails closed without minting).
        var clientKey = SsoRateLimiter.NormalizeClientKey(request.HttpContext.Connection.RemoteIpAddress);
        _outcomes.PruneExpired(DateTime.UtcNow);
        if (!_outcomes.TryReserve(clientKey, DateTime.UtcNow, out var shouldWarnCapacity))
        {
            // The per-client sub-cap or the global cap refused this login's outcome slot — fail closed BEFORE
            // the replay consume, so the assertion is not recorded as used and the login can be retried once
            // the store drains. The store throttles the capacity warning to one signal per interval so a flood
            // cannot amplify into log volume (CWE-400).
            if (shouldWarnCapacity)
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning("SAML login outcome refused for provider {Provider}: the per-client sub-cap or the outcome store is at capacity (warning throttled); the assertion was not consumed, so the login can be retried.", provider?.ReplaceLineEndings(string.Empty));
                }
            }

            return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
        }

        // Slot secured: now consume the one-time replay cache and build the verified identity. Everything from
        // here until the outcome is committed runs under a finally that releases the reservation unless it was
        // handed to a committed outcome — so "exactly one release per reservation" is structural, covering both
        // the fail-closed returns (a genuine replay or a NameID-less assertion, which mint nothing) AND any
        // unexpected throw between reserve and commit; a per-client slot can never leak.
        bool committed = false;
        try
        {
            if (!_validator.TryProduceVerifiedIdentity(config, provider, samlResponse, out var identity, out var rejection))
            {
                // A genuine replay (or an assertion with no usable NameID) still fails closed here, minting
                // nothing — so moving the capacity check ahead of the consume never lets a replayed assertion
                // through. The reserved slot is freed by the finally.
                return LoginStatusMapper.ToActionResult(rejection);
            }

            var outcome = new SamlLoginOutcome(
                SamlOutcomeStore.NewToken(),
                provider,
                identity,
                samlResponse.GetInResponseTo() ?? string.Empty,
                clientKey,
                DateTime.UtcNow);
            if (!_outcomes.CommitReserved(outcome))
            {
                // Only reachable on an effectively-impossible CSPRNG-token collision — the capacity was already
                // reserved, so this is not a cap refusal. The assertion is one-time and already consumed here,
                // so this ~2^-256 event fails closed (unretryable) rather than rendering a token that could
                // never redeem. The finally frees the reserved slot.
                return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
            }

            // The committed outcome now owns the reserved slot (released on its redeem or prune), so the finally
            // must NOT free it. AuthPage renders the token eagerly, so it is read before the finally runs.
            committed = true;
            return FlowResponses.AuthPage(response, nonce =>
                WebResponse.Generator(
                    data: outcome.Token,
                    provider: provider,
                    baseUrl: requestBase,
                    mode: "SAML",
                    nonce: nonce,
                    isLinking: false));
        }
        finally
        {
            if (!committed)
            {
                _outcomes.ReleaseReservation(clientKey);
            }
        }
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

        bool newPath = ResolveChallengeNewPath(provider, config, isLinking, request, _logger);

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
                    if (_logger.IsEnabled(LogLevel.Warning))
                    {
                        _logger.LogWarning("SAML request refused for provider {Provider}: the per-client sub-cap or the outstanding-request cache is at capacity (warning throttled).", provider?.ReplaceLineEndings(string.Empty));
                    }
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
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or CryptographicException or FormatException)
        {
            // Signing is enabled for this provider but the request could not be signed: the key is
            // missing/unusable (InvalidOperationException), the endpoint is empty (ArgumentException from
            // the signer), the platform key store refused the signing operation, or the at-rest signing
            // key could not be decrypted — the key file is missing/corrupt (CryptographicException) or the
            // stored envelope is corrupt (FormatException, #158). ANY of these fails closed with a clean
            // 500 — never a silent unsigned request — rather than escaping as a raw host 500. The key
            // material is not part of the message, so nothing sensitive is logged.
            if (_logger.IsEnabled(LogLevel.Error))
            {
                _logger.LogError("SAML challenge for provider {Provider} could not sign the AuthnRequest: {Reason}", provider?.ReplaceLineEndings(string.Empty), ex.Message);
            }

            return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; the SAML request signing key is misconfigured.");
        }

        return new RedirectResult(redirectUrl);
    }

    /// <summary>
    /// Serves this service provider's SAML 2.0 metadata for <paramref name="provider"/> (#162), so an
    /// administrator can register the SP at the identity provider by URL rather than hand-configuring the
    /// entity id, assertion-consumer URL and signing certificate. Anonymous by design — SP metadata is
    /// public — and deliberately request-free: unlike the login flow, it refuses to derive the published
    /// entity id/ACS from the request <c>Host</c>. Both are built ONLY from the provider's configured
    /// canonical Base URL (<see cref="Config.ProviderConfigBase.BaseUrlOverride"/>, #139); if that is not
    /// configured the endpoint fails closed rather than publish a spoofable ACS an attacker could point the
    /// identity provider at (RFC 9700 sect. 4.1). The signing certificate is advertised only when request
    /// signing is enabled, and only ever as the PUBLIC certificate.
    /// </summary>
    /// <param name="provider">The SAML provider whose metadata to serve.</param>
    /// <returns>The SP metadata document, or a fail-closed rejection when the provider is unknown/disabled or its metadata prerequisites are unconfigured.</returns>
    internal ActionResult Metadata(string provider)
    {
        // Unknown and disabled providers share the login flow's uniform rejection, so a disabled provider
        // does not expose its entity id / signing certificate through this anonymous surface either.
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        // The published ACS/entity id MUST be non-spoofable: build them ONLY from the configured canonical
        // Base URL, never the request Host (which a reverse proxy forwarding an unfiltered X-Forwarded-Host
        // could influence). With no canonical Base URL configured, fail closed rather than bake a
        // request-derived value into metadata an identity provider consumes to decide where to POST
        // assertions — the login flow may fall back to the request host, but published metadata must not.
        if (!CanonicalBaseUrl.TryNormalize(config.BaseUrlOverride, out var baseUrl))
        {
            return FlowResponses.PlainTextError(
                StatusCodes.Status409Conflict,
                "SAML metadata is unavailable: configure this provider's canonical Base URL first, so the published assertion-consumer URL cannot be derived from a spoofable request host.");
        }

        // The entity id is the value the challenge sends as the AuthnRequest Issuer (the client id); an
        // enabled SAML provider always has one, but guard fail-closed rather than emit metadata with an
        // empty entityID.
        var entityId = config.SamlClientId?.Trim();
        if (string.IsNullOrEmpty(entityId))
        {
            return FlowResponses.PlainTextError(
                StatusCodes.Status409Conflict,
                "SAML metadata is unavailable: this provider has no client id (SP entity id) configured.");
        }

        // Advertise the canonical new-path ACS spelling; the SP accepts either spelling on the way back
        // (SsoUrlBuilder.SamlExpectedAcsUrls), so publishing one is unambiguous for the identity provider.
        var acsUrl = SsoUrlBuilder.SamlAcsUrl(baseUrl, newPath: true, provider);

        if (!TryResolveSigningCertificates(config, out var signingCertificateBase64, out var rolloverSigningCertificateBase64))
        {
            // Request signing is enabled but a configured signing key could not be loaded — the same
            // fail-closed posture the signed challenge takes, so metadata never advertises signing the
            // challenge would then fail to perform, and never emits a broken KeyDescriptor for a set-but-
            // unloadable rollover key (#491).
            return FlowResponses.PlainTextError(
                StatusCodes.Status409Conflict,
                "SAML metadata is unavailable: request signing is enabled but a configured signing key could not be loaded.");
        }

        return new ContentResult
        {
            Content = SamlSpMetadataBuilder.Build(entityId, acsUrl, signingCertificateBase64, rolloverSigningCertificateBase64),
            ContentType = "application/samlmetadata+xml",
            StatusCode = StatusCodes.Status200OK,
        };
    }

    // Resolves the PUBLIC signing certificate(s) to advertise in the metadata. Both out values are null when
    // request signing is off (no KeyDescriptor). When it is on, the PRIMARY is mandatory — a set-but-
    // unloadable primary fails closed (false), mirroring BuildChallengeRedirectUrl so metadata never
    // advertises signing the challenge could not perform. The ROLLOVER (#491) is optional: a blank stored
    // value means no overlap window (single descriptor, byte-for-byte the pre-#491 output); a set-but-
    // unloadable rollover key also fails closed (false), so a hand-corrupted rollover key surfaces loudly as
    // a 409 rather than silently dropping a key the admin configured. When the rollover certificate is
    // identical to the primary — the natural end state after promoting the rollover into the primary field —
    // the redundant second descriptor is dropped, returning to a single descriptor without needing to blank
    // the write-only, blank-keeps-stored rollover key. Only the public RawData of each certificate is
    // exported; no private key ever leaves this method.
    private static bool TryResolveSigningCertificates(SamlConfig config, out string signingCertificateBase64, out string rolloverSigningCertificateBase64)
    {
        signingCertificateBase64 = null;
        rolloverSigningCertificateBase64 = null;
        if (!config.SignAuthnRequests)
        {
            return true;
        }

        if (!TryRevealPublicCertificate(config.SamlSigningKeyPfx, out signingCertificateBase64))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(config.SamlRolloverSigningKeyPfx))
        {
            return true;
        }

        if (!TryRevealPublicCertificate(config.SamlRolloverSigningKeyPfx, out rolloverSigningCertificateBase64))
        {
            return false;
        }

        if (string.Equals(rolloverSigningCertificateBase64, signingCertificateBase64, StringComparison.Ordinal))
        {
            rolloverSigningCertificateBase64 = null;
        }

        return true;
    }

    // Reveals a stored signing key (encrypted at rest, #158) and exports its PUBLIC certificate as Base64
    // (DER). Fail-closed: a missing/corrupt at-rest key throws CryptographicException, and a garbage or
    // private-key-less PKCS#12 fails to load — both return false so the caller emits no descriptor for it.
    // The private key never leaves this method; only certificate.RawData (the public DER) is exported.
    private static bool TryRevealPublicCertificate(string storedPfx, out string publicCertificateBase64)
    {
        publicCertificateBase64 = null;

        string revealed;
        try
        {
            revealed = SSOPlugin.Instance.Secrets.Reveal(storedPfx);
        }
        catch (CryptographicException)
        {
            return false;
        }

        if (!SamlSigningKey.TryLoad(revealed, out var certificate))
        {
            return false;
        }

        using (certificate)
        {
            publicCertificateBase64 = Convert.ToBase64String(certificate.RawData);
            return true;
        }
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
        if (_outcomes.TryRedeem(response?.Data, provider, DateTime.UtcNow) is { } outcome)
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
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SAML user: {UserId} has insufficient roles at the session-minting endpoint; login denied.",
                    samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty));
            }

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
    // OidcLoginService.ResolveChallengeNewPath.
    //
    // The record itself goes through MutateConfiguration rather than a bare field assignment (#412): the
    // `config` the caller passes in was read under ReadConfiguration's lock, which is released before this
    // runs, so writing straight into it raced a concurrent challenge for the same provider and never went
    // through the write path every other config mutation uses. The Mutate delegate re-resolves the
    // provider by name instead of trusting the outer `config` reference, so one deleted/disabled in that
    // race window is not written into. A plain locked comparison with no write serves the case where the
    // derived spelling already matches what is stored; an actual change is throttled by
    // _newPathPersistGate (see its comment) rather than persisted on every mismatched challenge, and a
    // persist failure is swallowed — this write is best-effort bookkeeping for a later login, never a
    // requirement for THIS one to succeed. Internal (not private) so ProviderConfigStoreTests-style
    // callers can exercise the race-window fallback branch directly and deterministically, the way
    // ResetSamlRequestsForTests-style hooks already do for other login-flow internals.
    internal static bool ResolveChallengeNewPath(string provider, SamlConfig config, bool isLinking, HttpRequest request, ILogger logger)
    {
        if (isLinking)
        {
            return config.NewPath;
        }

        var derived = ChallengePath.IsNewPath(request.Path.Value);
        if (derived == config.NewPath || !_newPathPersistGate.TryEnter(DateTime.Now))
        {
            return derived;
        }

        try
        {
            return SSOPlugin.Instance.MutateConfiguration(configuration =>
            {
                if (configuration.SamlConfigs.TryGetValue(provider, out var liveConfig) && liveConfig is { Enabled: true })
                {
                    liveConfig.NewPath = derived;
                }

                // The current redirect always uses `derived` regardless of whether the write above landed —
                // it reflects this request's own path, exactly like a read-only resolution would have.
                return derived;
            });
        }
        catch (Exception ex)
        {
            // Best-effort: a config-persist failure here (full disk, permissions, a corrupt secret
            // envelope surfacing mid-ProtectAll) must not turn an otherwise-valid login into a 500 over a
            // value that only helps a LATER linking flow guess the right spelling. Broad on purpose —
            // every persist failure is handled identically — but logged so a persistently failing config
            // write stays observable rather than silently accepted forever (mirrors AvatarService's
            // best-effort avatar fetch).
            logger?.LogWarning(ex, "Could not record the NewPath redirect spelling for provider {Provider}; this login proceeds with its own derived value.", provider?.ReplaceLineEndings(string.Empty));
            return derived;
        }
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

        // The signing key is stored encrypted at rest (#158); reveal it at the point of use. A legacy
        // plaintext value passes through unchanged (transparent migration); a missing/corrupt key throws
        // (CryptographicException), which the caller's signing try/catch turns into a clean fail-closed 500
        // rather than a silent unsigned request.
        if (!SamlSigningKey.TryLoad(SSOPlugin.Instance.Secrets.Reveal(config.SamlSigningKeyPfx), out var signingCertificate))
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

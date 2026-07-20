using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// The single home for inbound SAML assertion validation (#496, #318): parse plus signature, time-bound,
/// audience, recipient and algorithm-allowlist validation, the one-time replay consume, and the non-empty
/// NameID guard — the whole <c>IsSamlResponseValid</c>/<c>ValidateSaml</c>/replay path that used to be
/// spread across <see cref="Flows.SamlLoginService"/>. Consolidating it here makes the "a
/// <see cref="VerifiedIdentity"/> is produced ONLY after complete validation" invariant local and testable:
/// the sole SAML call to <see cref="VerifiedIdentity.FromValidatedSaml"/> lives in
/// <see cref="TryProduceVerifiedIdentity"/>, downstream of every gate here, and is pinned there by
/// <c>ArchitectureConformanceTests.VerifiedIdentity_IsConstructedOnlyByProtocolValidators</c>.
/// </summary>
/// <remarks>
/// This validator owns the assertion-validation concerns only; the flow service keeps the concerns that are
/// not assertion validation and must stay where the request context lives:
/// <list type="bullet">
/// <item>the login allow-list (<see cref="SamlLoginPolicy"/>), a policy gate enforced at BOTH the
/// assertion-consumer page and the session-minting endpoint;</item>
/// <item>the InResponseTo correlation and browser binding (the outstanding-request cache), which is
/// session-fixation correlation against a request this server issued, not assertion validation.</item>
/// </list>
/// The one-time replay cache is a <c>static readonly</c> field so it is process-wide exactly as it was on
/// the flow service — a fresh per-request flow service (and so a fresh validator) must not lose the consumed
/// assertion ids between the two-step post-then-authenticate legs.
/// </remarks>
internal sealed class SamlAssertionValidator
{
    // The SAML attribute name the whole RBAC design hinges on (the role allow-list check and the derived
    // authorize-state privileges both read it). One definition site, on the type that reads assertions, so
    // every read agrees on the exact attribute the identity provider must send (#370); the flow service
    // reads roles through GetAssertionRoles rather than re-declaring the name.
    private const string RoleAttributeName = "Role";

    // One-time-use tracking for consumed SAML assertion IDs (replay protection). One process-wide instance,
    // like the outstanding-request cache the flow service keeps and the OpenID caches the sibling flow
    // service keeps — the two-step post-then-authenticate legs run across separate per-request instances.
    private static readonly SamlReplayCache SamlReplays = new SamlReplayCache();

    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlAssertionValidator"/> class. Constructed per request
    /// by the SAML flow service, though it owns the process-wide replay cache as a static.
    /// </summary>
    /// <param name="logger">The logger for validation-failure diagnostics.</param>
    internal SamlAssertionValidator(ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // Test-only: clears the process-wide one-time replay cache between tests, the same static-state reset
    // reason as the flow service's request/outcome resets — a test that consumed an assertion id must not
    // leak it into a sibling test. Internal, reachable only through InternalsVisibleTo; never wired to an
    // endpoint or DI, so it adds no runtime or security surface.

    /// <summary>
    /// Test-only. Clears the process-wide one-time replay cache between tests so a consumed assertion id
    /// does not leak into a sibling test.
    /// </summary>
    internal static void ResetReplaysForTests() => SamlReplays.Clear();

    /// <summary>
    /// Reads the assertion's role values under the one role-attribute definition, so the flow service's
    /// policy check and warning logs read the exact same attribute the derived privileges here do (#370).
    /// </summary>
    /// <param name="samlResponse">The (already signature-validated) assertion to read.</param>
    /// <returns>The role values the assertion carries.</returns>
    internal static List<string> GetAssertionRoles(SamlResponse samlResponse) =>
        samlResponse.GetCustomAttributes(RoleAttributeName);

    /// <summary>
    /// Parses the untrusted response and runs the response-level validation shared by every SAML leg:
    /// signature, time bounds and audience (<see cref="ValidateSaml"/>) plus the opt-in recipient binding.
    /// On failure it logs the declared signature algorithm and the weak-algorithm remediation hint so an
    /// operator can tell a rejected SHA-1 signature (the expected post-upgrade lockout of a legacy IdP) apart
    /// from a bad certificate, an expired assertion, or an audience mismatch, all of which otherwise surface
    /// as the same opaque error.
    /// </summary>
    /// <param name="config">The provider configuration (signing certificate, audience, recipient opt-in).</param>
    /// <param name="provider">The provider that is calling back (for the expected assertion-consumer URLs).</param>
    /// <param name="requestBaseUrl">The resolved assertion-consumer base URL the Recipient is bound to.</param>
    /// <param name="rawResponse">The untrusted, Base64-encoded SAMLResponse.</param>
    /// <param name="samlResponse">The parsed, validated response on success; otherwise null.</param>
    /// <returns>True when the response parsed and passed response-level validation; otherwise false.</returns>
    internal bool TryValidate(SamlConfig config, string provider, string requestBaseUrl, string rawResponse, out SamlResponse samlResponse)
    {
        // A malformed response (non-base64, malformed XML, prohibited DOCTYPE) fails TryParse and is
        // rejected the same way an invalid one is — a clean 4xx, never an unhandled 500 (#199). The
        // optional secondary certificate is passed alongside the primary so a response signed by either is
        // accepted across an identity-provider signing-key overlap window (#491); when it is blank the
        // trial narrows to the primary alone (both the primary and any secondary are additionally required
        // to be within their validity window — see IsWithinValidityPeriod).
        if (!SamlResponseLoader.TryParse(config.SamlCertificate, config.SamlSecondaryCertificate, rawResponse, out samlResponse))
        {
            return false;
        }

        if (!IsResponseValid(config, provider, requestBaseUrl, samlResponse))
        {
            // The response parsed but failed response-level validation. It owns an unmanaged certificate
            // handle (#674), and the caller only ever consumes samlResponse on the true path, so dispose it
            // here and null the out parameter — honoring the "otherwise null" out contract so a caller can
            // never read (or be handed) a rejected, half-consumed response.
            samlResponse.Dispose();
            samlResponse = null;
            return false;
        }

        return true;
    }

    /// <summary>
    /// Consumes the SAML assertion's ID against the provider-scoped replay cache for one-time use. Returns
    /// false when the assertion was already used (or carries no ID — a missing ID stays empty, so TryConsume
    /// fails closed). The key is scoped by provider so two IdPs emitting the same assertion ID cannot block
    /// each other. Shared by the session mint and the account linking (#219).
    /// </summary>
    /// <param name="samlResponse">The validated response whose assertion ID is consumed.</param>
    /// <param name="provider">The provider the assertion ID is scoped under.</param>
    /// <returns>True on the first use; false on a replay (or a missing assertion ID).</returns>
    internal bool TryConsumeReplay(SamlResponse samlResponse, string provider)
    {
        var samlNow = DateTime.UtcNow;
        var replayRetention = SamlReplayCache.ComputeRetention(samlNow, samlResponse.GetNotOnOrAfter());
        var assertionId = samlResponse.GetAssertionId();
        var replayKey = ProviderScopedKey.For(provider, assertionId);
        var consumed = SamlReplays.TryConsume(replayKey, replayRetention, samlNow, out var shouldWarnCapacity);
        if (shouldWarnCapacity)
        {
            // The replay cache turned away a NEW assertion at its hard cap: the login already failed closed
            // (consumed is false). This is the single observation point for every replay consume — the login
            // mint, the deprecation-window mint leg, and the manual link redeem all funnel through here — so
            // surfacing it here covers them all, throttled once per interval by the cache's own gate. A full
            // replay cache is only reachable under extreme login volume or a compromised identity provider
            // replaying signed assertions, so it is a genuine operator signal (#470). provider is
            // identity-provider-routed input; strip line endings inline at the log call to prevent log forging
            // (a helper-boundary sanitizer is not recognized by CodeQL).
            _logger.LogWarning(
                "SAML assertion replay cache refused a new assertion for provider {Provider}: the cache is at capacity (warning throttled). This indicates extreme login volume or an identity provider replaying signed assertions.",
                provider?.ReplaceLineEndings(string.Empty));
        }

        return consumed;
    }

    /// <summary>
    /// Completes the SAML session-minting validation on a response that already passed
    /// <see cref="TryValidate"/>, the login allow-list, and the InResponseTo correlation: it enforces the
    /// one-time replay consume and the non-empty NameID guard, then — and only then — produces the verified
    /// identity through <see cref="VerifiedIdentity.FromValidatedSaml"/>. This is the sole SAML construction
    /// site of a <see cref="VerifiedIdentity"/>, so the "produced only after complete validation" invariant
    /// is local here.
    /// </summary>
    /// <param name="config">The provider configuration the privileges are derived against.</param>
    /// <param name="provider">The provider that verified the login.</param>
    /// <param name="samlResponse">The validated, allow-listed, correlated response.</param>
    /// <param name="assertionRoles">The assertion's role values, already evaluated once by the flow service for
    /// the login allow-list; reused here for the privilege derivation instead of re-reading the assertion (#479).</param>
    /// <param name="identity">The verified identity on success; otherwise null.</param>
    /// <param name="rejection">The fail-closed outcome on failure; otherwise null.</param>
    /// <returns>True with <paramref name="identity"/> set on success; false with <paramref name="rejection"/> set.</returns>
    internal bool TryProduceVerifiedIdentity(SamlConfig config, string provider, SamlResponse samlResponse, IReadOnlyList<string> assertionRoles, out VerifiedIdentity identity, out LoginOutcome rejection)
    {
        identity = null;

        // Enforce one-time use so a captured assertion cannot be replayed to mint another session.
        // Enforced only at the session-minting endpoint (and the link redeem), not at the SAML/post ACS
        // which merely renders the intermediate page, so the two-step post-then-auth flow consumes the id
        // once. A replay is a client-caused 400 in the uniform SAML body — it no longer discloses the replay
        // cache to the attacker who replayed, and the log-side diagnosis is unchanged.
        if (!TryConsumeReplay(samlResponse, provider))
        {
            rejection = new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid);
            return false;
        }

        // Derive the authorize-state privileges (admin, Live TV, Live TV management, folders) from the
        // assertion's roles and the provider configuration. The roles were already evaluated once by the flow
        // service for the login allow-list and are threaded in here, so the role XPath runs a single time per
        // response rather than once for the gate and again for this derivation (#479). Login validity was
        // already decided by SamlLoginPolicy at the flow service and the username is the assertion's NameID, so
        // neither is derived here.
        var derived = SamlAuthorizeStateBuilder.Build(assertionRoles, config);

        // Fail closed (#95): an assertion without a usable NameID carries no identity to log in — reject it
        // as an invalid login instead of failing downstream on a null canonical name. Whitespace-only counts
        // as unresolved (Jellyfin's username validation rejects it anyway).
        var nameId = samlResponse.GetNameID();
        if (string.IsNullOrWhiteSpace(nameId))
        {
            _logger.LogWarning("SAML login denied: the assertion resolved no NameID.");
            rejection = new LoginOutcome.Denied();
            return false;
        }

        // All SAML validation has now passed — signature, time bounds, audience, recipient, InResponseTo
        // correlation, the login allow-list, replay one-time-use, and the non-empty-NameID guard — so this
        // is the point at which the response becomes a fully-verified SAML identity (#473). SAML keys the
        // link directly on the NameID (subject and username are the same value; no migration path needed)
        // and carries no email_verified claim, so the verified-email gate is not applicable at the caller
        // (AdoptionGate.None); the resolver's unconditional admin-adoption refusal (#218) still applies.
        rejection = null;
        // Destructure the validated assertion into the protocol-agnostic ValidatedLogin the keystone takes
        // (#790). SAML keys the link directly on the NameID (subject and username are the same value) and
        // carries no email_verified claim, avatar, or issuer binding (all null — issuer binding is OpenID
        // only, #186).
        identity = VerifiedIdentity.FromValidatedSaml(new ValidatedLogin
        {
            Provider = provider,
            Subject = nameId,
            Issuer = null,
            Username = nameId,
            EmailVerified = null,
            Admin = derived.Admin,
            Folders = derived.Folders,
            EnableLiveTv = derived.EnableLiveTv,
            EnableLiveTvManagement = derived.EnableLiveTvManagement,
            AvatarUrl = null,
            PermissionGrants = derived.PermissionGrants ?? Array.Empty<PermissionGrant>(),
            MaxParentalRatingScore = derived.MaxParentalRatingScore,
        });
        return true;
    }

    // Validates a SAML response: signature + time bounds always, plus AudienceRestriction binding to this SP
    // unless explicitly opted out. Expected audience is the configured SamlAudience, falling back to the
    // SamlClientId (SP entity id). Both are trimmed so the comparison matches the trimmed Issuer sent in the
    // AuthnRequest, and an empty SamlAudience falls through to the client id.

    /// <summary>
    /// Validates a SAML response's signature and time bounds, and — unless the provider explicitly opts out —
    /// its AudienceRestriction binding to this service provider. The expected audience is the configured
    /// <c>SamlAudience</c>, falling back to the <c>SamlClientId</c>.
    /// </summary>
    /// <param name="samlResponse">The response to validate.</param>
    /// <param name="config">The provider configuration supplying the expected audience and the opt-out flag.</param>
    /// <returns>True if the response passes every applicable check; false otherwise.</returns>
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

    // Runs the response-level validation and, on failure, logs the declared signature algorithm plus the
    // weak-algorithm remediation hint (see TryValidate). Split from TryValidate so the parse and the
    // validation read as two distinct steps.
    private bool IsResponseValid(SamlConfig config, string provider, string requestBaseUrl, SamlResponse samlResponse)
    {
        if (!ValidateSaml(samlResponse, config))
        {
            // The algorithm URI is identity-provider-controlled; strip line endings inline at the log call to
            // prevent log forging (a helper-boundary sanitizer is not recognized by CodeQL).
            _logger.LogWarning(
                "SAML response validation failed (signature algorithm: {Algorithm}). SHA-1 is rejected; if that is the identity provider's algorithm, reconfigure it to sign with RSA/ECDSA-SHA-256 or stronger.",
                samlResponse.GetSignatureAlgorithm()?.ReplaceLineEndings(string.Empty));
            return false;
        }

        // Endpoint binding (#156, opt-in): the signed assertion must be addressed to this service provider's
        // assertion-consumer URL, so an assertion minted for a different endpoint (or a different SP sharing
        // the identity provider) cannot be presented here.
        if (config.ValidateRecipient
            && !SamlRecipientValidator.IsBound(samlResponse.GetRecipient(), samlResponse.GetDestination(), ExpectedAcsUrls(requestBaseUrl, provider)))
        {
            _logger.LogWarning("SAML response rejected: the assertion Recipient or Response Destination does not match this server's assertion-consumer URL.");
            return false;
        }

        return true;
    }

    // The assertion-consumer URLs this service provider advertises for the provider — the same value the
    // challenge puts in the AuthnRequest's AssertionConsumerServiceURL, so a signed Recipient (or
    // Destination) must equal one. Both the new ("post") and legacy ("p") path spellings are returned:
    // config.NewPath is process-wide mutable state a concurrent challenge can flip, and the Recipient
    // reflects whichever the AuthnRequest advertised at challenge time, so accepting either avoids rejecting
    // a valid login on a path-form flip; both are this provider's own ACS URLs. The base URL is resolved by
    // the flow service (with BaseUrlOverride pinning the canonical host when set, #139) and passed in.
    private static string[] ExpectedAcsUrls(string requestBaseUrl, string provider) =>
        SamlAcsUrlBuilder.ExpectedAcsUrls(requestBaseUrl, provider);
}

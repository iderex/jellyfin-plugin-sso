using System;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Flows;

/// <summary>
/// The one shared completion path both protocols funnel into once their validation has produced a
/// <see cref="VerifiedIdentity"/> (#473): resolve-or-create the account, build the session parameters, and
/// mint the session under the in-flight revocation gate, then audit and map to a <see cref="LoginOutcome"/>.
/// Extracting it here (#160, #318 step 11) leaves the controller's two callbacks a single delegation each,
/// and keeps the whole tail — every decision from a resolved identity to a minted session — in one flow-tier
/// collaborator rather than inline on the controller.
/// </summary>
/// <remarks>
/// The entrypoint takes a <see cref="VerifiedIdentity"/> and nothing rawer, so the compile-time "no mint
/// without validation" property the keystone establishes is preserved across the extraction: there is no
/// overload that accepts an unvalidated response. This flow tier holds no <c>HttpContext</c> dependency —
/// the controller passes the normalized client remote endpoint in as a resolver (#177), exactly as it does
/// for <see cref="SessionMinter"/>.
/// </remarks>
internal sealed class LoginCompletionService
{
    private readonly CanonicalLinkService _canonicalLinks;
    private readonly SessionMinter _sessionMinter;
    private readonly SsoOnlyLoginService _ssoOnly;
    private readonly ILogger _logger;

    internal LoginCompletionService(CanonicalLinkService canonicalLinks, SessionMinter sessionMinter, SsoOnlyLoginService ssoOnly, ILogger logger)
    {
        _canonicalLinks = canonicalLinks ?? throw new ArgumentNullException(nameof(canonicalLinks));
        _sessionMinter = sessionMinter ?? throw new ArgumentNullException(nameof(sessionMinter));
        _ssoOnly = ssoOnly ?? throw new ArgumentNullException(nameof(ssoOnly));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Completes a login from its fully-verified identity: resolve-or-create the account, build the session
    /// parameters, and mint the session under the in-flight revocation gate. Taking a
    /// <see cref="VerifiedIdentity"/> — the only type either protocol can produce, and only after full
    /// validation — is what makes minting from a raw, unvalidated response a compile error: there is no
    /// overload that accepts anything else. The only per-protocol input left is the adoption gate (OpenID may
    /// require a verified email #218; SAML passes <see cref="AdoptionGate.None"/>), so it is a parameter;
    /// every other divergence collapsed into the identity's own fields (its link namespace, audit label,
    /// subject, username, privileges).
    /// </summary>
    /// <param name="identity">The fully-verified login identity and privileges (#473).</param>
    /// <param name="response">The client's auth request context (app/device), carried into the session mint.</param>
    /// <param name="config">The provider configuration governing authorization/folder/default-provider grants.</param>
    /// <param name="adoptionGate">The extra proof a same-named adoption must clear (#218).</param>
    /// <param name="remoteEndPointResolver">Resolves the normalized client IP for the activity log (#177); the controller reads it from <c>HttpContext</c> and passes it in so this tier stays HttpContext-free. Evaluated at the original point inside the minter — after avatar/persistence, and not at all on the fail-closed path.</param>
    /// <returns>The HTTP result for the completed (or refused) login.</returns>
    internal async Task<ActionResult> CompleteAsync(
        VerifiedIdentity identity,
        AuthResponse response,
        ProviderConfigBase config,
        AdoptionGate adoptionGate,
        Func<string> remoteEndPointResolver)
    {
        Guid userId;
        try
        {
            userId = await _canonicalLinks.ResolveOrCreateAsync(
                identity.LinkMode,
                identity.Provider,
                identity.Subject,
                identity.Username,
                config.AllowExistingAccountLink,
                adoptionGate,
                identity.Issuer).ConfigureAwait(false);
        }
        catch (AccountLinkForbiddenException)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AccountLinkForbidden));
        }

        // SSO-only re-assertion on the login path (#165, criterion 5 / T-S1, Findings A/B/H1). While
        // DisablePasswordLogin is on, an SSO login must not leave the account's provider routing in a state
        // that undermines the mode: a non-exempt account is forced onto the SSO (non-password) provider so no
        // residual password door survives, and the break-glass admin is PINNED to the built-in password
        // provider so an SSO login can never strip its own password door (which would risk a total lockout
        // once the IdP fails). The single decision is derived from the RESOLVED account (by userId), not the
        // mutable IdP-supplied identity.Username, so it matches the enable sweep's break-glass basis exactly;
        // it also tracks a first-time non-exempt repoint (so the off-switch/boot reconcile can restore it) and
        // returns whether this is the break-glass admin so the mint can keep it admin/enabled. When the mode
        // is off (the default), the provider's own DefaultProvider is used unchanged and nothing is tracked.
        var configuredDefaultProvider = config.DefaultProvider?.Trim();
        var enforcement = _ssoOnly.ResolveLoginEnforcement(userId, configuredDefaultProvider);

        var sessionParameters = new SessionParameters
        {
            UserId = userId,
            IsAdmin = identity.Admin,
            IsBreakGlassAdmin = enforcement.IsBreakGlassAdmin,
            EnableAuthorization = config.EnableAuthorization,
            EnableAllFolders = config.EnableAllFolders,
            EnabledFolders = identity.Folders.ToArray(),
            EnableLiveTv = identity.EnableLiveTv,
            EnableLiveTvManagement = identity.EnableLiveTvManagement,
            PermissionGrants = identity.PermissionGrants,
            AuthResponse = response,
            DefaultProvider = enforcement.DefaultProvider,
            AvatarUrl = identity.AvatarUrl,
        };

        // Mint under the in-flight revocation gate (#232): the minter re-checks the link is still live both
        // before any user side effect and again as the last act before AuthenticateDirect. The remote-endpoint
        // resolver is passed rather than the value so the minter evaluates it at the exact original point.
        var authenticationResult = await _sessionMinter.MintAsync(
            sessionParameters,
            remoteEndPointResolver,
            () => _canonicalLinks.IsIdentityStillLinked(identity.LinkMode, identity.Provider, identity.Subject, userId)).ConfigureAwait(false);
        SsoAudit.LoginSucceeded(_logger, identity.AuditProtocol, identity.Provider, identity.Username, identity.Admin);
        return LoginStatusMapper.ToActionResult(new LoginOutcome.Success(authenticationResult));
    }
}

// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Session;

/// <summary>
/// Mints a Jellyfin session for a resolved SSO login: applies the granted permissions and the optional
/// avatar/default-provider updates to the user, then authenticates the client through
/// <see cref="ISessionManager"/>. The controller keeps the HTTP boundary and passes the already-normalized
/// client remote endpoint in, so this flow tier holds no <c>HttpContext</c> dependency.
/// </summary>
internal sealed class SessionMinter
{
    private readonly IUserManager _userManager;
    private readonly AvatarService _avatarService;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SessionMinter"/> class, wiring the user, avatar and
    /// session-manager collaborators the mint applies grants and authenticates through.
    /// </summary>
    /// <param name="userManager">The Jellyfin user manager the granted privileges are applied to.</param>
    /// <param name="avatarService">The avatar fetch/store service run during the mint.</param>
    /// <param name="sessionManager">The session manager that authenticates the client.</param>
    /// <param name="logger">The logger.</param>
    internal SessionMinter(IUserManager userManager, AvatarService avatarService, ISessionManager sessionManager, ILogger logger)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _avatarService = avatarService ?? throw new ArgumentNullException(nameof(avatarService));
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Applies the resolved login's permissions/avatar/default-provider to the user and mints a session.
    /// </summary>
    /// <param name="parameters">The resolved user, granted privileges, and client identity.</param>
    /// <param name="remoteEndPointResolver">Resolves the normalized client IP for the activity log (the controller reads it from <c>HttpContext</c>, #177). Invoked at the original point below — after avatar/persistence, and not at all on the fail-closed path — to preserve evaluation order.</param>
    /// <param name="identityStillLinked">The in-flight revocation gate (#232): re-checks, under the config lock, that the resolved identity is still linked. Evaluated twice — before any user side effect (so a revoked login persists no grants) and again as the last act before the session mint (so a revocation landing mid-method still yields no session); false fails closed. Required (no default) so a mint path cannot silently omit it and fail open.</param>
    /// <returns>The authenticated session result.</returns>
    internal async Task<AuthenticationResult> MintAsync(SessionParameters parameters, Func<string> remoteEndPointResolver, Func<bool> identityStillLinked)
    {
        User? user = _userManager.GetUserById(parameters.UserId);
        if (user is null)
        {
            // Fail closed: the account resolved for this SSO login no longer exists (e.g. it was
            // deleted between resolution and this call), so no session may be minted for it.
            throw new AuthenticationException("SSO authentication aborted: the target user does not exist.");
        }

        // First revocation gate (#232), BEFORE any user side effect: a login already revoked between
        // resolution (under the config lock) and here must not persist the SSO-derived permission,
        // avatar, or default-provider changes onto the account an admin is locking down. The final gate
        // below still catches a revocation that commits later in this method. Fail closed exactly like
        // the deleted-user guard above; the same AuthenticationException, no new error contract.
        if (!identityStillLinked())
        {
            throw new AuthenticationException("SSO authentication aborted: the identity is no longer linked (revoked in flight).");
        }

        if (parameters.EnableAuthorization)
        {
            // Break-glass survivability (#165, Finding H1): while SSO-only mode is on, the designated
            // recovery admin's OWN SSO login must never demote it. A provider whose claims do not grant
            // admin would otherwise strip IsAdministrator from the one account guaranteed to keep a
            // password door, so the guaranteed recovery account becomes useless exactly when the identity
            // provider is down. Leave its admin state intact; every non-break-glass account (and the whole
            // userbase when the mode is off) is unaffected. IsDisabled is separately barred from any SSO
            // role mapping (PermissionRolePolicy), so no login can disable this account either.
            if (!parameters.IsBreakGlassAdmin)
            {
                user.SetPermission(PermissionKind.IsAdministrator, parameters.IsAdmin);
            }

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

            // Generic role→permission grants for the full boolean PermissionKind surface (#164): apply each
            // permission the admin explicitly mapped, authoritatively and default-deny — granted when a
            // login role matched, revoked otherwise. Empty unless the feature is on, so this touches nothing
            // for existing deployments. The permissions with dedicated fields above (admin, all-folders,
            // Live TV) are excluded from this set at config validation, so there is exactly one authoritative
            // writer per permission and no grant here can silently override an admin/folder/Live TV decision.
            // Under the same EnableAuthorization master switch as those grants (#215), so turning SSO
            // permission management off leaves the whole permission surface untouched.
            foreach (var grant in parameters.PermissionGrants)
            {
                user.SetPermission(grant.Kind, grant.Granted);
            }

            // Parental-rating-score ceiling (#736): applied only when the login resolved one (a role matched a
            // configured mapping); a null leaves the account's existing MaxParentalRatingScore untouched, so an
            // unmapped or malformed claim never raises the ceiling. Under the same EnableAuthorization master
            // switch as the grants above, so turning RBAC off leaves the ceiling untouched too.
            if (parameters.MaxParentalRatingScore.HasValue)
            {
                user.MaxParentalRatingScore = parameters.MaxParentalRatingScore;
            }
        }

        await _avatarService.TrySetAsync(user, parameters.AvatarUrl).ConfigureAwait(false);

        // Set the default-provider id before the single user write so it persists in one round-trip
        // (#391). The pre-extraction Authenticate wrote the user a second time just for this field.
        if (!string.IsNullOrEmpty(parameters.DefaultProvider))
        {
            user.AuthenticationProviderId = parameters.DefaultProvider;
            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogInformation("Set default login provider to {DefaultProvider}", parameters.DefaultProvider);
            }
        }

        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        var authRequest = new AuthenticationRequest();
        authRequest.UserId = user.Id;
        authRequest.Username = user.Username;
        authRequest.App = parameters.AuthResponse.AppName;
        authRequest.AppVersion = parameters.AuthResponse.AppVersion;
        authRequest.DeviceId = parameters.AuthResponse.DeviceID;
        authRequest.DeviceName = parameters.AuthResponse.DeviceName;

        // Record the client IP so the SSO login shows a source address in Jellyfin's activity log,
        // exactly as password logins do (#177): the controller resolves it with Jellyfin's own
        // GetNormalizedRemoteIP, the very helper its built-in login path uses. It reads the
        // already-resolved connection address (so the plugin adds no proxy-trust logic of its own — the
        // server's "Known proxies" setting governs it) and normalizes it the same way (IPv4-mapped IPv6
        // collapsed to IPv4), so the SSO entry's source address matches a password entry's for the same
        // client byte-for-byte.
        authRequest.RemoteEndPoint = remoteEndPointResolver();
        _logger.LogInformation("Auth request created...");

        // Final revocation gate (#232), the LAST act before the mint: a revocation that committed during
        // the permission/avatar/user-write work above must still stop the session. This is the gate that
        // closes the login race; the earlier one only spares the side effects. Same fail-closed abort.
        if (!identityStillLinked())
        {
            throw new AuthenticationException("SSO authentication aborted: the identity is no longer linked (revoked in flight).");
        }

        return await _sessionManager.AuthenticateDirect(authRequest).ConfigureAwait(false);
    }
}

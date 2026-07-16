using System;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api;

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
    /// <returns>The authenticated session result.</returns>
    internal async Task<AuthenticationResult> MintAsync(SessionParameters parameters, Func<string> remoteEndPointResolver)
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

        await _avatarService.TrySetAsync(user, parameters.AvatarUrl).ConfigureAwait(false);

        // Set the default-provider id before the single user write so it persists in one round-trip
        // (#391). The pre-extraction Authenticate wrote the user a second time just for this field.
        if (!string.IsNullOrEmpty(parameters.DefaultProvider))
        {
            user.AuthenticationProviderId = parameters.DefaultProvider;
            _logger.LogInformation("Set default login provider to {DefaultProvider}", parameters.DefaultProvider);
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

        return await _sessionManager.AuthenticateDirect(authRequest).ConfigureAwait(false);
    }
}

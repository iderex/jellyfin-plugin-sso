using Jellyfin.Database.Implementations.Enums;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// A single generic permission grant a login resolves: the Jellyfin permission and whether it is granted
/// (true) or explicitly revoked (false). Produced by <see cref="PermissionRolePolicy"/> and applied
/// authoritatively at the session mint (#164).
/// </summary>
/// <param name="Kind">The Jellyfin permission this grant sets.</param>
/// <param name="Granted">Whether the permission is granted (true) or explicitly revoked (false).</param>
internal readonly record struct PermissionGrant(PermissionKind Kind, bool Granted);

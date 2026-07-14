using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Evidence that an authorize state was atomically claimed exactly once for its provider —
/// <see cref="OidcStateStore.TryRedeem"/> is the only production constructor, so code taking this
/// type cannot run before the one-time redeem (#318). An immutable snapshot of the redeemed identity
/// and privileges, taken at claim time.
/// </summary>
internal sealed class RedeemedState
{
    internal RedeemedState(TimedAuthorizeState claimed)
    {
        Subject = claimed.Subject;
        Username = claimed.Username;
        Admin = claimed.Admin;
        Folders = claimed.Folders;
        EnableLiveTv = claimed.EnableLiveTv;
        EnableLiveTvManagement = claimed.EnableLiveTvManagement;
        AvatarUrl = claimed.AvatarURL;
    }

    /// <summary>Gets the stable subject identifier keying the account link (#155).</summary>
    internal string Subject { get; }

    /// <summary>Gets the username resolved by the verified login.</summary>
    internal string Username { get; }

    /// <summary>Gets a value indicating whether the login grants administrator rights.</summary>
    internal bool Admin { get; }

    /// <summary>Gets the folders the login grants access to.</summary>
    internal List<string> Folders { get; }

    /// <summary>Gets a value indicating whether the login may view live TV.</summary>
    internal bool EnableLiveTv { get; }

    /// <summary>Gets a value indicating whether the login may manage live TV.</summary>
    internal bool EnableLiveTvManagement { get; }

    /// <summary>Gets the avatar URL resolved by the verified login.</summary>
    internal string AvatarUrl { get; }
}

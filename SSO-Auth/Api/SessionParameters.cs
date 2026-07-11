using System;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Everything the session-minting step needs to authenticate a resolved SSO login: the target user,
/// the privileges granted by the provider configuration and the login's roles, the client identity
/// to bind the session to, and the optional post-login user updates. Groups what was previously a
/// ten-parameter method signature; constructed with an object initializer at the call sites.
/// </summary>
internal sealed class SessionParameters
{
    /// <summary>
    /// Gets the id of the (existing) Jellyfin user to mint the session for.
    /// </summary>
    public required Guid UserId { get; init; }

    /// <summary>
    /// Gets a value indicating whether the user is granted administrator rights.
    /// </summary>
    public required bool IsAdmin { get; init; }

    /// <summary>
    /// Gets a value indicating whether role-based authorization is applied (when false, the
    /// admin/folder permissions are left untouched).
    /// </summary>
    public required bool EnableAuthorization { get; init; }

    /// <summary>
    /// Gets a value indicating whether the user may access all folders.
    /// </summary>
    public required bool EnableAllFolders { get; init; }

    /// <summary>
    /// Gets the folders enabled for the user (applied only when <see cref="EnableAllFolders"/> is false).
    /// </summary>
    public required string[] EnabledFolders { get; init; }

    /// <summary>
    /// Gets a value indicating whether the user may access Live TV.
    /// </summary>
    public required bool EnableLiveTv { get; init; }

    /// <summary>
    /// Gets a value indicating whether the user may manage Live TV.
    /// </summary>
    public required bool EnableLiveTvManagement { get; init; }

    /// <summary>
    /// Gets the client identity (app, version, device) the session is bound to.
    /// </summary>
    public required AuthResponse AuthResponse { get; init; }

    /// <summary>
    /// Gets the authentication provider id to persist as the user's default login provider, or
    /// null/empty to leave it unchanged.
    /// </summary>
    public required string? DefaultProvider { get; init; }

    /// <summary>
    /// Gets the avatar URL to fetch and set as the user's profile image, or null to skip.
    /// </summary>
    public required string? AvatarUrl { get; init; }
}

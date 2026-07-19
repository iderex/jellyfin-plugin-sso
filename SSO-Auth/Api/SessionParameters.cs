using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;

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
    /// Gets a value indicating whether the resolved account is the designated break-glass admin while
    /// SSO-only mode is on (#165, Finding H1). When true the mint must leave the account's administrator
    /// state intact — its own SSO login must never be able to demote the one guaranteed recovery account,
    /// which would lock the whole org out once the identity provider is unreachable. False for every other
    /// account and whenever the mode is off, so the ordinary role-derived admin grant applies unchanged.
    /// </summary>
    public required bool IsBreakGlassAdmin { get; init; }

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
    /// Gets the generic role→permission grants to apply at the mint (#164): one authoritative grant per
    /// permission the administrator explicitly mapped, applied only when <see cref="EnableAuthorization"/>
    /// is on. Required (no default) so a mint path cannot silently omit it; an empty list applies nothing.
    /// </summary>
    public required IReadOnlyList<PermissionGrant> PermissionGrants { get; init; }

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

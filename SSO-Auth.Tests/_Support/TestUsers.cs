// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Database.Implementations.Entities;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Factory for the Jellyfin <see cref="User"/> that SSO tests provision. Every SSO test user shares the same
/// authentication-provider pair (<c>"SSO-Auth"</c> authentication provider id, <c>"Default"</c> password-reset
/// provider id); keeping that pair here means renaming the provider id is one edit, not a sweep across every
/// test file. Composition, not a base class — a test that needs extra state sets it on the returned user.
/// </summary>
internal static class TestUsers
{
    /// <summary>Creates a user against this plugin's authentication provider, id left at the entity default.</summary>
    internal static User Named(string name) => new(name, "SSO-Auth", "Default");

    /// <summary>Creates a user as <see cref="Named(string)"/> with an explicit <see cref="User.Id"/>.</summary>
    internal static User Named(string name, Guid id)
    {
        var user = Named(name);
        user.Id = id;
        return user;
    }
}

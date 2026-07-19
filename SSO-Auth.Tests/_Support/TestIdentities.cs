using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Test fixtures that mint a <see cref="VerifiedIdentity"/> from a protocol authorize-state, mirroring the
/// production destructuring in <c>AuthorizeSession.Ready</c> (OpenID) and <c>SamlAssertionValidator</c>
/// (SAML). Kept in one place so the #790 dependency inversion — protocol state → <see cref="ValidatedLogin"/>
/// → the keystone factory — is applied identically wherever a test needs a ready-made verified identity,
/// without each test repeating the field mapping.
/// </summary>
internal static class TestIdentities
{
    internal static VerifiedIdentity Oidc(string provider, OidcAuthorizeStateBuilder.OidcAuthorizeState derived) =>
        VerifiedIdentity.FromValidatedOidc(new ValidatedLogin
        {
            Provider = provider,
            Subject = derived.Subject!,
            Issuer = derived.Issuer,
            Username = derived.Username!,
            EmailVerified = derived.EmailVerified,
            Admin = derived.Admin,
            Folders = derived.Folders,
            EnableLiveTv = derived.EnableLiveTv,
            EnableLiveTvManagement = derived.EnableLiveTvManagement,
            AvatarUrl = derived.AvatarUrl,
            PermissionGrants = derived.PermissionGrants ?? Array.Empty<PermissionGrant>(),
        });

    internal static VerifiedIdentity Saml(string provider, string nameId, SamlAuthorizeStateBuilder.SamlAuthorizeState privileges) =>
        VerifiedIdentity.FromValidatedSaml(new ValidatedLogin
        {
            Provider = provider,
            Subject = nameId,
            Issuer = null,
            Username = nameId,
            EmailVerified = null,
            Admin = privileges.Admin,
            Folders = privileges.Folders,
            EnableLiveTv = privileges.EnableLiveTv,
            EnableLiveTvManagement = privileges.EnableLiveTvManagement,
            AvatarUrl = null,
            PermissionGrants = privileges.PermissionGrants ?? Array.Empty<PermissionGrant>(),
        });
}

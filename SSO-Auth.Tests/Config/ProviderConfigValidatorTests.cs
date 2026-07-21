// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Security.Cryptography.X509Certificates;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Dedicated negative-path suite for the per-provider guards of <see cref="ProviderConfigValidator"/>
/// (#318) — the reject arms every admin write path shares. The whole-config <c>Validate</c> orchestration
/// is exercised in <see cref="ConfigPreservationTests"/>; this suite instead calls each per-provider method
/// directly so it can pin, for every fail-closed branch, the ACTUAL exception type, its <c>ParamName</c>,
/// and the distinguishing message text — and the ACCEPT/blank arm that must not throw. Each reject case
/// would flip to a failing <c>Assert.Throws</c> if the guard were loosened to accept.
/// </summary>
public class ProviderConfigValidatorTests
{
    // --- ValidateAcrRequirement (#757): reject RequireAcr with no acr_values (a silent-lockout footgun) ---

    [Fact]
    public void ValidateAcrRequirement_RequireAcrWithoutAcrValues_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ProviderConfigValidator.ValidateAcrRequirement("kc", new OidConfig { RequireAcr = true, AcrValues = "   " }));

        Assert.Equal("config", ex.ParamName);
        Assert.Contains("kc", ex.Message, StringComparison.Ordinal);
        Assert.Contains("RequireAcr", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true, "mfa")] // require-with-values is fine
    [InlineData(false, "")] // not requiring is fine with or without values
    [InlineData(false, "mfa")]
    public void ValidateAcrRequirement_ValidCombinations_DoNotThrow(bool requireAcr, string acrValues)
        => Assert.Null(Record.Exception(() =>
            ProviderConfigValidator.ValidateAcrRequirement("kc", new OidConfig { RequireAcr = requireAcr, AcrValues = acrValues })));

    // --- ValidateParentalRatingMappings (#736): reject a negative score or an entry with no roles ---

    [Fact]
    public void ValidateParentalRatingMappings_NegativeScore_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateParentalRatingMappings(
            "OpenID", "kc", new[] { new ParentalRatingRoleMap { Score = -1, Roles = new[] { "kids" } } }));

        Assert.Equal("mappings", ex.ParamName);
        Assert.Contains("kc", ex.Message, StringComparison.Ordinal);
        Assert.Contains("score", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateParentalRatingMappings_NullRoles_Throws()
        => AssertNoRolesRejected(null);

    [Fact]
    public void ValidateParentalRatingMappings_EmptyRoles_Throws()
        => AssertNoRolesRejected(Array.Empty<string>());

    private static void AssertNoRolesRejected(string[]? roles)
    {
        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateParentalRatingMappings(
            "SAML", "idp", new[] { new ParentalRatingRoleMap { Score = 5, Roles = roles! } }));

        Assert.Equal("mappings", ex.ParamName);
        Assert.Contains("no roles", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateParentalRatingMappings_ValidOrNullOrEmpty_DoesNotThrow()
    {
        Assert.Null(Record.Exception(() =>
        {
            ProviderConfigValidator.ValidateParentalRatingMappings("OpenID", "kc", new[] { new ParentalRatingRoleMap { Score = 0, Roles = new[] { "kids" } } });
            ProviderConfigValidator.ValidateParentalRatingMappings("OpenID", "kc", new ParentalRatingRoleMap[] { null! }); // a null entry is tolerated
            ProviderConfigValidator.ValidateParentalRatingMappings("OpenID", "kc", null); // no mappings at all
        }));
    }

    // --- ValidateProviderName (#336, #360): reject a NEW round-trip-breaking name; exempt existing names ---

    [Theory]
    [InlineData("OpenID", "my/realm")] // '/' builds a callback path no route can match
    [InlineData("OpenID", "prov%1")] // '%' breaks route decoding
    [InlineData("SAML", "corp\\realm")] // backslash normalizes to '/' in special-scheme URLs (WHATWG)
    [InlineData("SAML", "idp:1")] // gen-delim
    public void ValidateProviderName_NewNameWithReservedCharacter_ThrowsNamingProtocolProviderAndRule(string protocol, string provider)
    {
        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateProviderName(protocol, provider, isNew: true));

        Assert.Equal("provider", ex.ParamName);
        Assert.Contains(protocol, ex.Message, StringComparison.Ordinal);
        Assert.Contains(provider, ex.Message, StringComparison.Ordinal);
        // The rule text that names WHY the save was rejected — the callback-URL reserved/control set.
        Assert.Contains("control characters, URI-reserved characters, or a backslash", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateProviderName_NewNameWithControlCharacter_Throws_AndStripsTheControlFromTheEchoedMessage()
    {
        // A newline is a control character (#360): the name is rejected, and the raw control byte must NOT
        // survive into the exception text (which any log capturing it would inherit). The full control strip
        // means the echoed name is the reserved characters with the newline removed.
        const string provider = "corp\nrealm";

        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateProviderName("OpenID", provider, isNew: true));

        Assert.Equal("provider", ex.ParamName);
        Assert.DoesNotContain('\n', ex.Message);
        Assert.DoesNotContain('\r', ex.Message);
        Assert.Contains("corprealm", ex.Message, StringComparison.Ordinal); // control stripped, the rest echoed intact
    }

    [Fact]
    public void ValidateProviderName_ExistingReservedName_IsExempt_DoesNotThrow()
    {
        // A reserved-character name already registered with the identity provider must keep saving: its
        // callback-URL bytes are what the IdP already has, so blocking it would strand the deployment behind
        // a rename. isNew:false is the "already in the live config" signal.
        var ex = Record.Exception(() => ProviderConfigValidator.ValidateProviderName("OpenID", "kc=prod", isNew: false));

        Assert.Null(ex);
    }

    [Theory]
    [InlineData("keycloak")] // clean unreserved name
    [InlineData("my provider")] // spaces survive the round-trip (pinned in SsoUrlBuilderTests)
    [InlineData("käse")] // non-ASCII survives too
    [InlineData("")] // blank is out of this rule's scope: no route produces an empty provider segment
    [InlineData(null)]
    public void ValidateProviderName_NewCleanOrBlankName_DoesNotThrow(string? provider)
    {
        var ex = Record.Exception(() => ProviderConfigValidator.ValidateProviderName("OpenID", provider!, isNew: true));

        Assert.Null(ex);
    }

    // --- ValidateBaseUrlOverride (#139): reject a set-but-malformed override; blank/valid pass ---

    [Theory]
    [InlineData("OpenID", "not-a-url")] // not absolute
    [InlineData("SAML", "ftp://example.com")] // absolute but not http(s)
    [InlineData("OpenID", "https://user:pass@example.com")] // userinfo can mask the real host
    [InlineData("SAML", "https://example.com?x=1")] // a query would corrupt every derived redirect_uri
    public void ValidateBaseUrlOverride_MalformedOverride_ThrowsNamingProtocolAndProvider(string protocol, string baseUrlOverride)
    {
        var ex = Assert.Throws<ArgumentException>(
            () => ProviderConfigValidator.ValidateBaseUrlOverride(protocol, "idp", baseUrlOverride));

        Assert.Equal("baseUrlOverride", ex.ParamName);
        Assert.Contains(protocol, ex.Message, StringComparison.Ordinal);
        Assert.Contains("idp", ex.Message, StringComparison.Ordinal);
        Assert.Contains("invalid Base URL override", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")] // blank means the override feature is simply off
    [InlineData("https://jellyfin.example.com")]
    [InlineData("https://sso.example.com/jellyfin")] // a path base is allowed
    [InlineData("http://localhost:8096")]
    public void ValidateBaseUrlOverride_BlankOrValidAbsoluteHttpUrl_DoesNotThrow(string? baseUrlOverride)
    {
        var ex = Record.Exception(() => ProviderConfigValidator.ValidateBaseUrlOverride("OpenID", "idp", baseUrlOverride!));

        Assert.Null(ex);
    }

    // --- ValidateSamlCertificate (#206): reject a set-but-unloadable X.509; blank/valid pass ---

    [Theory]
    [InlineData("@@ not base64 @@")] // FormatException from Convert.FromBase64String
    [InlineData("QUJD")] // valid base64 ("ABC") but not a DER certificate -> CryptographicException
    public void ValidateSamlCertificate_SetButUnloadable_ThrowsNamingProviderAndKind(string certificate)
    {
        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateSamlCertificate("idp", certificate));

        Assert.Equal("certificate", ex.ParamName);
        Assert.Contains("idp", ex.Message, StringComparison.Ordinal);
        Assert.Contains("invalid signing certificate", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateSamlCertificate_ValidCertificate_DoesNotThrow()
    {
        var ex = Record.Exception(() => ProviderConfigValidator.ValidateSamlCertificate("idp", SamlTestFactory.Create().CertificateBase64));

        Assert.Null(ex);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateSamlCertificate_Blank_DoesNotThrow(string? certificate)
    {
        var ex = Record.Exception(() => ProviderConfigValidator.ValidateSamlCertificate("idp", certificate!));

        Assert.Null(ex);
    }

    // --- ValidateSamlSecondaryCertificate (#491): the inbound overlap-window cert, same rule, own message ---

    [Fact]
    public void ValidateSamlSecondaryCertificate_SetButUnloadable_ThrowsWithTheSecondaryMessage()
    {
        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateSamlSecondaryCertificate("idp", "QUJD"));

        Assert.Equal("certificate", ex.ParamName);
        Assert.Contains("idp", ex.Message, StringComparison.Ordinal);
        // The message must name the SECONDARY certificate so the admin can tell which field is at fault.
        Assert.Contains("invalid secondary signing certificate", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateSamlSecondaryCertificate_Blank_DoesNotThrow(string? certificate)
    {
        // Blank means no IdP-side signing-key overlap window is configured.
        var ex = Record.Exception(() => ProviderConfigValidator.ValidateSamlSecondaryCertificate("idp", certificate!));

        Assert.Null(ex);
    }

    [Fact]
    public void ValidateSamlSecondaryCertificate_ValidCertificate_DoesNotThrow()
    {
        var ex = Record.Exception(
            () => ProviderConfigValidator.ValidateSamlSecondaryCertificate("idp", SamlTestFactory.Create().CertificateBase64));

        Assert.Null(ex);
    }

    // --- ValidateSamlSigningKey (#167, #493): reject a set-but-unloadable PKCS#12; blank/valid PFX pass ---

    [Theory]
    [InlineData("@@ not base64 @@")] // FormatException
    [InlineData("QUJD")] // valid base64 but not a PKCS#12 -> CryptographicException
    public void ValidateSamlSigningKey_SetButUnloadable_ThrowsNamingProviderAndKind(string signingKeyPfx)
    {
        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateSamlSigningKey("idp", signingKeyPfx));

        Assert.Equal("signingKeyPfx", ex.ParamName);
        Assert.Contains("idp", ex.Message, StringComparison.Ordinal);
        Assert.Contains("invalid request signing key", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateSamlSigningKey_EncryptedPfx_Throws()
    {
        // A password-protected PKCS#12 cannot load with the null password the loader uses, so it is
        // set-but-unloadable and must be rejected — an operator who turned signing on can never get a silent
        // unsigned downgrade from a key the plugin cannot open.
        using var certificate = SamlSigningKeyFactory.CreateCertificate();
        var encryptedPfx = Convert.ToBase64String(certificate.Export(X509ContentType.Pfx, "s3cret"));

        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateSamlSigningKey("idp", encryptedPfx));

        Assert.Equal("signingKeyPfx", ex.ParamName);
        Assert.Contains("invalid request signing key", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateSamlSigningKey_PublicOnlyPfx_Throws()
    {
        // A PKCS#12 with no private key cannot sign, so it is as unusable as garbage and must be rejected.
        using var certificate = SamlSigningKeyFactory.CreateCertificate();
        var publicOnlyPfx = Convert.ToBase64String(
            X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert)).Export(X509ContentType.Pkcs12));

        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateSamlSigningKey("idp", publicOnlyPfx));

        Assert.Equal("signingKeyPfx", ex.ParamName);
        Assert.Contains("invalid request signing key", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateSamlSigningKey_Blank_DoesNotThrow(string? signingKeyPfx)
    {
        // Blank is "signing not configured" — valid; signing simply stays off.
        var ex = Record.Exception(() => ProviderConfigValidator.ValidateSamlSigningKey("idp", signingKeyPfx!));

        Assert.Null(ex);
    }

    [Fact]
    public void ValidateSamlSigningKey_ValidRsaPfx_DoesNotThrow()
    {
        var ex = Record.Exception(() => ProviderConfigValidator.ValidateSamlSigningKey("idp", SamlSigningKeyFactory.CreatePfxBase64()));

        Assert.Null(ex);
    }

    [Fact]
    public void ValidateSamlSigningKey_ValidEcdsaPfx_DoesNotThrow()
    {
        // An ECDSA SP signing key is a first-class option (#493) and must pass the admin-write guard.
        var ex = Record.Exception(() => ProviderConfigValidator.ValidateSamlSigningKey("idp", SamlSigningKeyFactory.CreateEcdsaPfxBase64()));

        Assert.Null(ex);
    }

    // --- ValidatePermissionRoleMappings (#164): reject a malformed generic permission-role mapping ---

    private static System.Collections.Generic.List<PermissionRoleMap> Mappings(string permission) =>
        new() { new PermissionRoleMap { Permission = permission, Roles = new[] { "role" } } };

    [Theory]
    [InlineData("OpenID", "kc")]
    [InlineData("SAML", "adfs")]
    public void ValidatePermissionRoleMappings_UnknownPermission_ThrowsNamingProtocolProviderAndPermission(string protocol, string provider)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ProviderConfigValidator.ValidatePermissionRoleMappings(protocol, provider, Mappings("NotARealPermission")));

        Assert.Equal("mappings", ex.ParamName);
        Assert.Contains(protocol, ex.Message, StringComparison.Ordinal);
        Assert.Contains(provider, ex.Message, StringComparison.Ordinal);
        Assert.Contains("NotARealPermission", ex.Message, StringComparison.Ordinal);
        Assert.Contains("not a known Jellyfin permission", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("IsAdministrator")]
    [InlineData("EnableAllFolders")]
    [InlineData("EnableLiveTvAccess")]
    [InlineData("EnableLiveTvManagement")]
    [InlineData("IsDisabled")] // #165 Finding H1: rejected fail-closed at the save boundary too
    public void ValidatePermissionRoleMappings_DedicatedPermission_IsRejected_NoDoubleMapping(string permission)
    {
        // The anti-escalation / single-source guarantee at the admin write boundary: a dedicated permission
        // (notably IsAdministrator) cannot be persisted into the generic map, so it can never be granted
        // through it. IsDisabled is barred here for the stronger whole-org-lockout reason (#165 Finding H1):
        // it must never be reachable as a role-mapped grant.
        var ex = Assert.Throws<ArgumentException>(() =>
            ProviderConfigValidator.ValidatePermissionRoleMappings("OpenID", "kc", Mappings(permission)));

        Assert.Equal("mappings", ex.ParamName);
        Assert.Contains("may not be mapped here", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void ValidatePermissionRoleMappings_EmptyPermissionName_IsRejected(string? permission)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ProviderConfigValidator.ValidatePermissionRoleMappings("OpenID", "kc", Mappings(permission!)));

        Assert.Equal("mappings", ex.ParamName);
        Assert.Contains("empty permission name", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidatePermissionRoleMappings_ControlCharacterInPermission_IsStrippedFromTheEchoedMessage()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ProviderConfigValidator.ValidatePermissionRoleMappings("OpenID", "kc", Mappings("Enable\nDownloading")));

        Assert.DoesNotContain('\n', ex.Message);
        Assert.DoesNotContain('\r', ex.Message);
    }

    [Fact]
    public void ValidatePermissionRoleMappings_ValidPermission_DoesNotThrow()
    {
        var ex = Record.Exception(() =>
            ProviderConfigValidator.ValidatePermissionRoleMappings("OpenID", "kc", Mappings("EnableContentDownloading")));

        Assert.Null(ex);
    }

    [Fact]
    public void ValidatePermissionRoleMappings_NullMappingsOrNullEntry_DoesNotThrow()
    {
        // A null list means "no mappings"; a null entry maps nothing and is tolerated (it grants nothing at
        // runtime) — the same fail-closed-but-not-fatal posture as the runtime mapper.
        Assert.Null(Record.Exception(() => ProviderConfigValidator.ValidatePermissionRoleMappings("OpenID", "kc", null)));

        var withNullEntry = new System.Collections.Generic.List<PermissionRoleMap> { null! };
        Assert.Null(Record.Exception(() => ProviderConfigValidator.ValidatePermissionRoleMappings("OpenID", "kc", withNullEntry)));
    }
}

using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlInsecureToggles"/> — the helper that names the enabled default-on-disable
/// options on a SAML provider (#672, the SAML parity of #140), so a save/import with one set can be
/// audit-logged.
/// </summary>
public class SamlInsecureTogglesTests
{
    [Fact]
    public void Enabled_FullyValidatedProvider_ReturnsEmpty()
    {
        Assert.Empty(SamlInsecureToggles.Enabled(new SamlConfig()));
    }

    [Fact]
    public void Enabled_NullConfig_ReturnsEmpty()
    {
        Assert.Empty(SamlInsecureToggles.Enabled(null));
    }

    [Fact]
    public void Enabled_DoNotValidateAudience_ReportsIt()
    {
        Assert.Equal(
            new[] { "DoNotValidateAudience" },
            SamlInsecureToggles.Enabled(new SamlConfig { DoNotValidateAudience = true }));
    }

    [Fact]
    public void Enabled_AdditiveHardeningFlags_AreNotReported()
    {
        // ValidateRecipient / ValidateInResponseTo are opt-in ADDITIVE protections, not downgrades of a
        // default-on check, so enabling them is not an insecure toggle and must not be audited here (#672).
        var config = new SamlConfig { ValidateRecipient = true, ValidateInResponseTo = true };
        Assert.Empty(SamlInsecureToggles.Enabled(config));
    }
}

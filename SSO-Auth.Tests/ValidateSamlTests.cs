using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for the controller's ValidateSaml helper: how the expected audience is derived
/// (SamlAudience, falling back to SamlClientId, both trimmed) and the DoNotValidateAudience opt-out.
/// </summary>
public class ValidateSamlTests
{
    private const string Audience = "https://jellyfin.example.com/sso";

    private static SamlResponse SignedResponseFor(string audience)
    {
        var fixture = SamlTestFactory.Create(audience: audience);
        return new SamlResponse(fixture.CertificateBase64, fixture.EncodeResponse());
    }

    [Fact]
    public void DoNotValidateAudience_SkipsAudienceCheck()
    {
        var response = SignedResponseFor("whatever");
        var config = new SamlConfig { DoNotValidateAudience = true, SamlClientId = "unrelated" };
        Assert.True(SSOController.ValidateSaml(response, config));
    }

    [Fact]
    public void SamlClientId_UsedAsAudienceWhenNoSamlAudience()
    {
        var response = SignedResponseFor(Audience);
        Assert.True(SSOController.ValidateSaml(response, new SamlConfig { SamlClientId = Audience }));
        Assert.False(SSOController.ValidateSaml(response, new SamlConfig { SamlClientId = "https://other" }));
    }

    [Fact]
    public void SamlAudience_OverridesSamlClientId()
    {
        var response = SignedResponseFor(Audience);
        var config = new SamlConfig { SamlAudience = Audience, SamlClientId = "https://other" };
        Assert.True(SSOController.ValidateSaml(response, config));
    }

    [Fact]
    public void EmptySamlAudience_FallsBackToSamlClientId()
    {
        var response = SignedResponseFor(Audience);
        var config = new SamlConfig { SamlAudience = "", SamlClientId = Audience };
        Assert.True(SSOController.ValidateSaml(response, config));
    }

    [Fact]
    public void ExpectedAudienceIsTrimmed()
    {
        var response = SignedResponseFor(Audience);
        Assert.True(SSOController.ValidateSaml(response, new SamlConfig { SamlClientId = "  " + Audience + "  " }));
        Assert.True(SSOController.ValidateSaml(response, new SamlConfig { SamlAudience = " " + Audience + " ", SamlClientId = "x" }));
    }

    [Fact]
    public void NoExpectedAudienceConfigured_FailsClosed()
    {
        var response = SignedResponseFor(Audience);
        Assert.False(SSOController.ValidateSaml(response, new SamlConfig()));
    }
}

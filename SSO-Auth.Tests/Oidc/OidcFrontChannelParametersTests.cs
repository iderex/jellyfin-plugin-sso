using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcFrontChannelParameters"/> — the optional step-up authorize parameters (#757).
/// Each of acr_values/prompt/max_age is emitted only when the provider set it; an unconfigured provider
/// yields null so the request is byte-identical to before (upgrade-safe).
/// </summary>
public class OidcFrontChannelParametersTests
{
    [Fact]
    public void FromConfig_NothingSet_ReturnsNull()
        => Assert.Null(OidcFrontChannelParameters.FromConfig(new OidConfig()));

    [Fact]
    public void FromConfig_AllSet_EmitsEachParameter()
    {
        var p = OidcFrontChannelParameters.FromConfig(new OidConfig { AcrValues = "  phr mfa ", Prompt = " login ", MaxAge = 0 });

        Assert.NotNull(p);
        Assert.Equal("phr mfa", p!.GetValues("acr_values").Single()); // trimmed, inner spaces preserved
        Assert.Equal("login", p.GetValues("prompt").Single());
        Assert.Equal("0", p.GetValues("max_age").Single()); // 0 forces re-auth and must be sent
    }

    [Fact]
    public void FromConfig_OnlyAcrValues_EmitsOnlyThatParameter()
    {
        var p = OidcFrontChannelParameters.FromConfig(new OidConfig { AcrValues = "mfa" });

        Assert.NotNull(p);
        Assert.Equal("mfa", p!.GetValues("acr_values").Single());
        Assert.False(p.ContainsKey("prompt"));
        Assert.False(p.ContainsKey("max_age"));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-3600)]
    public void FromConfig_NegativeMaxAge_IsTreatedAsUnset(int maxAge)
        => Assert.Null(OidcFrontChannelParameters.FromConfig(new OidConfig { MaxAge = maxAge }));

    [Fact]
    public void FromConfig_BlankStrings_AreTreatedAsUnset()
        => Assert.Null(OidcFrontChannelParameters.FromConfig(new OidConfig { AcrValues = "   ", Prompt = "" }));
}

using Jellyfin.Plugin.SSO_Auth.Api;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcResponseIssuer"/> — the RFC 9207 authorization-response issuer check (#125,
/// hardened #210). A present response <c>iss</c> must equal the authorization server's discovery issuer
/// OR the id_token issuer (the id_token anchor keeps templated / <c>DoNotValidateIssuerName</c> setups
/// working); absence is tolerated only when the server did not advertise the parameter, and rejected
/// when it did (§2.4); anything that cannot be shown to agree fails closed.
/// </summary>
public class OidcResponseIssuerTests
{
    private const string DiscoveryIssuer = "https://idp.example.com";

    // Builds a parseable (unsigned) id_token carrying the given iss. The check never verifies the
    // signature — it only reads the issuer — so a JWS with a throwaway signature segment is enough.
    private static string IdToken(string? issuer)
    {
        var payload = issuer == null ? "{}" : $"{{\"iss\":\"{issuer}\"}}";
        return Base64UrlEncoder.Encode("{\"alg\":\"none\",\"typ\":\"JWT\"}")
            + "." + Base64UrlEncoder.Encode(payload)
            + ".c2ln";
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IsRejected_AbsentAndNotAdvertised_False(string? responseIssuer)
    {
        // Many IdPs do not emit iss; when the server did not advertise the parameter, requiring it would
        // lock them out, so absence is tolerated.
        Assert.False(OidcResponseIssuer.IsRejected(responseIssuer, DiscoveryIssuer, IdToken(DiscoveryIssuer), required: false));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IsRejected_AbsentButAdvertised_True(string? responseIssuer)
    {
        // RFC 9207 §2.4: once the AS advertises authorization_response_iss_parameter_supported, a missing
        // iss is a downgrade and must be rejected.
        Assert.True(OidcResponseIssuer.IsRejected(responseIssuer, DiscoveryIssuer, IdToken(DiscoveryIssuer), required: true));
    }

    [Fact]
    public void IsRejected_PresentAndMatchesDiscoveryIssuer_False()
    {
        Assert.False(OidcResponseIssuer.IsRejected(DiscoveryIssuer, DiscoveryIssuer, IdToken(DiscoveryIssuer), required: false));
        Assert.False(OidcResponseIssuer.IsRejected(DiscoveryIssuer, DiscoveryIssuer, IdToken(DiscoveryIssuer), required: true));
    }

    [Fact]
    public void IsRejected_PresentAndMatchesIdTokenIssuerButNotDiscovery_False()
    {
        // The DoNotValidateIssuerName / templated / multi-tenant case: the discovery issuer is a template
        // that the concrete response iss (== the id_token iss) does not equal, but the login must NOT be
        // locked out — the id_token issuer is an accepted anchor.
        const string concrete = "https://idp.example.com/tenant-42";
        Assert.False(OidcResponseIssuer.IsRejected(concrete, DiscoveryIssuer, IdToken(concrete), required: false));
        Assert.False(OidcResponseIssuer.IsRejected(concrete, DiscoveryIssuer, IdToken(concrete), required: true));
    }

    [Fact]
    public void IsRejected_PresentButMatchesNeitherAnchor_True()
    {
        Assert.True(OidcResponseIssuer.IsRejected("https://attacker.example", DiscoveryIssuer, IdToken(DiscoveryIssuer), required: false));
    }

    [Fact]
    public void IsRejected_CaseDifferenceOnly_True()
    {
        // Issuer comparison is ordinal (RFC 9207 / OIDC simple string comparison): a case flip is a mismatch.
        Assert.True(OidcResponseIssuer.IsRejected(DiscoveryIssuer.ToUpperInvariant(), DiscoveryIssuer, IdToken(DiscoveryIssuer), required: false));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-jwt")]
    public void IsRejected_PresentResponseIssuerButBothAnchorsUnknown_True(string? identityToken)
    {
        // A response issuer that cannot be shown to match either anchor (unknown discovery issuer and a
        // no/garbage token, or a token with no iss) fails closed rather than being waved through.
        Assert.True(OidcResponseIssuer.IsRejected(DiscoveryIssuer, discoveryIssuer: null, identityToken, required: false));
    }

    [Fact]
    public void IsRejected_TokenWithoutIssuerClaimAndDiscoveryMismatch_True()
    {
        Assert.True(OidcResponseIssuer.IsRejected(DiscoveryIssuer, "https://other.example", IdToken(null), required: false));
    }

    [Theory]
    [InlineData("{\"authorization_response_iss_parameter_supported\":true}", true)]
    [InlineData("{\"authorization_response_iss_parameter_supported\":false}", false)]
    [InlineData("{\"issuer\":\"https://idp.example.com\"}", false)] // absent
    [InlineData("{\"authorization_response_iss_parameter_supported\":\"true\"}", false)] // string, not boolean
    [InlineData("{\"authorization_response_iss_parameter_supported\":1}", false)] // number, not boolean
    [InlineData("not json", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void DiscoveryAdvertisesResponseIssuer_ParsesTheFlag(string? discoveryJson, bool expected)
    {
        // Only an explicit boolean true advertises the parameter; everything else is tolerant (false), so
        // an unreadable/absent flag never turns into a lockout.
        Assert.Equal(expected, OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(discoveryJson));
    }
}

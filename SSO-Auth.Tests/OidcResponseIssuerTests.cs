using Jellyfin.Plugin.SSO_Auth.Api;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcResponseIssuer"/> — the RFC 9207 authorization-response issuer check (#125).
/// A present response <c>iss</c> must equal the id_token issuer; absence is tolerated; anything that
/// cannot be shown to agree is a mismatch (fail closed).
/// </summary>
public class OidcResponseIssuerTests
{
    private const string Issuer = "https://idp.example.com";

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
    public void IsMismatch_AbsentResponseIssuer_False(string? responseIssuer)
    {
        // Many IdPs do not emit iss; requiring it would lock them out, so absence is tolerated.
        Assert.False(OidcResponseIssuer.IsMismatch(responseIssuer, IdToken(Issuer)));
    }

    [Fact]
    public void IsMismatch_ResponseIssuerMatchesToken_False()
    {
        Assert.False(OidcResponseIssuer.IsMismatch(Issuer, IdToken(Issuer)));
    }

    [Fact]
    public void IsMismatch_ResponseIssuerDiffersFromToken_True()
    {
        Assert.True(OidcResponseIssuer.IsMismatch("https://attacker.example", IdToken(Issuer)));
    }

    [Fact]
    public void IsMismatch_CaseDifferenceOnly_True()
    {
        // Issuer comparison is ordinal (RFC 9207 / OIDC simple string comparison): a case flip is a mismatch.
        Assert.True(OidcResponseIssuer.IsMismatch(Issuer.ToUpperInvariant(), IdToken(Issuer)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-jwt")]
    public void IsMismatch_PresentResponseIssuerButUnreadableToken_True(string? identityToken)
    {
        // A response issuer that cannot be shown to match (no/garbage token, or a token with no iss)
        // fails closed rather than being waved through.
        Assert.True(OidcResponseIssuer.IsMismatch(Issuer, identityToken));
    }

    [Fact]
    public void IsMismatch_TokenWithoutIssuerClaim_True()
    {
        Assert.True(OidcResponseIssuer.IsMismatch(Issuer, IdToken(null)));
    }
}

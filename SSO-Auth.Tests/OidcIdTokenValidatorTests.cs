using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Exercises <see cref="OidcIdTokenValidator"/> against a static JWKS: the happy path and every
/// rejection path of OIDC Core 3.1.3.7 (signature, issuer, audience, azp, lifetime), plus the
/// algorithm allowlist (HS256 and unsigned tokens rejected regardless of key material) and the
/// "invalid_signature" key-refresh contract with OidcClient's response processor.
/// </summary>
public sealed class OidcIdTokenValidatorTests : IDisposable
{
    private const string Issuer = "https://idp.example.test";
    private const string ClientId = "jellyfin-client";
    private const string KeyId = "test-signing-key";

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly OidcIdTokenValidator _validator = new();

    public void Dispose() => _rsa.Dispose();

    [Fact]
    public async Task ValidRs256Token_Succeeds_WithRawClaimsAndAlgorithm()
    {
        var options = Options();
        var token = CreateToken(claims: new Dictionary<string, object>
        {
            ["sub"] = "user-1",
            ["preferred_username"] = "alice",
            ["groups"] = new[] { "media", "admin" },
        });

        var result = await _validator.ValidateAsync(token, options, TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
        Assert.Equal("RS256", result.SignatureAlgorithm);
        // Raw JWT claim names must survive (the downstream claim scan compares ordinally).
        Assert.Equal("alice", result.User.Claims.Single(c => c.Type == "preferred_username").Value);
        Assert.Equal("user-1", result.User.Claims.Single(c => c.Type == "sub").Value);
        // Array claims expand to one claim per element.
        Assert.Equal(2, result.User.Claims.Count(c => c.Type == "groups"));
    }

    [Fact]
    public async Task WrongIssuer_IsRejected()
    {
        var result = await _validator.ValidateAsync(
            CreateToken(issuer: "https://evil.example.test"), Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Contains("Issuer", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WrongIssuer_WithIssuerValidationDisabled_IsAccepted()
    {
        // The provider-level DoNotValidateIssuerName escape hatch relaxes ONLY the issuer match.
        var options = Options();
        options.Policy.Discovery.ValidateIssuerName = false;

        var result = await _validator.ValidateAsync(
            CreateToken(issuer: "https://other.example.test"), options, TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
    }

    [Fact]
    public async Task WrongAudience_IsRejected()
    {
        var result = await _validator.ValidateAsync(
            CreateToken(audience: "some-other-client"), Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Contains("Audience", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExpiredBeyondSkew_IsRejected()
    {
        var result = await _validator.ValidateAsync(
            CreateToken(lifetime: TimeSpan.FromMinutes(-10)), Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Contains("Expired", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExpiredWithinSkew_IsAccepted()
    {
        // OidcClientOptions.ClockSkew defaults to five minutes; two minutes past exp is inside it.
        var result = await _validator.ValidateAsync(
            CreateToken(lifetime: TimeSpan.FromMinutes(-2)), Options(), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
    }

    [Fact]
    public async Task Hs256Token_IsRejected()
    {
        // A symmetric signature must never authenticate a login: HS256 is outside the asymmetric-only
        // allowlist, and no symmetric key is ever placed in the JWKS to resolve it against.
        var descriptor = Descriptor();
        descriptor.SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(new byte[32]) { KeyId = KeyId }, SecurityAlgorithms.HmacSha256);
        var token = new JsonWebTokenHandler().CreateToken(descriptor);

        var result = await _validator.ValidateAsync(token, Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
    }

    [Fact]
    public async Task UnsignedToken_IsRejected()
    {
        var descriptor = Descriptor();
        descriptor.SigningCredentials = null; // alg=none
        var token = new JsonWebTokenHandler().CreateToken(descriptor);

        var result = await _validator.ValidateAsync(token, Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
    }

    [Fact]
    public async Task UnknownSigningKey_ReturnsInvalidSignature_ForKeyRefreshRetry()
    {
        // The exact "invalid_signature" string is the contract that makes OidcClient refresh the
        // JWKS and retry once — the path that heals a signing-key rotation.
        using var otherRsa = RSA.Create(2048);
        var descriptor = Descriptor();
        descriptor.SigningCredentials = new SigningCredentials(
            new RsaSecurityKey(otherRsa) { KeyId = "rotated-away" }, SecurityAlgorithms.RsaSha256);
        var token = new JsonWebTokenHandler().CreateToken(descriptor);

        var result = await _validator.ValidateAsync(token, Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Equal("invalid_signature", result.Error);
    }

    [Fact]
    public async Task AzpMismatch_IsRejected_AndMatchingAzpAccepted()
    {
        var mismatch = await _validator.ValidateAsync(
            CreateToken(claims: new Dictionary<string, object> { ["azp"] = "someone-else" }),
            Options(),
            TestContext.Current.CancellationToken);
        Assert.True(mismatch.IsError);
        Assert.Contains("azp", mismatch.Error, StringComparison.Ordinal);

        var match = await _validator.ValidateAsync(
            CreateToken(claims: new Dictionary<string, object> { ["azp"] = ClientId }),
            Options(),
            TestContext.Current.CancellationToken);
        Assert.False(match.IsError, match.Error);
    }

    [Fact]
    public async Task MultiAudience_WithoutAzp_IsRejected()
    {
        // OIDC Core 3.1.3.7 rules 3-4: our client id is among the audiences, but the token is also
        // scoped to another party and carries no azp — reject rather than accept a co-audience token.
        var descriptor = Descriptor();
        descriptor.Audience = null;
        descriptor.Audiences.Add(ClientId);
        descriptor.Audiences.Add("other-api");
        var token = new JsonWebTokenHandler().CreateToken(descriptor);

        var result = await _validator.ValidateAsync(token, Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Contains("audiences", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MultiAudience_WithMatchingAzp_IsAccepted()
    {
        var descriptor = Descriptor(claims: new Dictionary<string, object> { ["sub"] = "user-1", ["azp"] = ClientId });
        descriptor.Audience = null;
        descriptor.Audiences.Add(ClientId);
        descriptor.Audiences.Add("other-api");
        var token = new JsonWebTokenHandler().CreateToken(descriptor);

        var result = await _validator.ValidateAsync(token, Options(), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
    }

    [Fact]
    public async Task NullEntryInJwks_IsSkipped_GoodKeyStillValidates()
    {
        // A JWKS carrying a literal null entry must not 500 the login (skip-on-malformed contract).
        var p = _rsa.ExportParameters(false);
        var options = Options(jwks: $$"""
            {"keys":[null,{"kty":"RSA","use":"sig","kid":"{{KeyId}}",
              "n":"{{Base64UrlEncoder.Encode(p.Modulus)}}","e":"{{Base64UrlEncoder.Encode(p.Exponent)}}"}]}
            """);

        var result = await _validator.ValidateAsync(CreateToken(), options, TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-jwt")]
    [InlineData("only.two")]
    [InlineData("aaa.bbb.ccc.ddd.eee")]
    [InlineData("...")]
    public async Task MalformedToken_IsRejected_WithoutThrowing(string token)
    {
        // Hostile/garbage tokens must return a clean error result, never throw (which would surface as
        // a 500 on the OIDC callback instead of a rejected login).
        var result = await _validator.ValidateAsync(token, Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
    }

    [Fact]
    public async Task Es256Token_Succeeds_ViaEcKeyConversion()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = ecdsa.ExportParameters(false).Q;
        var options = Options(jwks: $$"""
            {"keys":[{"kty":"EC","use":"sig","kid":"{{KeyId}}","crv":"P-256",
              "x":"{{Base64UrlEncoder.Encode(point.X)}}","y":"{{Base64UrlEncoder.Encode(point.Y)}}"}]}
            """);
        var descriptor = Descriptor();
        descriptor.SigningCredentials = new SigningCredentials(
            new ECDsaSecurityKey(ecdsa) { KeyId = KeyId }, SecurityAlgorithms.EcdsaSha256);
        var token = new JsonWebTokenHandler().CreateToken(descriptor);

        var result = await _validator.ValidateAsync(token, options, TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
        Assert.Equal("ES256", result.SignatureAlgorithm);
    }

    [Fact]
    public async Task EncryptionOnlyKey_IsNotUsedForSignatures()
    {
        // The signing key is advertised as use:"enc": it must be excluded from signature validation,
        // leaving no usable key — the key-not-found path, i.e. "invalid_signature".
        var p = _rsa.ExportParameters(false);
        var options = Options(jwks: $$"""
            {"keys":[{"kty":"RSA","use":"enc","kid":"{{KeyId}}",
              "n":"{{Base64UrlEncoder.Encode(p.Modulus)}}","e":"{{Base64UrlEncoder.Encode(p.Exponent)}}"}]}
            """);

        var result = await _validator.ValidateAsync(CreateToken(), options, TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Equal("invalid_signature", result.Error);
    }

    [Fact]
    public async Task MalformedKeyInSet_IsSkipped_GoodKeyStillValidates()
    {
        // One broken advertised key must not take down logins signed by the good one.
        var p = _rsa.ExportParameters(false);
        var options = Options(jwks: $$"""
            {"keys":[
              {"kty":"RSA","use":"sig","kid":"broken","n":"!!not-base64url!!","e":"AQAB"},
              {"kty":"RSA","use":"sig","kid":"{{KeyId}}",
               "n":"{{Base64UrlEncoder.Encode(p.Modulus)}}","e":"{{Base64UrlEncoder.Encode(p.Exponent)}}"}]}
            """);

        var result = await _validator.ValidateAsync(CreateToken(), options, TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
    }

    // --- helpers ---

    private OidcClientOptions Options(string? jwks = null)
    {
        var p = _rsa.ExportParameters(false);
        jwks ??= $$"""
            {"keys":[{"kty":"RSA","use":"sig","kid":"{{KeyId}}",
              "n":"{{Base64UrlEncoder.Encode(p.Modulus)}}","e":"{{Base64UrlEncoder.Encode(p.Exponent)}}"}]}
            """;
        return new OidcClientOptions
        {
            ClientId = ClientId,
            ProviderInformation = new ProviderInformation
            {
                IssuerName = Issuer,
                KeySet = new Duende.IdentityModel.Jwk.JsonWebKeySet(jwks),
            },
        };
    }

    private SecurityTokenDescriptor Descriptor(
        string issuer = Issuer,
        string audience = ClientId,
        TimeSpan? lifetime = null,
        IDictionary<string, object>? claims = null)
    {
        var now = DateTime.UtcNow;
        var expires = now + (lifetime ?? TimeSpan.FromMinutes(5));
        return new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            IssuedAt = now - TimeSpan.FromMinutes(15),
            NotBefore = now - TimeSpan.FromMinutes(15),
            Expires = expires,
            Claims = claims ?? new Dictionary<string, object> { ["sub"] = "user-1" },
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(_rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
        };
    }

    private string CreateToken(
        string issuer = Issuer,
        string audience = ClientId,
        TimeSpan? lifetime = null,
        IDictionary<string, object>? claims = null)
    {
        return new JsonWebTokenHandler().CreateToken(Descriptor(issuer, audience, lifetime, claims));
    }
}

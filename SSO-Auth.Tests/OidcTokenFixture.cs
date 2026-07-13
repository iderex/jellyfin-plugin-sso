using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Builds a real signed OpenID Connect id_token plus the matching JWKS against a throw-away RSA key, so
/// a test can drive the token-exchange callback (<c>OidPost</c>) through the actual id_token validation
/// path (<see cref="Jellyfin.Plugin.SSO_Auth.Api.OidcIdTokenValidator"/>) rather than mocks. The
/// discovery document, this JWKS, and a token endpoint returning <see cref="TokenEndpointJson"/> are
/// served in-process through the harness's HTTP responder.
/// </summary>
internal sealed class OidcTokenFixture : IDisposable
{
    private const string KeyId = "oidpost-test-key";
    private readonly RSA _rsa = RSA.Create(2048);

    internal OidcTokenFixture(string issuer, string clientId)
    {
        Issuer = issuer;
        ClientId = clientId;
    }

    internal string Issuer { get; }

    internal string ClientId { get; }

    /// <summary>Gets the JWKS carrying this fixture's signing public key.</summary>
    internal string Jwks()
    {
        var p = _rsa.ExportParameters(false);
        return "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"" + KeyId + "\",\"alg\":\"RS256\","
            + "\"n\":\"" + Base64UrlEncoder.Encode(p.Modulus) + "\",\"e\":\"" + Base64UrlEncoder.Encode(p.Exponent) + "\"}]}";
    }

    /// <summary>
    /// Produces a signed id_token for the given username. A non-empty <paramref name="subject"/> is
    /// emitted as the "sub" claim; passing null/empty omits it (for the missing-sub rejection path).
    /// </summary>
    internal string IdToken(string? subject, string username)
    {
        var now = DateTime.UtcNow;
        var claims = new Dictionary<string, object> { ["preferred_username"] = username };
        if (!string.IsNullOrEmpty(subject))
        {
            claims["sub"] = subject;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            IssuedAt = now - TimeSpan.FromMinutes(1),
            NotBefore = now - TimeSpan.FromMinutes(1),
            Expires = now + TimeSpan.FromMinutes(5),
            Claims = claims,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    /// <summary>The token-endpoint response body carrying the signed id_token.</summary>
    internal string TokenEndpointJson(string idToken) =>
        "{\"access_token\":\"test-access-token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"id_token\":\"" + idToken + "\"}";

    /// <summary>The discovery document advertising this fixture's issuer and endpoints (all on the issuer).</summary>
    internal string Discovery() =>
        "{\"issuer\":\"" + Issuer + "\","
        + "\"authorization_endpoint\":\"" + Issuer + "/authorize\","
        + "\"token_endpoint\":\"" + Issuer + "/token\","
        + "\"jwks_uri\":\"" + Issuer + "/jwks\","
        + "\"userinfo_endpoint\":\"" + Issuer + "/userinfo\","
        + "\"response_types_supported\":[\"code\"],"
        + "\"subject_types_supported\":[\"public\"],"
        + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
        + "\"grant_types_supported\":[\"authorization_code\"],"
        + "\"code_challenge_methods_supported\":[\"S256\"]}";

    /// <summary>The URL the fixture serves each document at.</summary>
    internal string DiscoveryUrl => Issuer + "/.well-known/openid-configuration";

    internal string JwksUrl => Issuer + "/jwks";

    internal string TokenUrl => Issuer + "/token";

    public void Dispose() => _rsa.Dispose();
}

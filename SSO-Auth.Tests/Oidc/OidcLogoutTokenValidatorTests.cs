// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Exercises <see cref="OidcLogoutTokenValidator"/> against a static JWKS (#962). Every OIDC Back-Channel
/// Logout 1.0 §2.6 rule is fail-closed and has a negative test — signature/issuer/audience/lifetime (the
/// SAME <see cref="OidcSignatureKeys"/> basis the id_token uses), the mandatory back-channel-logout event
/// member, the forbidden nonce (an id_token replayed as a logout_token), the at-least-one-of-sub/sid rule,
/// and jti one-time-use. Each rejection carries a fixed reason code and never a subject identifier.
/// </summary>
public sealed class OidcLogoutTokenValidatorTests : IDisposable
{
    private const string Issuer = "https://idp.example.test";
    private const string ClientId = "jellyfin-client";
    private const string KeyId = "test-signing-key";
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    private static readonly TimeSpan Skew = TimeSpan.FromMinutes(5);

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly OidcLogoutTokenValidator _validator = new();
    private readonly DateTime _now = DateTime.UtcNow;

    public OidcLogoutTokenValidatorTests() => OidcLogoutTokenValidator.ResetReplaysForTests();

    public void Dispose()
    {
        _rsa.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Fact]
    public async Task ValidLogoutToken_WithSubAndSid_Succeeds()
    {
        var token = CreateToken(claims: Claims(sub: "user-1", sid: "sess-9"));

        var result = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.True(result.IsValid);
        Assert.Equal("user-1", result.Subject);
        Assert.Equal("sess-9", result.SessionIndex);
        Assert.Empty(result.ReasonCode);
    }

    [Fact]
    public async Task SubOnly_Succeeds_SidNull()
    {
        var result = await _validator.ValidateAsync(CreateToken(claims: Claims(sub: "user-1")), Params(), Skew, _now);

        Assert.True(result.IsValid);
        Assert.Equal("user-1", result.Subject);
        Assert.Null(result.SessionIndex);
    }

    [Fact]
    public async Task SidOnly_Succeeds_SubNull()
    {
        var result = await _validator.ValidateAsync(CreateToken(claims: Claims(sid: "sess-9")), Params(), Skew, _now);

        Assert.True(result.IsValid);
        Assert.Null(result.Subject);
        Assert.Equal("sess-9", result.SessionIndex);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public async Task AbsentToken_IsMalformed(string? token)
    {
        // Nothing was sent — a distinct fail-closed code from a bad token that reached the JWT handler.
        var result = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Malformed, result.ReasonCode);
    }

    [Theory]
    [InlineData("not-a-jwt")]
    [InlineData("only.two")]
    [InlineData("a.b.c")]
    public async Task GarbageNonJwt_IsInvalid_FailClosed(string token)
    {
        // A non-empty non-JWT reaches the handler and fails signature/parse validation — still fail-closed,
        // reported as Invalid (the handler catches it, it never throws a 500).
        var result = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Invalid, result.ReasonCode);
    }

    [Fact]
    public async Task WrongSigningKey_IsInvalid()
    {
        using var attacker = RSA.Create(2048);
        var forged = new JsonWebTokenHandler().CreateToken(Descriptor(Claims(sub: "user-1"), signingKey: attacker));

        var result = await _validator.ValidateAsync(forged, Params(), Skew, _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Invalid, result.ReasonCode);
    }

    [Fact]
    public async Task WrongIssuer_IsInvalid()
    {
        var token = CreateToken(claims: Claims(sub: "user-1"), issuer: "https://evil.example.test");

        var result = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Invalid, result.ReasonCode);
    }

    [Fact]
    public async Task WrongAudience_IsInvalid()
    {
        var token = CreateToken(claims: Claims(sub: "user-1"), audience: "another-client");

        var result = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Invalid, result.ReasonCode);
    }

    [Fact]
    public async Task ExpiredToken_IsInvalid()
    {
        // 10 minutes past exp is beyond the default 5-minute clock skew.
        var token = CreateToken(claims: Claims(sub: "user-1"), lifetime: TimeSpan.FromMinutes(-10));

        var result = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Invalid, result.ReasonCode);
    }

    [Fact]
    public async Task NoEventsClaim_IsNotALogoutToken()
    {
        var token = CreateToken(claims: new Dictionary<string, object> { ["sub"] = "user-1", ["jti"] = Guid.NewGuid().ToString() });

        var result = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.NotALogoutToken, result.ReasonCode);
    }

    [Fact]
    public async Task EventsWithoutTheBackChannelMember_IsNotALogoutToken()
    {
        // A valid, signed token whose events claim names a DIFFERENT event — not a back-channel logout.
        var claims = Claims(sub: "user-1");
        claims["events"] = new Dictionary<string, object> { ["http://schemas.openid.net/event/some-other"] = new Dictionary<string, object>() };
        var token = CreateToken(claims: claims);

        var result = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.NotALogoutToken, result.ReasonCode);
    }

    [Fact]
    public async Task TokenCarryingNonce_IsRejected_IdTokenReplayedAsLogout()
    {
        // §2.4: a logout_token MUST NOT carry a nonce — this is what refuses an id_token replayed here.
        var claims = Claims(sub: "user-1");
        claims["nonce"] = "abc123";
        var token = CreateToken(claims: claims);

        var result = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.ProhibitedNonce, result.ReasonCode);
    }

    [Fact]
    public async Task NeitherSubNorSid_IsRejected()
    {
        var result = await _validator.ValidateAsync(CreateToken(claims: Claims()), Params(), Skew, _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.NoSubjectOrSid, result.ReasonCode);
    }

    [Fact]
    public async Task ReplayedJti_IsRejected_OneTimeUse()
    {
        var token = CreateToken(claims: Claims(sub: "user-1", jti: "fixed-jti"));

        var first = await _validator.ValidateAsync(token, Params(), Skew, _now);
        var second = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.True(first.IsValid);
        Assert.False(second.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Replay, second.ReasonCode);
    }

    [Fact]
    public async Task NoJti_ByteIdenticalResend_IsCaughtAsReplay()
    {
        // A token with no jti still gets one-time-use via its signature — a byte-identical resend collides.
        var token = CreateToken(claims: Claims(sub: "user-1"));

        Assert.True((await _validator.ValidateAsync(token, Params(), Skew, _now)).IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Replay, (await _validator.ValidateAsync(token, Params(), Skew, _now)).ReasonCode);
    }

    [Fact]
    public async Task NoSubjectIdentifierEverAppearsInAReasonCode()
    {
        // Fixed codes only — a rejection is never a subject oracle (T-I1).
        var token = CreateToken(claims: Claims(sub: "secret-subject", sid: "secret-session"));
        // Force a replay rejection carrying no subject text.
        await _validator.ValidateAsync(token, Params(), Skew, _now);
        var replay = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.DoesNotContain("secret-subject", replay.ReasonCode, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-session", replay.ReasonCode, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoExpClaim_StillSucceeds()
    {
        // #962 review fix: OIDC Back-Channel Logout §2.4 does NOT require exp; a spec-compliant exp-less
        // IdP must NOT be silently no-op'd. Replay is bounded by jti one-time-use, not exp.
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            IssuedAt = DateTime.UtcNow - TimeSpan.FromMinutes(1),
            Claims = Claims(sub: "user-1"),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
        });

        var result = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.True(result.IsValid);
        Assert.Equal("user-1", result.Subject);
    }

    [Fact]
    public async Task AzpMismatch_IsInvalid()
    {
        // Parity with the id_token validator (OIDC Core 3.1.3.7 rule 5): an azp naming a different party is
        // refused even though this client is the audience.
        var claims = Claims(sub: "user-1");
        claims["azp"] = "another-client";
        var result = await _validator.ValidateAsync(CreateToken(claims: claims), Params(), Skew, _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Invalid, result.ReasonCode);
    }

    [Fact]
    public async Task MultipleAudiencesWithoutAzp_IsInvalid()
    {
        // Rules 3-4: a multi-audience token MUST carry azp; one minted for a co-listed different party is refused.
        var claims = Claims(sub: "user-1");
        claims["aud"] = new[] { ClientId, "another-client" }; // multi-audience, no azp
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            IssuedAt = DateTime.UtcNow - TimeSpan.FromMinutes(1),
            Expires = DateTime.UtcNow + TimeSpan.FromMinutes(5),
            Claims = claims,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
        });

        var result = await _validator.ValidateAsync(token, Params(), Skew, _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Invalid, result.ReasonCode);
    }

    private static Dictionary<string, object> Claims(string? sub = null, string? sid = null, string? jti = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["events"] = new Dictionary<string, object> { [LogoutEvent] = new Dictionary<string, object>() },
        };
        if (sub != null)
        {
            claims["sub"] = sub;
        }

        if (sid != null)
        {
            claims["sid"] = sid;
        }

        claims["jti"] = jti ?? Guid.NewGuid().ToString();
        return claims;
    }

    private TokenValidationParameters Params()
    {
        var p = _rsa.ExportParameters(false);
        var jwks = $$"""
            {"keys":[{"kty":"RSA","use":"sig","kid":"{{KeyId}}",
              "n":"{{Base64UrlEncoder.Encode(p.Modulus)}}","e":"{{Base64UrlEncoder.Encode(p.Exponent)}}"}]}
            """;
        var options = new OidcClientOptions
        {
            ClientId = ClientId,
            ProviderInformation = new ProviderInformation
            {
                IssuerName = Issuer,
                KeySet = new Duende.IdentityModel.Jwk.JsonWebKeySet(jwks),
            },
        };
        // The back-channel path builds with requireExpiration:false (OIDC Back-Channel Logout §2.4 does not
        // mandate exp), so the tests validate under the same posture the endpoint uses.
        return OidcSignatureKeys.BuildValidationParameters(options, new List<IDisposable>(), requireExpiration: false);
    }

    private string CreateToken(IDictionary<string, object> claims, string issuer = Issuer, string audience = ClientId, TimeSpan? lifetime = null)
        => new JsonWebTokenHandler().CreateToken(Descriptor(claims, issuer, audience, lifetime));

    private SecurityTokenDescriptor Descriptor(IDictionary<string, object> claims, string issuer = Issuer, string audience = ClientId, TimeSpan? lifetime = null, RSA? signingKey = null)
    {
        var now = DateTime.UtcNow;
        return new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            IssuedAt = now - TimeSpan.FromMinutes(1),
            NotBefore = now - TimeSpan.FromMinutes(1),
            Expires = now + (lifetime ?? TimeSpan.FromMinutes(5)),
            Claims = claims,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(signingKey ?? _rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
        };
    }
}

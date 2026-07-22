// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcIdTokenAuthTime"/> — the max_age gate reads auth_time from the RAW, signature-
/// verified id_token (#961), never the UserInfo-merged principal. A numeric auth_time parses; an absent,
/// non-numeric, negative, or degenerate one yields null so the caller's fail-closed check refuses it.
/// </summary>
public class OidcIdTokenAuthTimeTests
{
    [Fact]
    public void Read_TokenCarryingAuthTime_ReturnsTheSeconds()
        => Assert.Equal(1_700_000_000L, OidcIdTokenAuthTime.Read(TokenWith(("sub", "user-1"), ("auth_time", 1_700_000_000L))));

    [Fact]
    public void Read_TokenWithoutAuthTime_ReturnsNull()
        => Assert.Null(OidcIdTokenAuthTime.Read(TokenWith(("sub", "user-1"))));

    [Fact]
    public void Read_NegativeAuthTime_ReadsAsNull_Malformed()
        => Assert.Null(OidcIdTokenAuthTime.Read(TokenWith(("auth_time", -5L))));

    [Fact]
    public void Read_NonNumericAuthTime_ReadsAsNull()
        => Assert.Null(OidcIdTokenAuthTime.Read(TokenWith(("auth_time", "yesterday"))));

    [Theory]
    [InlineData(253_402_300_800L)] // one past the DateTimeOffset upper bound
    [InlineData(1_700_000_000_000L)] // auth_time in MILLISECONDS (a common provider mistake)
    [InlineData(long.MaxValue)]
    public void Read_OutOfRangeAuthTime_ReadsAsNull_NoThrow(long value)
        => Assert.Null(OidcIdTokenAuthTime.Read(TokenWith(("auth_time", value))));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("not-a-jwt")]
    [InlineData("only.two")]
    [InlineData("...")]
    public void Read_AbsentOrDegenerateToken_ReturnsNullWithoutThrowing(string? token)
        => Assert.Null(OidcIdTokenAuthTime.Read(token));

    private static string TokenWith(params (string Type, object Value)[] claims)
    {
        var dict = new Dictionary<string, object>();
        foreach (var (type, value) in claims)
        {
            dict[type] = value;
        }

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor { Claims = dict });
    }
}

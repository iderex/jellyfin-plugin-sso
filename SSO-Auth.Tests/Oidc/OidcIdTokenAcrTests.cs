// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcIdTokenAcr"/> — the step-up gate reads the acr claim from the RAW, signature-
/// verified id_token (#757), never the UserInfo-merged principal, so a UserInfo-supplied acr cannot satisfy
/// the requirement. A degenerate token yields null (fail-closed at the gate) rather than throwing.
/// </summary>
public class OidcIdTokenAcrTests
{
    [Fact]
    public void Read_TokenCarryingAcr_ReturnsTheClaimValue()
        => Assert.Equal("mfa", OidcIdTokenAcr.Read(TokenWith(("sub", "user-1"), ("acr", "mfa"))));

    [Fact]
    public void Read_TokenWithoutAcr_ReturnsNull()
        => Assert.Null(OidcIdTokenAcr.Read(TokenWith(("sub", "user-1"))));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("not-a-jwt")]
    [InlineData("only.two")]
    [InlineData("...")]
    public void Read_AbsentOrDegenerateToken_ReturnsNullWithoutThrowing(string? token)
        => Assert.Null(OidcIdTokenAcr.Read(token));

    private static string TokenWith(params (string Type, string Value)[] claims)
    {
        var dict = new Dictionary<string, object>();
        foreach (var (type, value) in claims)
        {
            dict[type] = value;
        }

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor { Claims = dict });
    }
}

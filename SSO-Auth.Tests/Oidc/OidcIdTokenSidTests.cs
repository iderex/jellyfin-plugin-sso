// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcIdTokenSid"/> — the Single Logout capture reads the sid claim from the RAW,
/// signature-verified id_token (#727), never the UserInfo-merged principal, so a UserInfo-supplied sid
/// cannot poison the persisted logout key. A degenerate token yields null rather than throwing.
/// </summary>
public class OidcIdTokenSidTests
{
    [Fact]
    public void Read_TokenCarryingSid_ReturnsTheClaimValue()
        => Assert.Equal("sess-42", OidcIdTokenSid.Read(TokenWith(("sub", "user-1"), ("sid", "sess-42"))));

    [Fact]
    public void Read_TokenWithoutSid_ReturnsNull()
        => Assert.Null(OidcIdTokenSid.Read(TokenWith(("sub", "user-1"))));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("not-a-jwt")]
    [InlineData("only.two")]
    [InlineData("...")]
    public void Read_AbsentOrDegenerateToken_ReturnsNullWithoutThrowing(string? token)
        => Assert.Null(OidcIdTokenSid.Read(token));

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

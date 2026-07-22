// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcRoleExtractor"/> — reading role values out of an OpenID claim along the
/// configured role-claim path. Pins the parsing behavior extracted from the OID callback so it can
/// be reasoned about and refactored independently of the controller.
/// </summary>
public class OidcRoleExtractorTests
{
    [Fact]
    public void SingleSegment_ReturnsRawClaimValueAsOneRole()
    {
        // A one-segment path is not JSON: the claim value itself is the single role.
        Assert.Equal(new List<string> { "jellyfin-admin" }, OidcRoleExtractor.ExtractRoles(new[] { "Role" }, "jellyfin-admin", false));
    }

    [Fact]
    public void TwoSegments_ReadsTerminalArray()
    {
        var roles = OidcRoleExtractor.ExtractRoles(new[] { "realm_access", "roles" }, "{\"roles\":[\"users\",\"admins\"]}", false);
        Assert.Equal(new List<string> { "users", "admins" }, roles);
    }

    [Fact]
    public void NestedSegments_WalkTheJsonPath()
    {
        var value = "{\"resource_access\":{\"jellyfin\":{\"roles\":[\"media\"]}}}";
        var roles = OidcRoleExtractor.ExtractRoles(new[] { "claim", "resource_access", "jellyfin", "roles" }, value, false);
        Assert.Equal(new List<string> { "media" }, roles);
    }

    [Fact]
    public void MissingIntermediateSegment_ReturnsEmpty()
    {
        // The intermediate "jellyfin" key is absent inside resource_access, so the walk stops short.
        var value = "{\"resource_access\":{\"other\":{\"roles\":[\"x\"]}}}";
        var roles = OidcRoleExtractor.ExtractRoles(new[] { "claim", "resource_access", "jellyfin", "roles" }, value, false);
        Assert.Empty(roles);
    }

    [Fact]
    public void IntermediateNodeNotAnObject_ReturnsEmpty()
    {
        var roles = OidcRoleExtractor.ExtractRoles(new[] { "claim", "resource_access", "roles" }, "{\"resource_access\":\"not-an-object\"}", false);
        Assert.Empty(roles);
    }

    [Fact]
    public void TerminalNotAnArray_ReturnsEmpty()
    {
        var roles = OidcRoleExtractor.ExtractRoles(new[] { "realm_access", "roles" }, "{\"roles\":\"single-string\"}", false);
        Assert.Empty(roles);
    }

    [Fact]
    public void MissingTerminalKey_ReturnsEmpty()
    {
        var roles = OidcRoleExtractor.ExtractRoles(new[] { "realm_access", "roles" }, "{\"other\":[\"x\"]}", false);
        Assert.Empty(roles);
    }

    [Fact]
    public void JsonNull_ReturnsEmpty()
    {
        // A literal JSON null deserializes to a null dictionary → no roles (not a throw).
        Assert.Empty(OidcRoleExtractor.ExtractRoles(new[] { "realm_access", "roles" }, "null", false));
    }

    [Fact]
    public void MultiSegmentPath_MalformedClaimValue_ReturnsEmpty()
    {
        // #216: a multi-segment path over a malformed (non-JSON) claim value fails CLOSED to no roles
        // instead of throwing an unhandled 500 on the public callback.
        Assert.Empty(OidcRoleExtractor.ExtractRoles(new[] { "realm_access", "roles" }, "not-json", false));
    }

    [Fact]
    public void TerminalArrayWithNonStringElements_KeepsOnlyStrings()
    {
        // #216: a terminal array mixing strings with objects/numbers must not throw; only the string
        // elements are taken as roles.
        var roles = OidcRoleExtractor.ExtractRoles(
            new[] { "realm_access", "roles" },
            "{\"roles\":[\"users\",1,{\"nested\":true},\"admins\"]}",
            false);
        Assert.Equal(new List<string> { "users", "admins" }, roles);
    }

    [Fact]
    public void ObjectMap_SingleSegment_ReadsThePropertyNamesAsRoles()
    {
        // #934: Zitadel's shape. The claim value IS the terminal object, and its property NAMES are the
        // roles; the values are the granting org's id→domain bookkeeping and are deliberately not read.
        var roles = OidcRoleExtractor.ExtractRoles(
            new[] { "urn:zitadel:iam:org:project:roles" },
            "{\"jellyfin-access\":{\"orgid\":\"example.com\"},\"jellyfin-admin\":{\"orgid\":\"example.com\"}}",
            true);
        Assert.Equal(new List<string> { "jellyfin-access", "jellyfin-admin" }, roles);
    }

    [Fact]
    public void ObjectMap_NestedPath_ReadsTheTerminalObjectsPropertyNames()
    {
        var value = "{\"resource_access\":{\"jellyfin\":{\"roles\":{\"media\":{\"x\":1}}}}}";
        var roles = OidcRoleExtractor.ExtractRoles(
            new[] { "claim", "resource_access", "jellyfin", "roles" },
            value,
            true);
        Assert.Equal(new List<string> { "media" }, roles);
    }

    [Fact]
    public void ObjectMap_EmptyObject_ReturnsNoRoles()
    {
        // An empty map must mean NO roles, never "any role" — the allow-list check would otherwise be
        // satisfiable by a provider that granted the user nothing.
        Assert.Empty(OidcRoleExtractor.ExtractRoles(new[] { "urn:zitadel:iam:org:project:roles" }, "{}", true));
    }

    [Fact]
    public void ObjectMap_ArrayTerminal_ReturnsEmpty()
    {
        // The flag names the shape; a mismatched terminal is no roles, not a fallback guess.
        Assert.Empty(OidcRoleExtractor.ExtractRoles(new[] { "realm_access", "roles" }, "{\"roles\":[\"users\"]}", true));
    }

    [Fact]
    public void ObjectMap_ScalarClaimValue_ReturnsEmpty()
    {
        // A single-segment object-map path no longer takes the raw value as a role: a provider that
        // regressed to emitting a plain string must grant nothing, not a role literally named "users".
        Assert.Empty(OidcRoleExtractor.ExtractRoles(new[] { "urn:zitadel:iam:org:project:roles" }, "users", true));
    }

    [Fact]
    public void ObjectMap_JsonArrayClaimValue_ReturnsEmpty()
    {
        // Deserializing a JSON array into the object shape throws inside the try — it must fail closed to
        // no roles, never an unhandled 500 on the public callback (#216).
        Assert.Empty(OidcRoleExtractor.ExtractRoles(new[] { "urn:zitadel:iam:org:project:roles" }, "[\"users\"]", true));
    }

    [Fact]
    public void ObjectMap_MalformedClaimValue_ReturnsEmpty()
    {
        Assert.Empty(OidcRoleExtractor.ExtractRoles(new[] { "urn:zitadel:iam:org:project:roles" }, "not-json", true));
    }

    [Theory]
    [InlineData("{\"a\":{},\"a\":{}}")]      // duplicate JSON keys
    [InlineData("{\"\":{}}")]                // empty property name
    [InlineData("{\"a\":null}")]
    [InlineData("{\"a\":1}")]
    [InlineData("{\"a\":[1,2]}")]
    [InlineData("\"scalar\"")]
    [InlineData("123")]
    [InlineData("true")]
    [InlineData("")]
    [InlineData("[\"users\"]")]
    public void ObjectMap_HostileClaimValues_NeverThrow(string claimValue)
    {
        // #216/#934: the claim value is attacker-influenced and reaches this parser on the ANONYMOUS public
        // callback, so no shape may escape as an unhandled exception (a 500). The method catches JsonException
        // only, so this pins that nothing else — a duplicate-key dictionary populate, an empty key, a scalar
        // or array root — throws something outside it.
        Assert.NotNull(OidcRoleExtractor.ExtractRoles(new[] { "roles" }, claimValue, true));
    }

    [Fact]
    public void ObjectMap_PathologicallyDeepClaimValue_FailsClosedWithoutThrowing()
    {
        // A depth-bomb claim value must fail closed, not stack-overflow or escape as a 500. Newtonsoft's
        // depth limit surfaces as a JsonException, which the parser already swallows.
        var deep = new System.Text.StringBuilder();
        for (int i = 0; i < 5000; i++)
        {
            deep.Append("{\"a\":");
        }

        deep.Append('1');
        for (int i = 0; i < 5000; i++)
        {
            deep.Append('}');
        }

        Assert.Empty(OidcRoleExtractor.ExtractRoles(new[] { "roles" }, deep.ToString(), true));
    }

    [Fact]
    public void ArrayMode_ObjectTerminal_StillReturnsEmpty()
    {
        // The pre-#934 behaviour is unchanged for every provider that does not opt in: an object terminal
        // read in array mode yields no roles rather than silently adopting the new shape.
        Assert.Empty(OidcRoleExtractor.ExtractRoles(new[] { "realm_access", "roles" }, "{\"roles\":{\"users\":{}}}", false));
    }
}

using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api;
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
        Assert.Equal(new List<string> { "jellyfin-admin" }, OidcRoleExtractor.ExtractRoles(new[] { "Role" }, "jellyfin-admin"));
    }

    [Fact]
    public void TwoSegments_ReadsTerminalArray()
    {
        var roles = OidcRoleExtractor.ExtractRoles(new[] { "realm_access", "roles" }, "{\"roles\":[\"users\",\"admins\"]}");
        Assert.Equal(new List<string> { "users", "admins" }, roles);
    }

    [Fact]
    public void NestedSegments_WalkTheJsonPath()
    {
        var value = "{\"resource_access\":{\"jellyfin\":{\"roles\":[\"media\"]}}}";
        var roles = OidcRoleExtractor.ExtractRoles(new[] { "claim", "resource_access", "jellyfin", "roles" }, value);
        Assert.Equal(new List<string> { "media" }, roles);
    }

    [Fact]
    public void MissingIntermediateSegment_ReturnsEmpty()
    {
        // The intermediate "jellyfin" key is absent inside resource_access, so the walk stops short.
        var value = "{\"resource_access\":{\"other\":{\"roles\":[\"x\"]}}}";
        var roles = OidcRoleExtractor.ExtractRoles(new[] { "claim", "resource_access", "jellyfin", "roles" }, value);
        Assert.Empty(roles);
    }

    [Fact]
    public void IntermediateNodeNotAnObject_ReturnsEmpty()
    {
        var roles = OidcRoleExtractor.ExtractRoles(new[] { "claim", "resource_access", "roles" }, "{\"resource_access\":\"not-an-object\"}");
        Assert.Empty(roles);
    }

    [Fact]
    public void TerminalNotAnArray_ReturnsEmpty()
    {
        var roles = OidcRoleExtractor.ExtractRoles(new[] { "realm_access", "roles" }, "{\"roles\":\"single-string\"}");
        Assert.Empty(roles);
    }

    [Fact]
    public void MissingTerminalKey_ReturnsEmpty()
    {
        var roles = OidcRoleExtractor.ExtractRoles(new[] { "realm_access", "roles" }, "{\"other\":[\"x\"]}");
        Assert.Empty(roles);
    }

    [Fact]
    public void JsonNull_ReturnsEmpty()
    {
        // A literal JSON null deserializes to a null dictionary → no roles (not a throw).
        Assert.Empty(OidcRoleExtractor.ExtractRoles(new[] { "realm_access", "roles" }, "null"));
    }

    [Fact]
    public void MultiSegmentPath_MalformedClaimValue_Throws()
    {
        // Characterizes the upstream behavior: a multi-segment path over a malformed (non-JSON-object)
        // claim value throws (surfaces as a 500 in the controller = fail-closed). Pinned so it stays deliberate.
        Assert.ThrowsAny<Newtonsoft.Json.JsonException>(
            () => OidcRoleExtractor.ExtractRoles(new[] { "realm_access", "roles" }, "not-json"));
    }
}

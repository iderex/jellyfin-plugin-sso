using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="CanonicalLinkRevoker"/> — removing a user's canonical links so an admin's SSO
/// unregister actually stops SSO login from resolving to the account (#213).
/// </summary>
public class CanonicalLinkRevokerTests
{
    private static readonly Guid Target = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Other = Guid.Parse("22222222-2222-2222-2222-222222222222");

    [Fact]
    public void RemovesOnlyTheTargetUsersEntries()
    {
        var links = new Dictionary<string, Guid>
        {
            ["sub-a"] = Target,
            ["sub-b"] = Other,
            ["legacy-alice"] = Target,
        };

        var removed = CanonicalLinkRevoker.RemoveUser(links, Target);

        Assert.Equal(2, removed);
        Assert.Equal(new[] { "sub-b" }, links.Keys);
        Assert.Equal(Other, links["sub-b"]);
    }

    [Fact]
    public void NoMatchingEntries_RemovesNothing()
    {
        var links = new Dictionary<string, Guid> { ["sub-b"] = Other };

        Assert.Equal(0, CanonicalLinkRevoker.RemoveUser(links, Target));
        Assert.Single(links);
    }

    [Fact]
    public void NullMap_IsNoOp()
    {
        Assert.Equal(0, CanonicalLinkRevoker.RemoveUser(null, Target));
    }
}

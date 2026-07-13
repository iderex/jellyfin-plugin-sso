using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization tests pinning the exact provider-scoped one-time-use key format, so the SAML replay
/// and outstanding-request caches keep isolating keys per provider and the empty-id passthrough is
/// preserved after the helper extraction (#318 step 2).
/// </summary>
public class ProviderScopedKeyTests
{
    [Fact]
    public void For_NonEmptyId_PrefixesTheProviderWithANewlineSeparator()
    {
        Assert.Equal("keycloak\nassertion-1", ProviderScopedKey.For("keycloak", "assertion-1"));
    }

    [Fact]
    public void For_EmptyId_PassesTheEmptyValueThrough()
    {
        Assert.Equal(string.Empty, ProviderScopedKey.For("keycloak", string.Empty));
    }

    [Fact]
    public void For_NullId_PassesNullThrough()
    {
        Assert.Null(ProviderScopedKey.For("keycloak", null));
    }

    [Fact]
    public void For_DistinctProviders_ProduceDistinctKeysForTheSameId()
    {
        Assert.NotEqual(ProviderScopedKey.For("a", "id"), ProviderScopedKey.For("b", "id"));
    }
}

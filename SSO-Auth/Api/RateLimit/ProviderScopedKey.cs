namespace Jellyfin.Plugin.SSO_Auth.Api.RateLimit;

/// <summary>
/// Forms the provider-scoped one-time-use key for the SAML replay and outstanding-AuthnRequest caches,
/// so a key issued under one provider can never be consumed on another provider's callback (#156, #219).
/// An empty or null id passes through unchanged — the caller treats an absent correlation id as its own
/// case rather than keying on a bare provider prefix.
/// </summary>
internal static class ProviderScopedKey
{
    // The newline separator cannot occur in a Guid-based AuthnRequest id, and both parts come from the
    // same trusted config/flow, so it partitions the key space by provider without collision.

    /// <summary>
    /// Forms the provider-scoped cache key <c>provider + "\n" + id</c>, so a one-time-use key issued under
    /// one provider cannot be consumed on another's callback (#156, #219). A null or empty
    /// <paramref name="id"/> passes through unchanged so the caller handles an absent correlation id itself.
    /// </summary>
    /// <param name="provider">The provider the key is scoped to.</param>
    /// <param name="id">The correlation id (e.g. AuthnRequest id); null/empty returns unchanged.</param>
    /// <returns>The scoped key, or the original null/empty id.</returns>
    internal static string? For(string provider, string? id) =>
        string.IsNullOrEmpty(id) ? id : provider + "\n" + id;
}

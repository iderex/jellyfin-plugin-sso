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
    internal static string For(string provider, string id) =>
        string.IsNullOrEmpty(id) ? id : provider + "\n" + id;
}

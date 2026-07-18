using System;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The SSO protocol a canonical-link operation applies to. The route's <c>{mode}</c> token is parsed into
/// this typed value once, at the controller boundary (<see cref="ProviderModeParser.TryParse"/>), and the
/// enum is threaded inward from there (#369) — so no inner layer re-parses or re-compares the raw string,
/// and an unknown token is rejected exactly once, fail-closed, before any protocol is chosen.
/// </summary>
internal enum ProviderMode
{
    /// <summary>SAML.</summary>
    Saml,

    /// <summary>OpenID Connect.</summary>
    Oid,
}

/// <summary>
/// The single home for the <see cref="ProviderMode"/> ↔ string-token mapping (#369): parsing the route
/// token into the enum at the boundary, and rendering the enum back to its lowercase link-namespace token
/// for operator log lines. Nothing else in the linking surface touches the raw <c>"oid"</c>/<c>"saml"</c>
/// strings — they thread the typed enum instead.
/// </summary>
internal static class ProviderModeParser
{
    /// <summary>
    /// Parses the route's <c>{mode}</c> token into a <see cref="ProviderMode"/>. Case-insensitive and
    /// culture-independent (ordinal), so the two protocols the plugin exposes are accepted in any casing
    /// while an unknown token fails closed — the caller rejects it rather than defaulting to a protocol.
    /// This replaces the two former divergent dispatches (a culture-sensitive <c>ToLower()</c> switch and an
    /// invariant-lowercase one) with one parse whose result every layer shares.
    /// </summary>
    /// <param name="value">The raw route token (<c>"oid"</c> / <c>"saml"</c>, any casing).</param>
    /// <param name="mode">The parsed mode when the token is recognized.</param>
    /// <returns><c>true</c> when the token names a known protocol; otherwise <c>false</c>.</returns>
    internal static bool TryParse(string? value, out ProviderMode mode)
    {
        if (string.Equals(value, "saml", StringComparison.OrdinalIgnoreCase))
        {
            mode = ProviderMode.Saml;
            return true;
        }

        if (string.Equals(value, "oid", StringComparison.OrdinalIgnoreCase))
        {
            mode = ProviderMode.Oid;
            return true;
        }

        mode = default;
        return false;
    }

    /// <summary>
    /// The lowercase link-namespace token (<c>"oid"</c> / <c>"saml"</c>) the canonical-link store keys under,
    /// used only to render the mode into operator-facing log lines. The exhaustive switch throws on an
    /// undefined enum value so a future third mode cannot slip through unlabelled.
    /// </summary>
    /// <param name="mode">The typed mode to render.</param>
    /// <returns>The lowercase protocol token.</returns>
    internal static string ToToken(this ProviderMode mode) => mode switch
    {
        ProviderMode.Saml => "saml",
        ProviderMode.Oid => "oid",
        _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown provider mode."),
    };
}

#nullable enable

using System;
using System.Buffers;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Rejects provider names that cannot round-trip through the callback URLs built from them (#336, #360).
/// The name is appended raw to the OIDC redirect_uri and the SAML AssertionConsumerServiceURL
/// (<see cref="SsoUrlBuilder"/>) and matched back by the callback routes, so URI-reserved characters
/// break the trip: '%' fails or changes route decoding, '/' produces a callback path no route can
/// match, '?' and '#' cut the name off at the query/fragment boundary, and the remaining RFC 3986
/// delimiters are structure to proxies and identity providers. Control characters break it the same way
/// and are rejected too (#360). Every registration surface shares this one predicate; the throw sites
/// (<see cref="SSOController"/>, <see cref="Config.ProviderConfigValidator"/>) gate only NEWLY registered
/// names, because the bytes built from an existing name are exactly what its identity provider already
/// has registered (pinned by the raw-provider tests in SsoUrlBuilderTests).
/// </summary>
internal static class ProviderNameValidator
{
    // RFC 3986 gen-delims and sub-delims, plus '%' (the percent-encoding escape, which routing decodes
    // or rejects before the config lookup ever sees the name), plus '\': browsers normalize a
    // backslash to '/' in special-scheme URLs (WHATWG URL), so an IdP redirect to ".../redirect/a\b"
    // arrives as ".../redirect/a/b" — the same unmatchable callback path as a literal slash. Space and
    // non-ASCII are deliberately NOT rejected: they survive the round-trip today, so rejecting them
    // would strand every existing working name that uses them.
    private static readonly SearchValues<char> UriReservedOrEscape = SearchValues.Create("%:/?#[]@!$&'()*+,;=\\");

    // A null or blank name yields an empty span, so the loop never runs and it stays valid — no route can
    // produce an empty provider segment, matching the blank-is-valid convention of the sibling predicates
    // (CanonicalBaseUrl, SamlCertificate).
    internal static bool IsInvalid(string? name)
    {
        foreach (char c in name.AsSpan())
        {
            // char.IsControl covers C0 (U+0000–U+001F), DEL (U+007F), and C1 (U+0080–U+009F) by name —
            // chosen over spelling the two disjoint ranges out with ContainsAnyInRange because the BCL
            // property states the intent where hex bounds would need verifying. Control characters do
            // not round-trip through the callback URL, and a newline is also the ProviderScopedKey
            // separator hazard flagged in #360; the reserved set holds the round-trip breakers above.
            if (char.IsControl(c) || UriReservedOrEscape.Contains(c))
            {
                return true;
            }
        }

        return false;
    }
}

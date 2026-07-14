#nullable enable

using System;
using System.Buffers;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Rejects provider names that cannot round-trip through the callback URLs built from them (#336).
/// The name is appended raw to the OIDC redirect_uri and the SAML AssertionConsumerServiceURL
/// (<see cref="SsoUrlBuilder"/>) and matched back by the callback routes, so URI-reserved characters
/// break the trip: '%' fails or changes route decoding, '/' produces a callback path no route can
/// match, '?' and '#' cut the name off at the query/fragment boundary, and the remaining RFC 3986
/// delimiters are structure to proxies and identity providers. Every registration surface shares this
/// one predicate; the throw sites (<see cref="SSOController"/>, <see cref="Config.ProviderConfigValidator"/>)
/// gate only NEWLY registered names, because the bytes built from an existing name are exactly what
/// its identity provider already has registered (pinned by the raw-provider tests in SsoUrlBuilderTests).
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

    // Blank is not this rule's concern (no route can produce an empty provider segment), matching the
    // blank-is-valid convention of the sibling predicates (CanonicalBaseUrl, SamlCertificate).
    internal static bool IsInvalid(string? name) => name.AsSpan().ContainsAny(UriReservedOrEscape);
}

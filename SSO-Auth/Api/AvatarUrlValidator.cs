using System;
using System.Net;
using System.Net.Sockets;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Validation helpers that constrain the server-side avatar fetch to public http(s) targets,
/// mitigating server-side request forgery via IdP-supplied avatar URLs/claims.
/// </summary>
internal static class AvatarUrlValidator
{
    /// <summary>
    /// Checks that the URL is an absolute http/https URL that does not obviously target a
    /// loopback/private/link-local address or localhost. Hostnames are validated again at connect
    /// time against their resolved address to defend against DNS-based SSRF and rebinding.
    /// </summary>
    /// <param name="url">The candidate avatar URL.</param>
    /// <param name="uri">The parsed URI when allowed; otherwise null.</param>
    /// <returns>True when the URL is allowed to be fetched.</returns>
    internal static bool IsAllowedUrl(string url, out Uri uri)
    {
        uri = null;
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var parsed))
        {
            return false;
        }

        if (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        // Strip a fully-qualified trailing dot ("localhost." / "host.") before the localhost check,
        // since it resolves the same but would otherwise slip past the string comparison.
        var host = parsed.DnsSafeHost.TrimEnd('.');
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (IPAddress.TryParse(host, out var literal) && IsBlockedAddress(literal))
        {
            return false;
        }

        uri = parsed;
        return true;
    }

    /// <summary>
    /// Determines whether an IP address belongs to a range that must never be reached by the
    /// avatar fetch (loopback, private, carrier-grade NAT, link-local, unique-local, unspecified).
    /// </summary>
    /// <param name="address">The address to classify.</param>
    /// <returns>True when the address is blocked.</returns>
    internal static bool IsBlockedAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => IsBlockedIPv4(address.GetAddressBytes()),
            AddressFamily.InterNetworkV6 => IsBlockedIPv6(address),

            // Unknown address family: block by default.
            _ => true,
        };
    }

    private static bool IsBlockedIPv4(byte[] b)
    {
        // 0.0.0.0/8 (this network), 10.0.0.0/8, 100.64.0.0/10 (CGNAT), 169.254.0.0/16 (link-local),
        // 172.16.0.0/12, 192.0.0.0/24 (IETF protocol assignments incl. the 192.0.0.192 cloud-metadata
        // address), 192.0.2.0/24 / 198.51.100.0/24 / 203.0.113.0/24 (TEST-NET-1/2/3), 192.88.99.0/24
        // (6to4 relay anycast), 192.168.0.0/16, 198.18.0.0/15 (benchmarking), and 224.0.0.0/3
        // (multicast 224/4, reserved 240/4, broadcast).
        return b[0] == 0
            || b[0] == 10
            || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
            || (b[0] == 169 && b[1] == 254)
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 0 && b[2] == 0)
            || (b[0] == 192 && b[1] == 0 && b[2] == 2)
            || (b[0] == 192 && b[1] == 88 && b[2] == 99)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 198 && (b[1] == 18 || b[1] == 19))
            || (b[0] == 198 && b[1] == 51 && b[2] == 100)
            || (b[0] == 203 && b[1] == 0 && b[2] == 113)
            || b[0] >= 224;
    }

    private static bool IsBlockedIPv6(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            return IsBlockedAddress(address.MapToIPv4());
        }

        // IPv4-in-IPv6 transition addresses (6to4, the NAT64 well-known prefix, and the deprecated
        // IPv4-compatible form) embed an IPv4 address that can target an internal range - unwrap it and
        // re-check, so e.g. [64:ff9b::7f00:1] cannot smuggle 127.0.0.1 past the filter.
        if (TryExtractEmbeddedIPv4(address.GetAddressBytes(), out var embedded))
        {
            return IsBlockedAddress(embedded);
        }

        // fec0::/10 is the deprecated site-local range (RFC 3879); block it as defense-in-depth.
        var v6 = address.GetAddressBytes();
        var siteLocal = v6[0] == 0xfe && (v6[1] & 0xc0) == 0xc0;

        return address.IsIPv6LinkLocal
            || address.IsIPv6UniqueLocal
            || address.IsIPv6Multicast
            || siteLocal
            || IPAddress.IPv6Any.Equals(address);
    }

    /// <summary>
    /// Extracts the IPv4 address embedded in an IPv4-in-IPv6 transition address (6to4 <c>2002::/16</c>, the
    /// NAT64 well-known prefix <c>64:ff9b::/96</c>, or the deprecated IPv4-compatible <c>::/96</c> form), so a
    /// blocked internal IPv4 cannot be reached by wrapping it in one of these formats.
    /// </summary>
    /// <param name="bytes">The 16 bytes of the IPv6 address.</param>
    /// <param name="embedded">The embedded IPv4 address when one is present; otherwise null.</param>
    /// <returns>True when an embedded IPv4 address was extracted.</returns>
    private static bool TryExtractEmbeddedIPv4(byte[] bytes, out IPAddress embedded)
    {
        embedded = null;

        // 6to4 (2002::/16): the embedded IPv4 is bytes 2-5.
        if (bytes[0] == 0x20 && bytes[1] == 0x02)
        {
            embedded = new IPAddress(new[] { bytes[2], bytes[3], bytes[4], bytes[5] });
            return true;
        }

        // NAT64 well-known prefix (64:ff9b::/96): the embedded IPv4 is the last 4 bytes.
        if (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b
            && bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0
            && bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0)
        {
            embedded = new IPAddress(new[] { bytes[12], bytes[13], bytes[14], bytes[15] });
            return true;
        }

        // IPv4-compatible (::/96, deprecated): first 96 bits zero, last 32 bits an IPv4 that is not the
        // unspecified (::) or loopback (::1) address (both already handled above).
        for (var i = 0; i < 12; i++)
        {
            if (bytes[i] != 0)
            {
                return false;
            }
        }

        if (!(bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && (bytes[15] == 0 || bytes[15] == 1)))
        {
            embedded = new IPAddress(new[] { bytes[12], bytes[13], bytes[14], bytes[15] });
            return true;
        }

        return false;
    }
}

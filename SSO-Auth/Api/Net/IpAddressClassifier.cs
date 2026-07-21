using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace Jellyfin.Plugin.SSO_Auth.Api.Net;

/// <summary>
/// Classifies a client-supplied or connection IP address as public or blocked (loopback, private,
/// carrier-grade NAT, link-local, unique/site-local, unspecified, reserved, or multicast), and unwraps the
/// IPv4 address embedded in an IPv4-in-IPv6 transition form (6to4, NAT64, the deprecated IPv4-compatible
/// form). Two unrelated callers share this one definition so they can never disagree on what counts as a
/// public address: the avatar-fetch SSRF guard (AvatarUrlValidator) rejects a blocked target
/// before fetching it, and the login rate limiter (SsoRateLimiter.NormalizeClientKey) exempts a
/// blocked/non-public connection address from throttling entirely. Neither caller's own file is the right
/// home for this shared invariant — tuning the avatar SSRF policy must never silently change which clients
/// the login rate limiter exempts, and vice versa (#370).
/// </summary>
internal static class IpAddressClassifier
{
    /// <summary>
    /// Determines whether an IP address belongs to a range that must never be treated as a public,
    /// externally-reachable client (loopback, private, carrier-grade NAT, link-local, unique-local,
    /// unspecified).
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

    /// <summary>
    /// Extracts the IPv4 address embedded in an IPv4-in-IPv6 transition address (6to4 <c>2002::/16</c>, the
    /// NAT64 well-known prefix <c>64:ff9b::/96</c>, or the deprecated IPv4-compatible <c>::/96</c> form). Both
    /// callers of this classifier share this single definition so they cannot disagree on what an embedded
    /// IPv4 is: the SSRF classifier unwraps it so a blocked internal IPv4 cannot be reached by wrapping it in
    /// one of these formats, and the rate limiter (SsoRateLimiter.NormalizeClientKey) keys a
    /// transition source on its embedded IPv4 instead of collapsing every such client into one shared /64
    /// bucket.
    /// </summary>
    /// <param name="bytes">The 16 bytes of the IPv6 address.</param>
    /// <param name="embedded">The embedded IPv4 address when one is present; otherwise null.</param>
    /// <returns>True when an embedded IPv4 address was extracted.</returns>
    internal static bool TryExtractEmbeddedIPv4(byte[] bytes, [NotNullWhen(true)] out IPAddress? embedded)
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

        var bytes = address.GetAddressBytes();

        // IPv4-in-IPv6 transition addresses (6to4, the NAT64 well-known prefix, and the deprecated
        // IPv4-compatible form) embed an IPv4 address that can target an internal range - unwrap it and
        // re-check, so e.g. [64:ff9b::7f00:1] cannot smuggle 127.0.0.1 past the filter.
        if (TryExtractEmbeddedIPv4(bytes, out var embedded))
        {
            return IsBlockedAddress(embedded);
        }

        // fec0::/10 is the deprecated site-local range (RFC 3879); block it as defense-in-depth.
        var siteLocal = bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0xc0;

        return address.IsIPv6LinkLocal
            || address.IsIPv6UniqueLocal
            || address.IsIPv6Multicast
            || siteLocal
            || IPAddress.IPv6Any.Equals(address);
    }
}

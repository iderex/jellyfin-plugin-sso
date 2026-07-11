using System.Net;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Coverage for the avatar-fetch SSRF guard: only public http(s) targets may be fetched.
/// </summary>
public class AvatarUrlValidatorTests
{
    [Theory]
    [InlineData("https://cdn.example.com/avatar.png")]
    [InlineData("http://example.com/a.jpg")]
    [InlineData("https://8.8.8.8/pic.png")]
    public void IsAllowedUrl_PublicHttpTargets_ReturnsTrue(string url)
    {
        Assert.True(AvatarUrlValidator.IsAllowedUrl(url, out var uri));
        Assert.NotNull(uri);
    }

    [Theory]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://example.com/x")]
    [InlineData("gopher://example.com/x")]
    [InlineData("not a url")]
    [InlineData("/relative/path")]
    [InlineData("")]
    [InlineData("http://localhost/x")]
    [InlineData("http://service.localhost/x")]
    [InlineData("http://127.0.0.1/x")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("http://192.0.0.192/")]
    [InlineData("http://10.0.0.5/x")]
    [InlineData("http://192.168.1.1/x")]
    [InlineData("http://172.16.0.1/x")]
    [InlineData("http://[::1]/x")]
    public void IsAllowedUrl_DisallowedTargets_ReturnsFalse(string url)
    {
        Assert.False(AvatarUrlValidator.IsAllowedUrl(url, out var uri));
        Assert.Null(uri);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.0.1")]
    [InlineData("169.254.0.1")]
    [InlineData("100.64.0.1")]
    [InlineData("0.0.0.0")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fc00::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("224.0.0.1")] // multicast
    [InlineData("239.255.255.250")] // multicast (SSDP)
    [InlineData("240.0.0.1")] // reserved
    [InlineData("255.255.255.255")] // broadcast
    [InlineData("64:ff9b::7f00:1")] // NAT64 well-known prefix embedding 127.0.0.1
    [InlineData("64:ff9b::a00:5")] // NAT64 embedding 10.0.0.5
    [InlineData("2002:7f00:1::")] // 6to4 embedding 127.0.0.1
    [InlineData("2002:c0a8:101::")] // 6to4 embedding 192.168.1.1
    [InlineData("::7f00:1")] // deprecated IPv4-compatible ::127.0.0.1
    [InlineData("192.0.0.192")] // Oracle Cloud metadata (192.0.0.0/24 protocol assignments)
    [InlineData("fec0::1")] // deprecated IPv6 site-local
    public void IsBlockedAddress_PrivateOrLoopback_ReturnsTrue(string ip)
    {
        Assert.True(AvatarUrlValidator.IsBlockedAddress(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("172.32.0.1")]
    [InlineData("100.63.255.255")]
    [InlineData("223.255.255.255")] // last unicast address just below the 224/4 multicast range
    [InlineData("2606:4700:4700::1111")]
    [InlineData("64:ff9b::808:808")] // NAT64 embedding the public 8.8.8.8
    public void IsBlockedAddress_PublicAddresses_ReturnsFalse(string ip)
    {
        Assert.False(AvatarUrlValidator.IsBlockedAddress(IPAddress.Parse(ip)));
    }
}

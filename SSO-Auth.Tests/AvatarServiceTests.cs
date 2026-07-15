using System.IO;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="AvatarService"/> — the SSRF-safe avatar fetch/store extracted from the controller
/// (#318). The security-relevant early returns (a null URL, and a URL the allow-list rejects) fail closed
/// without any outbound fetch or profile-image write; these are unit-testable without live HTTP. The fetch
/// path itself (transport SSRF guard, content-type allow-list, size cap) needs a live endpoint and is
/// exercised by the helper tests (AvatarUrlValidator, AvatarContentType) plus the real-server checklist.
/// </summary>
public class AvatarServiceTests
{
    private static (AvatarService Service, IProviderManager Providers, IUserManager Users, CapturingLogger Log) Build()
    {
        var users = Substitute.For<IUserManager>();
        var providers = Substitute.For<IProviderManager>();
        var serverConfig = Substitute.For<IServerConfigurationManager>();
        var log = new CapturingLogger();
        var service = new AvatarService(users, providers, serverConfig, log, "test-agent/1.0");
        return (service, providers, users, log);
    }

    private static User UserNamed(string name) => new User(name, "SSO-Auth", "Default");

    [Fact]
    public async Task TrySetAsync_NullUrl_DoesNothing()
    {
        var (service, providers, users, _) = Build();

        await service.TrySetAsync(UserNamed("alice"), null);

        await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
    }

    [Theory]
    [InlineData("http://127.0.0.1/avatar.png")] // loopback
    [InlineData("http://169.254.169.254/latest/meta-data/")] // cloud metadata
    [InlineData("http://10.0.0.5/x")] // private range
    [InlineData("file:///etc/passwd")] // non-http scheme
    [InlineData("not a url")] // unparseable
    public async Task TrySetAsync_DisallowedUrl_RefusesWithoutFetchingOrWriting(string url)
    {
        var (service, providers, users, log) = Build();

        await service.TrySetAsync(UserNamed("alice"), url);

        await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("disallowed URL"));
    }
}

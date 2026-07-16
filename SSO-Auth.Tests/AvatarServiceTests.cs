using System;
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
    private static readonly string UserDataRoot = Path.Combine("data", "users");

    private static (AvatarService Service, IProviderManager Providers, IUserManager Users, CapturingLogger Log) Build()
    {
        var users = Substitute.For<IUserManager>();
        var providers = Substitute.For<IProviderManager>();
        var serverConfig = Substitute.For<IServerConfigurationManager>();
        serverConfig.ApplicationPaths.UserConfigurationDirectoryPath.Returns(UserDataRoot);
        var log = new CapturingLogger();
        var service = new AvatarService(users, providers, serverConfig, log, "test-agent/1.0");
        return (service, providers, users, log);
    }

    private static string ProfilePath(string username, string extension)
        => Path.Combine(UserDataRoot, username, "profile" + extension);

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

    [Fact]
    public async Task StoreAsync_SaveFails_LeavesThePreviousAvatarUntouched()
    {
        // The #377 regression: a transient save failure must not downgrade the user from a working
        // avatar to a cleared record plus a dangling path — the write comes first, the user last.
        var (service, providers, users, _) = Build();
        var user = UserNamed("alice");
        var previous = new ImageInfo(ProfilePath("alice", ".jpg"));
        user.ProfileImage = previous;
        providers.SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromException(new IOException("disk full")));

        await Assert.ThrowsAsync<IOException>(
            () => service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png"));

        Assert.Same(previous, user.ProfileImage); // record untouched, still the old path
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
    }

    [Fact]
    public async Task StoreAsync_SamePathReLogin_OverwritesInPlaceWithoutClearing()
    {
        // The common re-login with the same content type overwrites the same file in place; the
        // record is already correct, so ClearProfileImageAsync (a DB-row removal) must not run —
        // it would drop and re-insert the record for nothing. The timestamp refresh is what makes
        // clients re-fetch the changed image.
        var (service, providers, users, _) = Build();
        var user = UserNamed("alice");
        var previous = new ImageInfo(ProfilePath("alice", ".png")) { LastModified = DateTime.UtcNow.AddDays(-1) };
        user.ProfileImage = previous;

        await service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png");

        Assert.Same(previous, user.ProfileImage); // record kept, not replaced
        Assert.True(user.ProfileImage.LastModified > DateTime.UtcNow.AddMinutes(-1)); // cache-busting refresh
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("alice", ".png"));
    }

    [Fact]
    public async Task StoreAsync_ChangedPath_ClearsTheOldImageOnlyAfterTheWrite()
    {
        // A changed content type moves the stored path: the old record+file are dropped only once
        // the new bytes are safely on disk (write -> clear order is the rollback-safety property).
        var (service, providers, users, _) = Build();
        var user = UserNamed("alice");
        user.ProfileImage = new ImageInfo(ProfilePath("alice", ".jpg"));

        await service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png");

        Received.InOrder(() =>
        {
            providers.SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("alice", ".png"));
            users.ClearProfileImageAsync(user);
        });
        Assert.Equal(ProfilePath("alice", ".png"), user.ProfileImage?.Path);
    }

    [Fact]
    public async Task StoreAsync_NoPreviousImage_AssignsWithoutClearing()
    {
        var (service, providers, users, _) = Build();
        var user = UserNamed("alice");

        await service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png");

        Assert.Equal(ProfilePath("alice", ".png"), user.ProfileImage?.Path);
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("alice", ".png"));
    }
}

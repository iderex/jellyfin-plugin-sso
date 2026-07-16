using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
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

    // Builds a service whose HTTP fetch is served by a stub handler returning the given response, so the
    // fetch path (content-type gate, size cap, happy path) runs without live HTTP (#385 seam).
    private static (AvatarService Service, IProviderManager Providers, IUserManager Users, CapturingLogger Log) Build(HttpResponseMessage response)
    {
        var users = Substitute.For<IUserManager>();
        var providers = Substitute.For<IProviderManager>();
        var serverConfig = Substitute.For<IServerConfigurationManager>();
        serverConfig.ApplicationPaths.UserConfigurationDirectoryPath.Returns(UserDataRoot);
        var log = new CapturingLogger();
        var service = new AvatarService(users, providers, serverConfig, log, "test-agent/1.0", () => new StubHandler(response));
        return (service, providers, users, log);
    }

    // An allowed public URL: the stub handler answers before any connection, so the URL only needs to
    // clear the allow-list — the SSRF transport guard (ConnectCallback) is never reached here.
    private const string AllowedUrl = "https://cdn.example.com/avatar.png";

    private static HttpResponseMessage ImageResponse(string mediaType, byte[] body, long? contentLength = null)
    {
        var content = new StreamContent(new MemoryStream(body));
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(mediaType);
        if (contentLength is { } length)
        {
            content.Headers.ContentLength = length;
        }

        return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
    }

    // Returns a single canned response for every request, standing in for the live HTTP fetch.
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly HttpResponseMessage _response;

        public StubHandler(HttpResponseMessage response) => _response = response;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_response);
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

    [Fact]
    public async Task ReadCappedAsync_BodyOverTheCap_Throws()
    {
        // #220, the single most security-relevant untested branch: a body larger than the cap — the
        // shape a hostile or Content-Length-lying endpoint produces — is aborted rather than buffered.
        using var response = ImageResponse("image/png", new byte[11]);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await AvatarService.ReadCappedAsync(response, maxBytes: 10, CancellationToken.None));
    }

    [Fact]
    public async Task ReadCappedAsync_BodyAtTheCap_RoundTripsRewound()
    {
        // A body exactly at the cap is accepted and returned ready to read (Position 0) for the store step.
        var body = new byte[10];
        using var response = ImageResponse("image/png", body);

        using var result = await AvatarService.ReadCappedAsync(response, maxBytes: 10, CancellationToken.None);

        Assert.Equal(10, result.Length);
        Assert.Equal(0, result.Position);
    }

    [Fact]
    public async Task TrySetAsync_DisallowedContentType_RefusesWithoutStoring()
    {
        // The content-type allow-list (#217): a non-raster type (here text/html, the shape an SVG or an
        // HTML error page would take) is refused after the fetch, before anything is written.
        using var response = ImageResponse("text/html", Encoding.UTF8.GetBytes("<html></html>"));
        var (service, providers, users, log) = Build(response);

        await service.TrySetAsync(UserNamed("alice"), AllowedUrl);

        await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("disallowed content type"));
    }

    [Fact]
    public async Task TrySetAsync_ContentLengthOverTheCap_RefusesWithoutStoring()
    {
        // The Content-Length pre-check rejects an oversized advertised body before streaming a byte.
        using var response = ImageResponse("image/png", new byte[1], contentLength: AvatarService.MaxAvatarBytes + 1);
        var (service, providers, _, _) = Build(response);

        await service.TrySetAsync(UserNamed("alice"), AllowedUrl);

        await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task TrySetAsync_AllowedImage_FetchesAndStores()
    {
        // The happy path end to end over the seam: an allowed raster type within the cap is fetched and
        // saved under the user's profile path with the media type carried through. The exact filename
        // (the missing extension dot) is #384's concern, so it is not pinned here.
        using var response = ImageResponse("image/png", new byte[] { 1, 2, 3 });
        var (service, providers, _, _) = Build(response);

        await service.TrySetAsync(UserNamed("alice"), AllowedUrl);

        await providers.Received(1).SaveImage(
            Arg.Any<Stream>(),
            "image/png",
            Arg.Is<string>(path => path.Contains("alice") && path.Contains("profile")));
    }
}

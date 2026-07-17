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

    // Builds a service whose store step serializes on the supplied lock, so a test can drive the #400
    // per-user serialization deterministically (hold the key, prove StoreAsync parks). The stub handler
    // is never invoked — these tests call StoreAsync directly, not the fetch path.
    private static (AvatarService Service, IProviderManager Providers, IUserManager Users, CapturingLogger Log) Build(KeyedLockStore userStoreLocks)
    {
        var users = Substitute.For<IUserManager>();
        var providers = Substitute.For<IProviderManager>();
        var serverConfig = Substitute.For<IServerConfigurationManager>();
        serverConfig.ApplicationPaths.UserConfigurationDirectoryPath.Returns(UserDataRoot);
        var log = new CapturingLogger();
        var service = new AvatarService(users, providers, serverConfig, log, "test-agent/1.0", () => new StubHandler(new HttpResponseMessage()), userStoreLocks);
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
    public async Task StoreAsync_ConcurrentSameUser_IsSerializedAndLeavesAConsistentRecord()
    {
        // #400, a deterministic overlapping-call test via the injected per-user lock seam: we take the
        // user's lock to stand in for a store already mid-flight for the SAME user, then start a real
        // StoreAsync. While the lock is held it cannot reach SaveImage — it is serialized behind the
        // in-flight store, proven by the held handle rather than by timing. Releasing the lock lets it run
        // to a single consistent record. (Unrelated users never block each other — KeyedLockStoreTests.)
        var locks = new KeyedLockStore(StringComparer.Ordinal);
        var (service, providers, users, _) = Build(locks);
        var user = UserNamed("racer");

        Task store;
        using (await locks.AcquireAsync(user.Username, TestContext.Current.CancellationToken))
        {
            store = service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png");

            Assert.False(store.IsCompleted); // parked before the write while the per-user lock is held
            await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
        }

        await store;

        // Once the in-flight store released, ours ran exactly once and left a single consistent record.
        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("racer", ".png"));
        Assert.Equal(ProfilePath("racer", ".png"), user.ProfileImage?.Path);
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
        Assert.Equal(0, locks.TrackedKeys); // both holders left; the map is collected
    }

    [Fact]
    public async Task StoreAsync_TwoOverlappingStores_SerializeAndTheLaterStoreWins()
    {
        // #400 acceptance criterion #2, the full shape: TWO real concurrent StoreAsync calls for the same
        // user must serialize the whole save + profile-image transition, and the later store's record must
        // be the final one (last-writer-consistent, no clobber). Deterministic via TaskCompletionSource
        // gates, no timing: the first store's SaveImage parks mid-critical-section (holding the per-user
        // lock) until we release it, so the second store provably cannot enter until then.
        var locks = new KeyedLockStore(StringComparer.Ordinal);
        var (service, providers, users, _) = Build(locks);
        var user = UserNamed("racer");
        var ct = TestContext.Current.CancellationToken;

        var pngPath = ProfilePath("racer", ".png"); // the first store's target
        var jpgPath = ProfilePath("racer", ".jpg"); // the second store's target (different path -> a real transition)
        var firstInsideCriticalSection = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirst = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        providers.SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(ci =>
            {
                // The first store's write parks here — inside the critical section, holding the lock —
                // until the test releases it; the second store's write completes at once.
                if (string.Equals(ci.ArgAt<string>(2), pngPath, StringComparison.Ordinal))
                {
                    firstInsideCriticalSection.TrySetResult();
                    return releaseFirst.Task;
                }

                return Task.CompletedTask;
            });

        var first = service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png");
        await firstInsideCriticalSection.Task.WaitAsync(ct); // the first store now holds the per-user lock

        var second = service.StoreAsync(user, new MemoryStream(new byte[] { 2 }), "image/jpeg", ".jpg");

        // The second store cannot enter the critical section while the first holds the lock: its write is
        // never issued, so the sequence is serialized rather than interleaved.
        Assert.False(second.IsCompleted);
        await providers.Received(1).SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
        await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), "image/jpeg", jpgPath);

        releaseFirst.SetResult();
        await first;
        await second;

        // Last-writer-consistent: the final record is the second store's, written only after the first
        // fully completed. Each store wrote exactly once, and the .png -> .jpg transition cleared the old
        // record only after the new bytes were on disk (#377), so there is no clobber.
        Assert.Equal(jpgPath, user.ProfileImage?.Path);
        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", pngPath);
        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/jpeg", jpgPath);
        await users.Received(1).ClearProfileImageAsync(user);
        Assert.Equal(0, locks.TrackedKeys); // both holders left; the map is collected
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
    public async Task TrySetAsync_AllowedImage_FetchesAndStoresWithDottedExtension()
    {
        // The happy path end to end over the seam: an allowed raster type within the cap is fetched and
        // saved to the resolved profile path — with a real dotted extension since #384.
        using var response = ImageResponse("image/png", new byte[] { 1, 2, 3 });
        var (service, providers, _, _) = Build(response);

        await service.TrySetAsync(UserNamed("alice"), AllowedUrl);

        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("alice", ".png"));
    }
}

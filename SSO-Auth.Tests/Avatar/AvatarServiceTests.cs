// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
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
    // fetch path (content-type gate, size cap, happy path, conditional 304) runs without live HTTP (#385
    // seam). The client wraps the stub and stands in for the process-wide shared client (#248).
    private static (AvatarService Service, IProviderManager Providers, IUserManager Users, CapturingLogger Log) Build(HttpResponseMessage response)
    {
        var users = Substitute.For<IUserManager>();
        var providers = Substitute.For<IProviderManager>();
        var serverConfig = Substitute.For<IServerConfigurationManager>();
        serverConfig.ApplicationPaths.UserConfigurationDirectoryPath.Returns(UserDataRoot);
        var log = new CapturingLogger();
        var service = new AvatarService(users, providers, serverConfig, log, "test-agent/1.0", new HttpClient(new StubHandler(response)));
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
        var service = new AvatarService(users, providers, serverConfig, log, "test-agent/1.0", new HttpClient(new StubHandler(new HttpResponseMessage())), userStoreLocks);
        return (service, providers, users, log);
    }

    // Builds a service whose store-lock ACQUIRE WAIT is bounded by the given (short, test-only) timeout
    // rather than the production 3s (#448, shortened by #541), so a test can drive the abort-on-timeout
    // branch deterministically and quickly instead of waiting out the real bound.
    private static (AvatarService Service, IProviderManager Providers, IUserManager Users, CapturingLogger Log) Build(KeyedLockStore userStoreLocks, TimeSpan storeLockAcquireTimeout)
    {
        var users = Substitute.For<IUserManager>();
        var providers = Substitute.For<IProviderManager>();
        var serverConfig = Substitute.For<IServerConfigurationManager>();
        serverConfig.ApplicationPaths.UserConfigurationDirectoryPath.Returns(UserDataRoot);
        var log = new CapturingLogger();
        var service = new AvatarService(
            users,
            providers,
            serverConfig,
            log,
            "test-agent/1.0",
            new HttpClient(new StubHandler(new HttpResponseMessage())),
            userStoreLocks,
            fileExists: null,
            storeLockAcquireTimeout: storeLockAcquireTimeout);
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

    // Returns a single canned response for every request, standing in for the live HTTP fetch, and records
    // what it was asked so a test can assert the conditional-fetch header (#248) and the reuse count.
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly HttpResponseMessage _response;

        public StubHandler(HttpResponseMessage response) => _response = response;

        // How many requests this one handler served — proves the client/handler is reused across fetches
        // (#248) rather than rebuilt per fetch.
        public int Invocations { get; private set; }

        // The If-Modified-Since sent on the most recent request, or null if the fetch was unconditional.
        public DateTimeOffset? LastIfModifiedSince { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Invocations++;
            LastIfModifiedSince = request.Headers.IfModifiedSince;
            return Task.FromResult(_response);
        }
    }

    private static HttpResponseMessage NotModifiedResponse() => new HttpResponseMessage(HttpStatusCode.NotModified);

    private static string ProfilePath(string username, string extension)
        => Path.Combine(UserDataRoot, username, "profile" + extension);


    [Fact]
    public async Task TrySetAsync_NullUrl_DoesNothing()
    {
        var (service, providers, users, _) = Build();

        await service.TrySetAsync(TestUsers.Named("alice"), null);

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

        await service.TrySetAsync(TestUsers.Named("alice"), url);

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
        var user = TestUsers.Named("alice");
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
        var user = TestUsers.Named("alice");
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
        var user = TestUsers.Named("alice");
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
        var user = TestUsers.Named("racer");

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
    public async Task StoreAsync_LockAcquireTimesOut_AbortsWithoutStoringUnguarded()
    {
        // #448: CancellationToken.None made the same-user acquire wait unbounded, so a store step stalled
        // while holding the gate could park every other concurrent login for that user forever. With a
        // bounded wait, a stalled holder (stood in for here by a lock we hold and never release) times the
        // waiter out; the store must abort — SaveImage is NEVER called (no unguarded write bypassing the
        // lock) and the user's profile-image record is left untouched — rather than propagate an unhandled
        // exception into the best-effort login path.
        var locks = new KeyedLockStore(StringComparer.Ordinal);
        var (service, providers, users, log) = Build(locks, TimeSpan.FromMilliseconds(50));
        var user = TestUsers.Named("racer");
        var previous = new ImageInfo(ProfilePath("racer", ".jpg"));
        user.ProfileImage = previous;

        using (await locks.AcquireAsync(user.Username, TestContext.Current.CancellationToken))
        {
            // The lock is held for the whole store attempt, standing in for a stalled concurrent store.
            await service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png");
        }

        await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
        Assert.Same(previous, user.ProfileImage); // record untouched — no unguarded store ran
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("Timed out"));
        Assert.Equal(0, locks.TrackedKeys); // the timed-out waiter left no reference behind
    }

    [Fact]
    public async Task StoreAsync_LockAcquiredBeforeTimeout_StoresNormally()
    {
        // The counterpart to the timeout test: when the lock is free (the normal case), a bounded wait
        // still lets the store through exactly as before — the timeout only aborts a genuinely stalled
        // wait, it does not shrink the normal-load window.
        var locks = new KeyedLockStore(StringComparer.Ordinal);
        var (service, providers, _, log) = Build(locks, TimeSpan.FromSeconds(3));
        var user = TestUsers.Named("alice");

        await service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png");

        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("alice", ".png"));
        Assert.Equal(ProfilePath("alice", ".png"), user.ProfileImage?.Path);
        Assert.DoesNotContain(log.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("Timed out"));
        Assert.Equal(0, locks.TrackedKeys);
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
        var user = TestUsers.Named("racer");
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
        var user = TestUsers.Named("alice");

        await service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png");

        Assert.Equal(ProfilePath("alice", ".png"), user.ProfileImage?.Path);
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("alice", ".png"));
    }

    [Theory]
    [InlineData("..")] // parent-directory escape: Path.Combine(root, "..", ...) writes into the PARENT of the user-config dir
    [InlineData(".")] // current-directory component
    [InlineData("../evil")] // separator + traversal
    [InlineData("a/b")] // forward slash
    [InlineData("a\\b")] // backslash
    public async Task StoreAsync_UnsafeUsername_SkipsWriteWithoutThrowingOrEscaping(string username)
    {
        // #447: user.Username is IdP-controlled (OIDC preferred_username / SAML NameID) and only the host's
        // own CreateUserAsync validates it — a regex that ADMITS '.' and '..'. A username of ".." would make
        // Path.Combine write the fetched image into the PARENT of the user-config directory. The store must
        // fail closed: no out-of-directory write (SaveImage is never called with any path), no throw (login
        // is best-effort and must still complete), and no profile-image record.
        var (service, providers, users, log) = Build();
        var user = TestUsers.Named(username);

        await service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png");

        await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
        Assert.Null(user.ProfileImage);
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("safe path component"));
    }

    [Fact]
    public async Task StoreAsync_UnsafeUsername_LeavesAnExistingProfileImageUntouched()
    {
        // Fail-closed must not be destructive either: a rejected ".." username skips the write AND leaves
        // any previously set profile-image record exactly as it was (no clear, no re-point).
        var (service, providers, users, _) = Build();
        var user = TestUsers.Named("..");
        var previous = new ImageInfo(ProfilePath("alice", ".jpg"));
        user.ProfileImage = previous;

        await service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png");

        Assert.Same(previous, user.ProfileImage);
        await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
    }

    [Fact]
    public async Task StoreAsync_WindowsTrailingDotUsername_DoesNotWriteIntoAnotherUsersDirectory()
    {
        // #447 layer-2 (the round-trip containment check, the branch the character check can't reach):
        // the host username regex admits a trailing dot, and Windows strips it, so "victim." would fold
        // onto another user's "victim" directory — an in-root cross-user avatar overwrite. The guard must
        // reject any username whose resolved path is not exactly root/username. On POSIX nothing is
        // stripped, so "victim." is a distinct literal directory and the avatar stores there normally.
        // Either way there is no cross-user write and no escape.
        var (service, providers, users, log) = Build();
        var user = TestUsers.Named("victim.");

        await service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png");

        if (OperatingSystem.IsWindows())
        {
            await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
            await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
            Assert.Null(user.ProfileImage);
            Assert.Contains(log.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("safe path component"));
        }
        else
        {
            await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("victim.", ".png"));
            Assert.Equal(ProfilePath("victim.", ".png"), user.ProfileImage?.Path);
        }
    }

    [Fact]
    public async Task StoreAsync_LegitimateUsernameWithDotAndAt_StillStoresUnchanged()
    {
        // Behavior preserved for legitimate usernames the host allows (dots and '@' are valid — e.g. an
        // email-style preferred_username): the store path is unchanged and the write happens as before.
        var (service, providers, _, _) = Build();
        var user = TestUsers.Named("first.last@example.com");

        await service.StoreAsync(user, new MemoryStream(new byte[] { 1 }), "image/png", ".png");

        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("first.last@example.com", ".png"));
        Assert.Equal(ProfilePath("first.last@example.com", ".png"), user.ProfileImage?.Path);
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

        await service.TrySetAsync(TestUsers.Named("alice"), AllowedUrl);

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

        await service.TrySetAsync(TestUsers.Named("alice"), AllowedUrl);

        await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task TrySetAsync_AllowedImage_FetchesAndStoresWithDottedExtension()
    {
        // The happy path end to end over the seam: an allowed raster type within the cap is fetched and
        // saved to the resolved profile path — with a real dotted extension since #384.
        using var response = ImageResponse("image/png", new byte[] { 1, 2, 3 });
        var (service, providers, _, _) = Build(response);

        await service.TrySetAsync(TestUsers.Named("alice"), AllowedUrl);

        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("alice", ".png"));
    }

    // Builds a service over a StubHandler the test keeps a handle to, so it can assert the conditional
    // fetch header and the handler reuse count (#248). The logger is returned too, so a test can assert the
    // 304 path took the early return rather than a swallowed error. The on-disk probe (#480) defaults to
    // "present" so the conditional-cadence tests exercise the normal file-present path; the missing-file
    // self-heal tests pass their own predicate returning false.
    private static (AvatarService Service, IProviderManager Providers, IUserManager Users, StubHandler Handler, CapturingLogger Log) BuildWithHandler(HttpResponseMessage response, Func<string, bool>? fileExists = null)
    {
        var users = Substitute.For<IUserManager>();
        var providers = Substitute.For<IProviderManager>();
        var serverConfig = Substitute.For<IServerConfigurationManager>();
        serverConfig.ApplicationPaths.UserConfigurationDirectoryPath.Returns(UserDataRoot);
        var handler = new StubHandler(response);
        var log = new CapturingLogger();
        var service = new AvatarService(users, providers, serverConfig, log, "test-agent/1.0", new HttpClient(handler), fileExists: fileExists ?? (_ => true));
        return (service, providers, users, handler, log);
    }

    [Fact]
    public async Task TrySetAsync_NotModified_KeepsExistingAvatarAndDoesNotReStore()
    {
        // The decided cadence (#248): when the user already has an avatar, the fetch is conditional on
        // If-Modified-Since, and a 304 means the image is unchanged — keep the existing profile image and
        // download/store nothing. 304 must be handled BEFORE EnsureSuccessStatusCode (which throws on it).
        using var response = NotModifiedResponse();
        var (service, providers, users, handler, log) = BuildWithHandler(response);
        var user = TestUsers.Named("alice");
        var previous = new ImageInfo(ProfilePath("alice", ".png")) { LastModified = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc) };
        user.ProfileImage = previous;

        await service.TrySetAsync(user, AllowedUrl);

        // The conditional header was sent, carrying our last-store timestamp.
        Assert.Equal(new DateTimeOffset(previous.LastModified, TimeSpan.Zero), handler.LastIfModifiedSince);
        // Nothing re-downloaded/re-stored; the existing record is untouched.
        Assert.Same(previous, user.ProfileImage);
        await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
        // The 304 was handled by the early return, not by EnsureSuccessStatusCode throwing into the
        // best-effort catch: were the early return removed, 304 would raise, be swallowed, and log an error
        // while leaving the assertions above unchanged. Asserting no error logged is what pins the early return.
        Assert.DoesNotContain(log.Entries, e => e.Level == LogLevel.Error);
    }

    [Fact]
    public async Task TrySetAsync_ExistingImageChanged_SendsConditionalHeaderAndRefreshes()
    {
        // The 200 side of the decided cadence: the origin reports the image changed (a 200, not a 304), so
        // the new bytes are fetched and re-stored over the same path — the conditional header was still sent.
        using var response = ImageResponse("image/png", new byte[] { 9 });
        var (service, providers, _, handler, _) = BuildWithHandler(response);
        var user = TestUsers.Named("alice");
        user.ProfileImage = new ImageInfo(ProfilePath("alice", ".png")) { LastModified = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc) };

        await service.TrySetAsync(user, AllowedUrl);

        Assert.NotNull(handler.LastIfModifiedSince);
        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("alice", ".png"));
    }

    [Fact]
    public async Task TrySetAsync_NoPreviousImage_FetchesUnconditionally()
    {
        // First login for this user: no stored image, so no If-Modified-Since — the fetch is unconditional
        // and the avatar is stored, exactly as before the conditional-fetch change.
        using var response = ImageResponse("image/png", new byte[] { 1, 2, 3 });
        var (service, providers, _, handler, _) = BuildWithHandler(response);

        await service.TrySetAsync(TestUsers.Named("alice"), AllowedUrl);

        Assert.Null(handler.LastIfModifiedSince);
        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("alice", ".png"));
    }

    [Fact]
    public async Task TrySetAsync_ProfileFileMissingOnDisk_FetchesUnconditionallyAndReStores()
    {
        // #480: the ImageInfo record is live but the on-disk profile.* file was deleted out-of-band. Under the
        // conditional-fetch cadence (#248) this login would send If-Modified-Since, get a 304, and skip the
        // re-download — so the avatar could never self-heal from the surviving record. With the local file
        // absent we now fetch UNCONDITIONALLY (no If-Modified-Since) and re-store, restoring the file. This is
        // the self-heal that the always-download behaviour had before #248, back for the missing-file case only.
        using var response = ImageResponse("image/png", new byte[] { 1, 2, 3 });
        var (service, providers, _, handler, _) = BuildWithHandler(response, fileExists: _ => false);
        var user = TestUsers.Named("alice");
        user.ProfileImage = new ImageInfo(ProfilePath("alice", ".png")) { LastModified = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc) };

        await service.TrySetAsync(user, AllowedUrl);

        Assert.Null(handler.LastIfModifiedSince); // the missing file forced a full, unconditional fetch
        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("alice", ".png"));
    }

    [Fact]
    public async Task TrySetAsync_ProfileFileMissingOnDisk_SuppressesConditionalEvenUnderAStubbornNotModified()
    {
        // #480 fail-closed edge: with the local file gone we must NOT advertise our stale last-store timestamp,
        // so If-Modified-Since is withheld even though the record still carries a valid one — the file-existence
        // gate overrides the timestamp-based conditional. A well-behaved origin then re-sends the image (asserted
        // above); a non-compliant origin that answers 304 to an UNCONDITIONAL request refuses us the bytes, so
        // the best-effort path simply keeps the existing record and, critically, never throws into the login.
        // Pins that the header is suppressed and that the 304 short-circuit stays safe when the file is missing.
        using var response = NotModifiedResponse();
        var (service, providers, users, handler, log) = BuildWithHandler(response, fileExists: _ => false);
        var user = TestUsers.Named("alice");
        var previous = new ImageInfo(ProfilePath("alice", ".png")) { LastModified = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc) };
        user.ProfileImage = previous;

        await service.TrySetAsync(user, AllowedUrl);

        Assert.Null(handler.LastIfModifiedSince); // the stale timestamp was deliberately withheld
        Assert.Same(previous, user.ProfileImage); // best-effort: the record is left untouched
        await providers.DidNotReceive().SaveImage(Arg.Any<Stream>(), Arg.Any<string>(), Arg.Any<string>());
        await users.DidNotReceive().ClearProfileImageAsync(Arg.Any<User>());
        Assert.DoesNotContain(log.Entries, e => e.Level == LogLevel.Error); // never throws into login
    }

    [Fact]
    public async Task TrySetAsync_ProfileImageWithoutRealTimestamp_FetchesUnconditionallyEvenWithFilePresent()
    {
        // Fail-closed edge on the re-validation anchor: a live ImageInfo whose LastModified is the sentinel
        // DateTime.MinValue (a record with no real "when we last stored it" time) offers no basis for a 304,
        // so even with the on-disk file present we fetch UNCONDITIONALLY rather than advertise a bogus year-0001
        // If-Modified-Since. Pins the `lastStored > DateTime.MinValue` guard that the #480 hunk carries: a
        // `>`->`>=` slip would send the sentinel as the conditional header, which this asserts against.
        using var response = ImageResponse("image/png", new byte[] { 1, 2, 3 });
        var (service, providers, _, handler, _) = BuildWithHandler(response); // file present (default _ => true)
        var user = TestUsers.Named("alice");
        user.ProfileImage = new ImageInfo(ProfilePath("alice", ".png")) { LastModified = DateTime.MinValue };

        await service.TrySetAsync(user, AllowedUrl);

        Assert.Null(handler.LastIfModifiedSince); // no real anchor -> unconditional despite the file being present
        await providers.Received(1).SaveImage(Arg.Any<Stream>(), "image/png", ProfilePath("alice", ".png"));
    }

    [Fact]
    public void ProductionInstances_ShareOneHttpClient()
    {
        // #248 trim 1, cross-instance: the controller builds a fresh AvatarService per request (see
        // SSOController), so reuse only helps if the client is process-wide. Two services built through the
        // production constructor must reference the very same HttpClient instance — i.e. the static shared
        // one — not a fresh per-instance client (which would reopen a connection pool each login).
        var users = Substitute.For<IUserManager>();
        var providers = Substitute.For<IProviderManager>();
        var serverConfig = Substitute.For<IServerConfigurationManager>();
        serverConfig.ApplicationPaths.UserConfigurationDirectoryPath.Returns(UserDataRoot);

        var first = new AvatarService(users, providers, serverConfig, new CapturingLogger(), "test-agent/1.0");
        var second = new AvatarService(users, providers, serverConfig, new CapturingLogger(), "test-agent/1.0");

        var clientField = typeof(AvatarService).GetField("_httpClient", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(clientField);
        Assert.Same(clientField!.GetValue(first), clientField.GetValue(second));
    }

    [Fact]
    public async Task TrySetAsync_TwoFetches_ReuseTheSameHttpStack()
    {
        // #248 trim 1: TrySetAsync no longer builds its own HttpClient/handler per fetch — it uses the
        // injected (in production: process-wide shared) client. Two fetches through one service are served
        // by the one handler instance, proving the stack is reused rather than rebuilt per login. (The
        // static-field structural guarantee that this reuse spans the controller's per-request AvatarService
        // instances is locked in ArchitectureConformanceTests.)
        using var response = ImageResponse("image/png", new byte[] { 1 });
        var (service, _, _, handler, _) = BuildWithHandler(response);

        await service.TrySetAsync(TestUsers.Named("alice"), AllowedUrl);
        await service.TrySetAsync(TestUsers.Named("bob"), AllowedUrl);

        Assert.Equal(2, handler.Invocations);
    }
}

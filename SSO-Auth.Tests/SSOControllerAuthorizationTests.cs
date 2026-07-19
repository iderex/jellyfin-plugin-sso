using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Proves the elevation guard on the SSO admin surface is genuinely ENFORCED, not merely present. The
/// production <see cref="Jellyfin.Plugin.SSO_Auth.Api.SSOController"/> is hosted in a real in-process Kestrel
/// server (see <see cref="SsoAuthorizationServerFixture"/>); requests travel through the same ASP.NET Core
/// routing + authentication + authorization middleware that runs inside Jellyfin. A non-elevated caller is
/// rejected before the action body executes, on EVERY <c>[Authorize(RequiresElevation)]</c> endpoint,
/// enumerated from the live routing table rather than a hand-maintained list.
///
/// This complements the reflection checks (which assert the attribute is on the method) by exercising the
/// enforcement path end to end: a stray <c>[AllowAnonymous]</c>, a wrong/absent policy name, a controller-level
/// override, or a new unguarded admin endpoint would all fail here where a reflection check on the old set
/// would pass.
/// </summary>
[Collection("SSOController")]
public sealed class SSOControllerAuthorizationTests : IClassFixture<SsoAuthorizationServerFixture>
{
    private static readonly int[] Rejections = { StatusCodes401, StatusCodes403 };

    private const int StatusCodes401 = (int)HttpStatusCode.Unauthorized;
    private const int StatusCodes403 = (int)HttpStatusCode.Forbidden;

    // The admin surface expected to be elevation-gated. The dynamic theories below cover whatever the live
    // table exposes; this fixed set is the completeness anchor — an endpoint silently losing its guard drops
    // out of the discovered set and fails CoversExactlyTheKnownElevationSurface.
    private static readonly string[] ExpectedElevationActions =
    {
        "OidAdd", "OidDel", "OidProviders", "OidTest", "OidStates",
        "SamlAdd", "SamlDel", "SamlProviders", "SamlTest",
        "ExportConfig", "ImportConfig", "Unregister",
        // The SSO-only login admin surface (#165): the mode toggle, the break-glass designation, and status.
        "EnableSsoOnly", "DisableSsoOnly", "DesignateBreakGlassAdmin", "SsoOnlyStatus",
    };

    // The endpoints guarded by a bare [Authorize] (any authenticated caller, no elevation) — the canonical
    // link management surface.
    private static readonly string[] ExpectedAuthenticatedActions =
    {
        "AddCanonicalLink", "DeleteCanonicalLink", "GetSamlLinksByUser", "GetOidLinksByUser",
    };

    private readonly SsoAuthorizationServerFixture _fixture;

    public SSOControllerAuthorizationTests(SsoAuthorizationServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public void CoversExactlyTheKnownElevationSurface()
    {
        // The live routing table's elevation-gated actions must be exactly the known admin surface. A NEW
        // guarded endpoint (uncovered) or a guard REMOVED from a known one both break this, forcing a review.
        var discovered = _fixture.Endpoints.ElevationGated.Select(e => e.Action).Distinct().OrderBy(n => n, StringComparer.Ordinal);
        Assert.Equal(ExpectedElevationActions.OrderBy(n => n, StringComparer.Ordinal), discovered);
    }

    [Fact]
    public void PlainAuthorizeSurfaceIsDistinctFromElevation()
    {
        var discovered = _fixture.Endpoints.AuthenticatedOnly.Select(e => e.Action).Distinct().OrderBy(n => n, StringComparer.Ordinal);
        Assert.Equal(ExpectedAuthenticatedActions.OrderBy(n => n, StringComparer.Ordinal), discovered);
    }

    [Fact]
    public async Task UnauthenticatedCaller_IsRejectedOnEveryElevationEndpoint()
    {
        await AssertAllAsync(
            _fixture.Endpoints.ElevationGated,
            role: null,
            expected: status => status == StatusCodes401,
            because: "an unauthenticated caller must get 401");
    }

    [Fact]
    public async Task AuthenticatedNonAdmin_IsForbiddenOnEveryElevationEndpoint()
    {
        await AssertAllAsync(
            _fixture.Endpoints.ElevationGated,
            role: TestRoles.User,
            expected: status => status == StatusCodes403,
            because: "an authenticated non-administrator must get 403");
    }

    [Fact]
    public async Task Administrator_PassesTheAuthorizationStageOnEveryElevationEndpoint()
    {
        // An administrator clears the guard, so the response is whatever the action body produces — never a
        // 401/403. Proving "not rejected" is the point: the guard admits the elevated caller.
        await AssertAllAsync(
            _fixture.Endpoints.ElevationGated,
            role: TestRoles.Admin,
            expected: status => !Rejections.Contains(status),
            because: "an administrator must pass the elevation guard (no 401/403)");
    }

    [Fact]
    public async Task UnauthenticatedCaller_IsRejectedOnEveryAuthenticatedEndpoint()
    {
        await AssertAllAsync(
            _fixture.Endpoints.AuthenticatedOnly,
            role: null,
            expected: status => status == StatusCodes401,
            because: "a bare [Authorize] endpoint must reject an unauthenticated caller with 401");
    }

    [Fact]
    public async Task AuthenticatedNonAdmin_PassesTheAuthorizationStageOnEveryAuthenticatedEndpoint()
    {
        // The distinction matters: a plain [Authorize] endpoint must NOT be treated as elevation-gated, so a
        // non-admin authenticated caller passes the authorization stage (no 401/403).
        await AssertAllAsync(
            _fixture.Endpoints.AuthenticatedOnly,
            role: TestRoles.User,
            expected: status => !Rejections.Contains(status),
            because: "a bare [Authorize] endpoint must admit any authenticated caller (no 401/403)");
    }

    private async Task AssertAllAsync(
        IReadOnlyList<GatedEndpoint> endpoints,
        string? role,
        Func<int, bool> expected,
        string because)
    {
        Assert.NotEmpty(endpoints);

        var failures = new List<string>();
        foreach (var endpoint in endpoints)
        {
            var status = (int)(await SendAsync(endpoint, role).ConfigureAwait(false)).StatusCode;
            if (!expected(status))
            {
                failures.Add($"{endpoint} -> {status}");
            }
        }

        Assert.True(failures.Count == 0, $"{because}, but these did not: {string.Join("; ", failures)}");
    }

    private async Task<HttpResponseMessage> SendAsync(GatedEndpoint endpoint, string? role)
    {
        using var request = new HttpRequestMessage(new HttpMethod(endpoint.Method), endpoint.Url);
        if (role is not null)
        {
            request.Headers.Add(TestRoles.Header, role);
        }

        // A minimal JSON body for methods that carry one, so a [FromBody] action does not 415 before running.
        // Irrelevant to the assertions (they only care whether the guard produced a 401/403), but it keeps the
        // authorized-path responses to genuine action outcomes.
        if (HttpMethod.Post.Method.Equals(endpoint.Method, StringComparison.OrdinalIgnoreCase)
            || HttpMethod.Put.Method.Equals(endpoint.Method, StringComparison.OrdinalIgnoreCase))
        {
            request.Content = new StringContent("null", Encoding.UTF8, "application/json");
        }

        return await _fixture.Client.SendAsync(request).ConfigureAwait(false);
    }
}

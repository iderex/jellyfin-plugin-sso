using System;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using MediaBrowser.Controller.Net;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Fail-closed matrix for <see cref="RequestHelpers.AssertCanUpdateUser"/>, the admin-or-self guard the
/// canonical-link endpoints run before mutating a user's record. The helper returns
/// <c>(target == caller || caller.IsAdministrator) &amp;&amp; caller.EnableUserPreferenceAccess</c>, so the
/// authorization contract has three independent terms and each row below pins one of them: self is allowed
/// without admin, an administrator may act on another user, a plain caller may not, the preference-access
/// term gates every path (even self, even admin), and a request with no authenticated user faults closed
/// via an explicit deny rather than returning an allow. The deny rows assert <c>false</c>, so loosening the
/// helper to default-allow makes them fail. These tests drive the helper directly through a substituted
/// <see cref="IAuthorizationContext"/>; they touch no process-wide state and so need no test collection.
/// </summary>
public class RequestHelpersTests
{
    private static readonly Guid Caller = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Other = Guid.Parse("22222222-2222-2222-2222-222222222222");

    [Fact]
    public async Task SelfCaller_WithPreferenceAccess_IsAllowed()
    {
        // Self-edit is the base case: a non-admin caller may update their own record.
        var authContext = ContextFor(BuildUser(Caller, isAdmin: false, preferenceAccess: true));

        Assert.True(await RequestHelpers.AssertCanUpdateUser(authContext, Request(), Caller));
    }

    [Fact]
    public async Task Administrator_EditingAnotherUser_IsAllowed()
    {
        // The admin override: editing a record that is not the caller's own is permitted for an administrator.
        var authContext = ContextFor(BuildUser(Caller, isAdmin: true, preferenceAccess: true));

        Assert.True(await RequestHelpers.AssertCanUpdateUser(authContext, Request(), Other));
    }

    [Fact]
    public async Task NonAdministrator_EditingAnotherUser_IsDenied()
    {
        // The core fail-closed gate: a plain caller cannot touch another user's record. If the helper were
        // loosened to default-allow this asserts a denial and so fails.
        var authContext = ContextFor(BuildUser(Caller, isAdmin: false, preferenceAccess: true));

        Assert.False(await RequestHelpers.AssertCanUpdateUser(authContext, Request(), Other));
    }

    [Fact]
    public async Task SelfCaller_WithoutPreferenceAccess_IsDenied()
    {
        // The EnableUserPreferenceAccess term gates even a self-edit: dropping it from the helper would let
        // this pass, so the denial pins the term.
        var authContext = ContextFor(BuildUser(Caller, isAdmin: false, preferenceAccess: false));

        Assert.False(await RequestHelpers.AssertCanUpdateUser(authContext, Request(), Caller));
    }

    [Fact]
    public async Task Administrator_WithoutPreferenceAccess_IsDenied()
    {
        // The preference-access term also overrides the admin path: an administrator without it is refused.
        var authContext = ContextFor(BuildUser(Caller, isAdmin: true, preferenceAccess: false));

        Assert.False(await RequestHelpers.AssertCanUpdateUser(authContext, Request(), Other));
    }

    [Fact]
    public async Task UnauthenticatedContext_FailsClosed()
    {
        // No authenticated user resolved: the explicit null-guard returns a clean deny rather than
        // dereferencing the (null) user and faulting with a NullReferenceException — the ambiguous case
        // never yields true and never surfaces as a 500.
        var authContext = ContextFor(user: null);

        Assert.False(await RequestHelpers.AssertCanUpdateUser(authContext, Request(), Other));
    }

    private static IAuthorizationContext ContextFor(User? user)
    {
        var authContext = Substitute.For<IAuthorizationContext>();
        // AuthorizationInfo.UserId is derived from User.Id, so the seeded user fixes the caller identity the
        // helper compares the target against.
        authContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = user }));
        return authContext;
    }

    private static User BuildUser(Guid id, bool isAdmin, bool preferenceAccess)
    {
        var user = new User("caller", "SSO-Auth", "Default") { Id = id, EnableUserPreferenceAccess = preferenceAccess };
        user.SetPermission(PermissionKind.IsAdministrator, isAdmin);
        return user;
    }

    private static HttpRequest Request() => new DefaultHttpContext().Request;
}

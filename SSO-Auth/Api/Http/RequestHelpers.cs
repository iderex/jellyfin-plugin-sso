// The following code is a derivative work of the code from the Jellyfin project,
// which is licensed GPLv2. This code therefore is also licensed under the terms
// of the GNU Public License, verison 2.
// https://github.com/jellyfin/jellyfin/blob/a60cb280a3d31ba19ffb3a94cf83ef300a7473b7/Jellyfin.Api/Helpers/RequestHelpers.cs#L63-L77

// Use of this relatively small snippet complies with fair use
// See https://www.gnu.org/licenses/gpl-faq.en.html#SourceCodeInDocumentation
// These helpers were not published within a Nuget package, so it was neccessary to re-implement.

using System;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using MediaBrowser.Controller.Net;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>
/// Request Extensions. Internal like the rest of the helper surface — its only member is internal, so
/// nothing public was ever exposed either way (#671).
/// </summary>
internal static class RequestHelpers
{
    /// <summary>
    /// Checks if the user can update an entry.
    /// </summary>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="requestContext">The <see cref="HttpRequest"/>.</param>
    /// <param name="userId">The user id.</param>
    /// <returns>A <see cref="bool"/> whether the user can update the entry.</returns>
    internal static async Task<bool> AssertCanUpdateUser(IAuthorizationContext authContext, HttpRequest requestContext, Guid userId)
    {
        if (authContext is null)
        {
            return false;
        }

        var auth = await authContext.GetAuthorizationInfo(requestContext).ConfigureAwait(false);

        // Fail closed on an unresolved caller: a null authorization result or unauthenticated request
        // is an explicit deny, not a NullReferenceException that would surface as a 500. Every real
        // caller sits behind [Authorize], so this only guards the ambiguous/misconfigured case.
        if (auth?.User is not { } authenticatedUser)
        {
            return false;
        }

        // Updating the record of another user requires an administrator; every caller edits user
        // preferences, so the upstream restrictUserPreferences flag is folded in as always-on here.
        return (userId.Equals(auth.UserId) || authenticatedUser.HasPermission(PermissionKind.IsAdministrator))
            && authenticatedUser.EnableUserPreferenceAccess;
    }
}

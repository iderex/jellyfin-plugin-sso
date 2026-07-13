using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Reads the role values out of an OpenID claim according to the configured role-claim path.
/// The path is the pre-split <c>RoleClaim</c> (see the controller): its first segment names the
/// claim, and any further segments walk into the claim's JSON object to the array that holds the
/// roles. This is pure parsing — it makes no authorization decision; the caller maps the returned
/// role strings to privileges.
/// </summary>
internal static class OidcRoleExtractor
{
    /// <summary>
    /// Extracts the role values from a claim value for the given role-claim path.
    /// </summary>
    /// <param name="roleClaimSegments">
    /// The role-claim path already split on unescaped dots and un-escaped (segment[0] is the claim
    /// name). Must be non-empty; the caller only invokes this for the claim whose type equals segment[0].
    /// </param>
    /// <param name="claimValue">The matched claim's value (a raw role, or a JSON object for a nested path).</param>
    /// <returns>
    /// The extracted roles: the raw claim value as a single role for a one-segment path; otherwise the
    /// string elements of the array reached by walking the JSON path (non-string elements are ignored).
    /// Returns an empty list when the path does not resolve to a JSON array (missing segment, non-object
    /// node, or non-array terminal) and when the claim value is malformed JSON — a multi-segment parse
    /// fails closed to no roles rather than throwing (#216).
    /// </returns>
    internal static List<string> ExtractRoles(string[] roleClaimSegments, string claimValue)
    {
        // A single-segment path is not JSON: the claim value itself is the role.
        if (roleClaimSegments.Length == 1)
        {
            return new List<string> { claimValue };
        }

        // A multi-segment path parses the claim value as a JSON object and walks it. The claim value is
        // attacker-influenced, so it must never throw an unhandled 500 on the public callback (#216): any
        // malformed or non-resolving shape (non-object root, non-object node, non-array terminal) fails
        // closed to an empty role set, and the terminal array is filtered to its string elements — a mixed
        // array keeps its strings, an array with no strings yields none.
        try
        {
            var json = JsonConvert.DeserializeObject<IDictionary<string, object>>(claimValue);
            if (json is null)
            {
                return new List<string>();
            }

            // Walk the intermediate segments; any missing key or non-object node yields no roles.
            for (int i = 1; i < roleClaimSegments.Length - 1; i++)
            {
                var segment = roleClaimSegments[i];
                if (!json.TryGetValue(segment, out var nextToken) || nextToken is not JObject nextObject)
                {
                    return new List<string>();
                }

                json = nextObject.ToObject<IDictionary<string, object>>();
                if (json is null)
                {
                    return new List<string>();
                }
            }

            // The terminal segment must resolve to a JSON array; take only its string elements so a
            // terminal array of objects or numbers cannot throw.
            if (!json.TryGetValue(roleClaimSegments[^1], out var rolesToken) || rolesToken is not JArray rolesArray)
            {
                return new List<string>();
            }

            return rolesArray.Where(token => token.Type == JTokenType.String).Select(token => token.Value<string>()).ToList();
        }
        catch (JsonException)
        {
            return new List<string>();
        }
    }
}

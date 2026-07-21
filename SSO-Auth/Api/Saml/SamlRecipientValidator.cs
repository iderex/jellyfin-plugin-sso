#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Pure endpoint-binding check for a SAML response (#156): the bearer SubjectConfirmationData
/// Recipient — and the Response Destination when present — must match one of this service provider's
/// assertion-consumer URLs. Kept out of the controller so it is unit-testable in isolation; the
/// controller supplies the candidate URLs (host-derived) and does the logging.
/// </summary>
internal static class SamlRecipientValidator
{
    /// <summary>
    /// Returns true if the response is bound to one of the expected assertion-consumer URLs.
    /// </summary>
    /// <param name="recipient">The assertion's Recipient (signed); required.</param>
    /// <param name="destination">The Response Destination; validated only when present.</param>
    /// <param name="expectedAcsUrls">This service provider's acceptable assertion-consumer URLs.</param>
    /// <returns>
    /// True when the Recipient is present and matches an expected URL, and the Destination (if any)
    /// also matches. False otherwise — a missing Recipient fails closed.
    /// </returns>
    internal static bool IsBound(string? recipient, string? destination, IReadOnlyCollection<string> expectedAcsUrls)
    {
        recipient = recipient?.Trim();
        if (string.IsNullOrEmpty(recipient) || !expectedAcsUrls.Contains(recipient, StringComparer.Ordinal))
        {
            return false;
        }

        // Destination is Response-level, so it is only signature-covered when the whole Response is
        // signed; enforce it only when the response carries one (defense in depth on top of Recipient).
        destination = destination?.Trim();
        return string.IsNullOrEmpty(destination) || expectedAcsUrls.Contains(destination, StringComparer.Ordinal);
    }
}

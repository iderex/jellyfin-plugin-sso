using System;
using System.Globalization;

namespace Jellyfin.Plugin.SSO_Auth;

/// <summary>
/// Pure, fail-closed validation of a SAML assertion's time bounds.
/// </summary>
internal static class SamlAssertionTime
{
    /// <summary>
    /// The clock-skew tolerance applied to both bounds, so a small clock difference between the
    /// identity provider and this server does not reject an otherwise-valid assertion. Five minutes
    /// matches the common IdP default (e.g. ADFS).
    /// </summary>
    internal static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Determines whether an assertion is currently within its validity window. Fail-closed:
    /// at least one upper bound (NotOnOrAfter) MUST be present and parseable, or the assertion is
    /// rejected; a bound that is present but unparseable is likewise a rejection. Bounds are
    /// evaluated in UTC with <see cref="ClockSkew"/> tolerance.
    /// </summary>
    /// <param name="subjectNotOnOrAfter">SubjectConfirmationData/@NotOnOrAfter, or null if absent.</param>
    /// <param name="conditionsNotBefore">Conditions/@NotBefore, or null if absent.</param>
    /// <param name="conditionsNotOnOrAfter">Conditions/@NotOnOrAfter, or null if absent.</param>
    /// <param name="nowUtc">The current time, in UTC.</param>
    /// <param name="skew">The clock-skew tolerance applied to each bound.</param>
    /// <returns>True only when a valid upper bound exists and every present bound is satisfied.</returns>
    internal static bool IsWithinValidity(
        string subjectNotOnOrAfter,
        string conditionsNotBefore,
        string conditionsNotOnOrAfter,
        DateTime nowUtc,
        TimeSpan skew)
    {
        // Apply the skew to "now" rather than to the parsed bounds: nowUtc is always a present-day
        // value, so nowUtc +/- skew cannot overflow, whereas a pathological IdP-supplied bound near
        // DateTime.MaxValue/MinValue would throw if skew were added to it.
        var lowerReference = nowUtc + skew; // must be >= NotBefore
        var upperReference = nowUtc - skew; // must be < NotOnOrAfter
        var haveUpperBound = false;

        foreach (var raw in new[] { subjectNotOnOrAfter, conditionsNotOnOrAfter })
        {
            if (raw == null)
            {
                continue;
            }

            if (!TryParseUtc(raw, out var notOnOrAfter))
            {
                return false; // present but unparseable -> fail closed
            }

            haveUpperBound = true;
            if (upperReference >= notOnOrAfter) // NotOnOrAfter is an exclusive upper bound
            {
                return false;
            }
        }

        if (!haveUpperBound)
        {
            return false; // no time bound at all -> never accept
        }

        if (conditionsNotBefore != null)
        {
            if (!TryParseUtc(conditionsNotBefore, out var notBefore))
            {
                return false;
            }

            if (lowerReference < notBefore)
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryParseUtc(string raw, out DateTime utc)
    {
        // SAML timestamps are xsd:dateTime in UTC ('...Z'). Parse culture-invariantly and normalize
        // to UTC, assuming UTC when no offset is present rather than the machine's local zone.
        return DateTime.TryParse(
            raw,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
            out utc);
    }
}

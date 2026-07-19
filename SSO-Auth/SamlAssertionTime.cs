#nullable enable
using System;
using System.Xml;

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
        string? subjectNotOnOrAfter,
        string? conditionsNotBefore,
        string? conditionsNotOnOrAfter,
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

    internal static bool TryParseUtc(string? raw, out DateTime utc)
    {
        utc = default;
        if (raw == null)
        {
            return false;
        }

        // SAML NotBefore/NotOnOrAfter are xsd:dateTime. Parse them with XmlConvert.ToDateTime, which
        // implements the xsd:dateTime grammar faithfully — unlike DateTime.TryParse, which accepts non-xsd
        // shapes and REJECTS some valid ones, notably fractional seconds beyond the 7 digits it caps at that
        // xsd permits and some IdPs emit (#677). XmlDateTimeSerializationMode.Utc normalizes any offset (or an
        // offset-less value) to UTC. XmlConvert.ToDateTime THROWS on malformed input, so wrap it and fail
        // CLOSED (return false) on any parse failure — this method's non-throwing bool contract is unchanged.
        try
        {
            utc = XmlConvert.ToDateTime(raw, XmlDateTimeSerializationMode.Utc);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            return false;
        }

        // Utc mode yields a Kind=Utc DateTime; assert it so a bound is never compared against nowUtc in a
        // mismatched kind, and so a future refactor of the mode cannot silently reintroduce local-time drift.
        return utc.Kind == DateTimeKind.Utc;
    }
}

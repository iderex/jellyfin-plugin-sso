// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Orchestrates the inbound IdP-initiated SAML <c>LogoutRequest</c> validation (#727, SLO-3b): parse plus
/// signature/time validation (<see cref="SamlLogoutRequest"/>) followed by the one-time-use (replay)
/// consume of the request <c>ID</c>. It is the SAML-logout analogue of
/// <see cref="SamlAssertionValidator"/> — it owns the process-wide replay cache as a <c>static readonly</c>
/// field, so the controller endpoint that calls it holds no mutable static state, and reuses the SHARED
/// <see cref="SamlReplayCache"/> primitive rather than a copy.
/// </summary>
/// <remarks>
/// On success the caller receives the validated NameID and SessionIndex list; on failure it receives a
/// FIXED reason code (never request-derived text) for the audit trail. The reason is server-side only — the
/// endpoint renders every failure as one uniform 400, so the caller cannot tell the causes apart.
/// </remarks>
internal sealed class SamlLogoutValidator
{
    // One-time-use tracking for consumed LogoutRequest IDs (replay protection), process-wide exactly like the
    // login-path SamlAssertionValidator.SamlReplays — a captured LogoutRequest must not revoke twice.
    private static readonly SamlReplayCache LogoutReplays = new SamlReplayCache();

    /// <summary>
    /// Test-only. Clears the process-wide one-time replay cache between tests so a consumed request ID does
    /// not leak into a sibling test (mirrors <see cref="SamlAssertionValidator.ResetReplaysForTests"/>).
    /// </summary>
    internal static void ResetReplaysForTests() => LogoutReplays.Clear();

    /// <summary>
    /// Parses and fully validates an inbound <c>LogoutRequest</c> for a provider: signature (against the
    /// provider's configured primary/secondary certificate), the optional <c>NotOnOrAfter</c> time bound,
    /// and one-time use of the request ID. Fail-closed: any failure returns <see langword="false"/> with a
    /// fixed <paramref name="reasonCode"/> and no resolved subject.
    /// </summary>
    /// <param name="config">The SAML provider configuration (signing certificate(s)).</param>
    /// <param name="provider">The provider the request arrived for (scopes the replay key so two IdPs cannot block each other).</param>
    /// <param name="rawRequest">The untrusted, Base64-encoded <c>SAMLRequest</c>.</param>
    /// <param name="nowUtc">The current UTC time (supplied for determinism).</param>
    /// <param name="nameId">On success, the subject NameID the request names.</param>
    /// <param name="sessionIndexes">On success, the SessionIndex values the request carries (possibly empty).</param>
    /// <param name="requestId">On success, the request's <c>ID</c> — the value the SP echoes as the <c>InResponseTo</c> of the signed <c>LogoutResponse</c> (#727, SLO-3c). Empty on failure.</param>
    /// <param name="reasonCode">On failure, a fixed audit reason code; empty on success.</param>
    /// <returns><see langword="true"/> when the request is fully valid; otherwise <see langword="false"/>.</returns>
    internal bool TryValidate(
        SamlConfig config,
        string provider,
        string? rawRequest,
        DateTime nowUtc,
        out string nameId,
        out IReadOnlyList<string> sessionIndexes,
        out string requestId,
        out string reasonCode)
    {
        ArgumentNullException.ThrowIfNull(config);
        nameId = string.Empty;
        sessionIndexes = Array.Empty<string>();
        requestId = string.Empty;

        if (!SamlLogoutRequest.TryParse(config.SamlCertificate ?? string.Empty, config.SamlSecondaryCertificate, rawRequest, out var logoutRequest))
        {
            reasonCode = RejectReason.Malformed;
            return false;
        }

        // The parsed request owns an unmanaged certificate handle; dispose it on every path.
        using var owned = logoutRequest;

        // Signature + time-bound validation. An unsigned, wrong-key, wrapped, weak-algorithm or expired
        // request fails here, before any subject is exposed or any replay slot is consumed.
        if (!logoutRequest.IsValid())
        {
            reasonCode = RejectReason.Invalid;
            return false;
        }

        // A validated request with no usable NameID resolves no subject — reject rather than fall through to a
        // blank-subject lookup (SessionLogoutStore.FindByProviderSubject also refuses a blank subject, but the
        // guard here keeps the contract explicit and fail-closed).
        var resolvedNameId = logoutRequest.GetNameId();
        if (string.IsNullOrEmpty(resolvedNameId))
        {
            reasonCode = RejectReason.Invalid;
            return false;
        }

        // One-time use: consume the request ID so a captured LogoutRequest cannot be replayed to revoke again.
        // Retained for the request's own NotOnOrAfter window (or the one-hour floor when it carries none), the
        // same retention policy the login replay path uses. A missing ID fails closed inside TryConsume.
        //
        // DELIBERATE ORDERING — consume at validation time, BEFORE the endpoint's revoke, not only on a
        // successful revoke (#727). A signed LogoutRequest is single-use by design regardless of downstream
        // outcome, mirroring the login-side SamlAssertionValidator consume. Two reasons this is the more
        // correct SLO semantic than a consume-on-success: (1) TryConsume is the ATOMIC claim that serialises
        // concurrent copies of the same request — without it two in-flight copies could both resolve and
        // revoke and race on removing store entries; (2) revocation is idempotent and a real IdP mints a FRESH
        // request ID per retry, so burning the ID on a transient revoke fault blocks no genuine retry — the
        // endpoint additionally leaves the matched entries in the store on a revoke fault, so a fresh-ID retry
        // still finds and acts on them. Replay protection here is a hygiene/DoS bound, not a session-minting
        // gate, so single-use-regardless is the safe default.
        var retention = SamlReplayCache.ComputeRetention(nowUtc, logoutRequest.GetNotOnOrAfter());
        var resolvedRequestId = logoutRequest.GetRequestId();
        var replayKey = ProviderScopedKey.For(provider, resolvedRequestId);
        if (!LogoutReplays.TryConsume(replayKey, retention, nowUtc, out _))
        {
            reasonCode = RejectReason.Replay;
            return false;
        }

        nameId = resolvedNameId;
        sessionIndexes = logoutRequest.GetSessionIndexes();
        // TryConsume succeeded above, and ProviderScopedKey.For fails closed on a null/blank id, so a true
        // return here guarantees a usable request ID to echo as the LogoutResponse InResponseTo.
        requestId = resolvedRequestId ?? string.Empty;
        reasonCode = string.Empty;
        return true;
    }

    /// <summary>The fixed audit reason codes for a rejected logout request; never request-derived text.</summary>
    internal static class RejectReason
    {
        /// <summary>The body did not parse (non-base64, malformed XML, prohibited DOCTYPE, or an unloadable configured certificate).</summary>
        internal const string Malformed = "malformed";

        /// <summary>The signature or time-bound validation failed (unsigned, wrong key, wrapped, weak algorithm, expired).</summary>
        internal const string Invalid = "signature_or_time_invalid";

        /// <summary>The request ID was already consumed (a replay) or absent.</summary>
        internal const string Replay = "replay";
    }
}

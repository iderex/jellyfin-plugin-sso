// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Validates an inbound OpenID Connect back-channel <c>logout_token</c> (OIDC Back-Channel Logout 1.0
/// §2.4–§2.6, #962). The endpoint that calls this is ANONYMOUS — the token's signature is the only
/// authenticator — so every §2.6 rule is fail-closed and each maps to a fixed reason code (never
/// request-derived text, so a rejection leaves an audit trail without a subject-identifier oracle,
/// mirroring the SAML inbound-logout validator). Signature/JWKS/algorithm verification goes through the
/// SAME <see cref="OidcSignatureKeys"/> basis the id_token validator uses — there is no second, laxer
/// verification path. On success it yields the (sub, sid) pair the revocation lookup keys on; the
/// validator itself revokes nothing.
/// </summary>
internal sealed class OidcLogoutTokenValidator
{
    // The logout event the events claim MUST contain (§2.4). A member-presence check, not equality on the
    // whole claim — the claim is a JSON object whose keys are event URIs.
    private const string BackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    // Distinct from the login-path id_token replay set and the SAML logout set: a consumed logout_token jti
    // must not be redeemable twice (§2.6 rule the spec RECOMMENDS; here it is enforced as one-time-use so a
    // captured valid token cannot churn revocations). Process-wide, bounded, fail-closed at capacity.
    private static readonly ReplayCache LogoutTokenReplays = new ReplayCache();

    /// <summary>Clears the replay set so a jti consumed in one test does not leak into a sibling.</summary>
    internal static void ResetReplaysForTests() => LogoutTokenReplays.Clear();

    /// <summary>
    /// Parses and fully validates a <c>logout_token</c> for a provider.
    /// </summary>
    /// <param name="logoutToken">The raw compact-serialized logout_token.</param>
    /// <param name="validationParameters">The signature/issuer/audience/lifetime parameters — the SAME basis the id_token uses.</param>
    /// <param name="clockSkew">The validation clock skew (used for the jti-retention window; matches the parameters' ClockSkew).</param>
    /// <param name="nowUtc">The current time (injected for determinism).</param>
    /// <returns>The validation outcome.</returns>
    internal async Task<Result> ValidateAsync(
        string? logoutToken,
        TokenValidationParameters validationParameters,
        TimeSpan clockSkew,
        DateTime nowUtc)
    {
        if (string.IsNullOrEmpty(logoutToken))
        {
            return new Result(false, null, null, RejectReason.Malformed);
        }

        // Signature / issuer / audience / lifetime — the SAME hardened basis as the id_token (the caller
        // builds validationParameters via OidcSignatureKeys); any failure is fail-closed.
        var handler = new JsonWebTokenHandler { MapInboundClaims = false };
        var result = await handler.ValidateTokenAsync(logoutToken, validationParameters).ConfigureAwait(false);
        if (!result.IsValid)
        {
            return new Result(false, null, null, RejectReason.Invalid);
        }

        var token = (JsonWebToken)result.SecurityToken;

        // azp / additional-audience restriction (OIDC Core 3.1.3.7 rules 3-5), the SAME check the id_token
        // validator applies — §2.4 says the logout_token aud follows OpenID.Core, so the two token types
        // must not drift on it: when azp is present it MUST equal this client's id, and a multi-audience
        // token MUST carry azp (a token minted for a different party that merely co-lists this client is
        // refused). ValidateAudience already confirmed this client is AMONG the audiences.
        var azp = result.ClaimsIdentity.FindFirst("azp")?.Value;
        if (azp != null && !string.Equals(azp, validationParameters.ValidAudience, StringComparison.Ordinal))
        {
            return new Result(false, null, null, RejectReason.Invalid);
        }

        if (azp == null && token.Audiences.Count() > 1)
        {
            return new Result(false, null, null, RejectReason.Invalid);
        }

        // §2.4: a logout_token MUST NOT contain a nonce. Rejecting it here is what refuses an id_token
        // (which carries nonce) replayed at the back-channel endpoint.
        if (token.TryGetPayloadValue<string>("nonce", out var nonce) && !string.IsNullOrEmpty(nonce))
        {
            return new Result(false, null, null, RejectReason.ProhibitedNonce);
        }

        // §2.4/§2.6: the events claim MUST be a JSON object containing the back-channel-logout member.
        if (!HasBackChannelLogoutEvent(token))
        {
            return new Result(false, null, null, RejectReason.NotALogoutToken);
        }

        var sub = token.TryGetPayloadValue<string>("sub", out var s) && !string.IsNullOrEmpty(s) ? s : null;
        var sid = token.TryGetPayloadValue<string>("sid", out var i) && !string.IsNullOrEmpty(i) ? i : null;

        // §2.4: at least one of sub / sid MUST be present.
        if (sub is null && sid is null)
        {
            return new Result(false, null, null, RejectReason.NoSubjectOrSid);
        }

        // One-time-use on jti so a captured valid token cannot be replayed to churn revocations. A token
        // without a jti is treated as non-replayable-once (fail-closed): give it a synthetic key derived
        // from its signature so an identical token still collides, while distinct tokens do not.
        var jti = token.TryGetPayloadValue<string>("jti", out var j) && !string.IsNullOrEmpty(j)
            ? j
            : token.EncodedSignature;
        var retention = ReplayCache.ComputeRetention(nowUtc, token.ValidTo == DateTime.MinValue ? null : token.ValidTo, clockSkew);
        if (!LogoutTokenReplays.TryConsume(jti, retention, nowUtc, out _))
        {
            return new Result(false, null, null, RejectReason.Replay);
        }

        return new Result(true, sub, sid, string.Empty);
    }

    // The events claim is a JSON object; presence of the back-channel-logout member is what makes this a
    // logout_token. Read it as a JsonElement and require the member — a claim that is absent, not an object,
    // or an object without the member is rejected. Any parse failure is a fail-closed "not a logout_token".
    private static bool HasBackChannelLogoutEvent(JsonWebToken token)
    {
        if (!token.TryGetPayloadValue<JsonElement>("events", out var events))
        {
            return false;
        }

        return events.ValueKind == JsonValueKind.Object
            && events.TryGetProperty(BackChannelLogoutEvent, out _);
    }

    /// <summary>
    /// The outcome of validating a <c>logout_token</c>: on success the (sub, sid) pair the caller keys its
    /// <c>FindByProviderSubject</c> lookup on (either may be null, but never both — §2.4); on failure a
    /// fixed <see cref="RejectReason"/> code.
    /// </summary>
    /// <param name="IsValid">Whether the token is a valid logout_token.</param>
    /// <param name="Subject">The token's <c>sub</c> claim on success, else null.</param>
    /// <param name="SessionIndex">The token's <c>sid</c> claim on success, else null.</param>
    /// <param name="ReasonCode">A fixed rejection reason code on failure, else empty.</param>
    internal readonly record struct Result(bool IsValid, string? Subject, string? SessionIndex, string ReasonCode);

    /// <summary>The fixed rejection reason codes — request-independent, safe to audit and never a subject oracle.</summary>
    internal static class RejectReason
    {
        /// <summary>The token was absent, unparseable, or not a JWT.</summary>
        internal const string Malformed = "malformed";

        /// <summary>Signature, issuer, audience, algorithm, or lifetime validation failed (unsigned, wrong key, weak alg, expired).</summary>
        internal const string Invalid = "signature_or_time_invalid";

        /// <summary>The events claim is absent or does not contain the back-channel-logout event — this is not a logout_token.</summary>
        internal const string NotALogoutToken = "not_a_logout_token";

        /// <summary>The token carries a nonce, which §2.4 forbids (an id_token replayed as a logout_token).</summary>
        internal const string ProhibitedNonce = "prohibited_nonce";

        /// <summary>Neither sub nor sid is present — nothing to match a session on.</summary>
        internal const string NoSubjectOrSid = "no_subject_or_sid";

        /// <summary>The jti was already consumed — a replayed logout_token.</summary>
        internal const string Replay = "replay";
    }
}

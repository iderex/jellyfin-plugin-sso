using System;
using System.Net;
using Jellyfin.Plugin.SSO_Auth.Api;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Shared;

/// <summary>
/// The shared per-client rate-limit gate over the SSO flow endpoints (#128, #160): the anonymous login
/// endpoints, the authenticated link/unlink admin write surface (#382) and the admin SSO-revoke (#516). It owns the ONE
/// process-wide <see cref="SsoRateLimiter"/> instance and the opt-in check every rate-limited endpoint
/// fronts itself with — the last mutable process-wide static that lived on <see cref="SSOController"/> (#318).
/// Relocating it into the shared tier leaves the controller a stateless request dispatcher (every store,
/// cache and limiter now lives in a flow service or here) while keeping the gate byte-for-byte identical: the
/// same fire points, the same fail-open classifier, and the same <see cref="LoginOutcome.Throttled"/> 429
/// rendered by the single mapper (#474). Pure static home — one shared instance, no per-request allocation,
/// and no <c>ControllerBase</c> coupling, so both login flows and the admin link endpoints call the one gate
/// rather than a controller-owned static, each under its own endpoint-class budget.
/// </summary>
internal static class SsoRateLimitGate
{
    // The opt-in per-client rate limiter over the SSO flow endpoints (#128). One process-wide instance
    // (static readonly), exactly as it was on the controller: every rate-limited endpoint reaches it through
    // this gate, so a single shared window per client is preserved across the OpenID and SAML login endpoints
    // (and now the link/unlink admin surface, #382, and the admin SSO-revoke, #516, each under its own class)
    // rather than split into separate limiters.
    private static readonly SsoRateLimiter RateLimiter = new SsoRateLimiter();

    /// <summary>
    /// Applies the opt-in per-client rate limit (#128) to one rate-limited endpoint: returns null when the
    /// request may proceed, else the throttled outcome rendered by the single mapper (#474). Reads the
    /// settings under the config lock; an unattributable or non-public client is never throttled (fail open,
    /// availability over throttling). Keys on the connection's remote address only — proxy attribution is the
    /// host's job (Jellyfin's "Known proxies" setting resolves the real client into it); see
    /// <see cref="SsoRateLimiter.NormalizeClientKey"/>. The endpoint class (challenge/callback/auth for the
    /// anonymous login flows, "link" for the authenticated link/unlink write surface, #382, and "unregister"
    /// for the admin SSO-revoke write, #516) is part of the key, so each class carries an independent budget:
    /// one login — which hits all three login classes — gets the full budget at each stage rather than a third
    /// of it, keeping the default generous for shared egress addresses (NAT/CGNAT).
    /// </summary>
    /// <param name="endpointClass">The endpoint class folded into the rate-limit key (e.g. challenge/callback/auth/link/unregister).</param>
    /// <param name="remoteIp">The connection's remote address, the sole attribution input (proxy resolution is the host's job).</param>
    /// <param name="logger">The caller's logger, for the bounded throttle-engaged observability signal (#195).</param>
    /// <param name="response">The response whose Retry-After header a throttled outcome sets (#474).</param>
    /// <returns>Null when the request may proceed, or the throttled 429 outcome otherwise.</returns>
    internal static ActionResult Check(string endpointClass, IPAddress remoteIp, ILogger logger, HttpResponse response)
    {
        var (enabled, maxAttempts, windowSeconds) = SSOPlugin.Instance.ReadConfiguration(
            c => (c.EnableRateLimit, c.RateLimitMaxAttempts, c.RateLimitWindowSeconds));
        if (!enabled || windowSeconds < 1)
        {
            // maxAttempts < 1 is handled inside IsAllowed (it disables the limiter there).
            return null;
        }

        var key = SsoRateLimiter.NormalizeClientKey(remoteIp);
        if (key != null)
        {
            key = endpointClass + ":" + key;
        }

        var now = DateTime.UtcNow;
        if (RateLimiter.IsAllowed(key, maxAttempts, TimeSpan.FromSeconds(windowSeconds), now, out var retryAfterSeconds))
        {
            return null;
        }

        // Bounded observability signal (#195): so an operator can notice a sustained brute-force or a
        // reverse proxy misconfigured to pool every client into one bucket, without the notice itself
        // becoming a log/CPU amplifier. The limiter emits at most one line per interval, carrying only
        // an aggregate count (no client key — nothing to sanitize or forge); a returned 0 stays silent.
        var throttledCount = RateLimiter.RecordThrottledHit(now);
        if (throttledCount > 0)
        {
            logger.LogWarning("SSO rate limit engaged: {Count} request(s) throttled since the last notice; further notices are suppressed for at least a minute.", throttledCount);
        }

        // The rejection is expressed as a LoginOutcome and rendered by the single mapper (#474): the status,
        // plain-text body and the retry-delay header all originate there, so the gate no longer emits a bare
        // rate-limit ContentResult or sets the delay header itself.
        return LoginStatusMapper.ToActionResult(new LoginOutcome.Throttled(retryAfterSeconds), response);
    }
}

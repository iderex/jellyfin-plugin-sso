#nullable enable

using System;
using System.Globalization;
using System.Net.Mime;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.SSO_Auth.Api.Session;

/// <summary>
/// The single translation from a <see cref="LoginOutcome"/> to an HTTP response. Rejection bodies
/// are plain text and deliberately uniform per category, so a response does not reveal why it was
/// rejected beyond what the category already states publicly — the server log disambiguates. This is
/// also the one place the rate-limit 429 and its Retry-After header are emitted (#474): a Throttled
/// outcome carries the delay and is rendered through the response-aware overload, which owns the header.
/// </summary>
internal static class LoginStatusMapper
{
    /// <summary>
    /// The uniform denial body for any rejected login. Actionable without enumerating (#668): it tells the
    /// user their account is not permitted through this provider — the most common trigger is the role
    /// allow-list not matching — without revealing which accounts or roles are allowed. The server log
    /// disambiguates the exact reason.
    /// </summary>
    internal const string PermissionDeniedMessage = "Login denied. Your account is not permitted to sign in through this provider.";

    /// <summary>
    /// The body for an unresolved provider — one wording for both the unknown and the disabled case,
    /// so the two cannot be told apart (no provider-enumeration oracle). Shared with the controller's
    /// remaining direct provider-lookup rejections so the wording is defined once.
    /// </summary>
    internal const string NoMatchingProviderMessage = "No matching provider found";

    /// <summary>
    /// The rate-limit 429 body (#128, #474) — deliberately human-readable rather than a bare status, since
    /// the challenge/callback endpoints are navigated directly in the browser and a blank 429 would look
    /// like a broken login (the XHR auth page reads the status, not this body). Worded generically rather
    /// than "login attempts" because the same gate, and so the same body, also fronts the authenticated
    /// admin link/unlink (#382) and unregister (#516) write surfaces, where nobody is logging in (#517).
    /// The Retry-After header carries the machine-readable delay.
    /// </summary>
    internal const string RateLimitedMessage = "Too many attempts. Please wait a moment and try again.";

    internal static ActionResult ToActionResult(LoginOutcome outcome) => outcome switch
    {
        LoginOutcome.Success success => new OkObjectResult(success.Session),
        LoginOutcome.Denied => Emit(StatusCodes.Status401Unauthorized, PermissionDeniedMessage),
        LoginOutcome.Rejected rejected => ToActionResult(rejected.Reason),
        // Throttled carries a Retry-After header this pure overload cannot set; it must be rendered through
        // ToActionResult(outcome, response). Reaching here is a wiring fault, so it throws (500) rather than
        // silently emitting a 429 without the header — fail closed, never a default-accept.
        LoginOutcome.Throttled => throw new InvalidOperationException("Throttled must be mapped through the response-aware overload so Retry-After is set."),
        // Unreachable while the sum stays closed, but the compiler cannot prove it; an impossible
        // case is a genuine server fault, so it throws (500) — never a default-accept.
        _ => throw new InvalidOperationException($"Unhandled login outcome: {outcome.GetType().Name}"),
    };

    /// <summary>
    /// Renders an outcome that may need the response. The only such case is <see cref="LoginOutcome.Throttled"/>,
    /// whose 429 carries a Retry-After header — this is the single place that header is set. Every other outcome
    /// defers to the pure overload unchanged, so a caller can route all outcomes through this one.
    /// </summary>
    /// <param name="outcome">The login outcome to translate.</param>
    /// <param name="response">The response whose Retry-After header a Throttled outcome sets.</param>
    /// <returns>The HTTP action result.</returns>
    internal static ActionResult ToActionResult(LoginOutcome outcome, HttpResponse response) => outcome switch
    {
        LoginOutcome.Throttled throttled => Throttle(throttled.RetryAfterSeconds, response),
        _ => ToActionResult(outcome),
    };

    private static ContentResult ToActionResult(PublicReason reason) => reason switch
    {
        PublicReason.UnknownProvider => Emit(StatusCodes.Status400BadRequest, NoMatchingProviderMessage),
        PublicReason.InvalidState => Emit(StatusCodes.Status400BadRequest, "Invalid or expired state"),
        PublicReason.AccountLinkForbidden => Emit(StatusCodes.Status403Forbidden, "SSO login is not permitted for this account."),
        PublicReason.SsoResponseInvalid => Emit(StatusCodes.Status400BadRequest, "SSO response validation failed"),
        PublicReason.SamlResponseInvalid => Emit(StatusCodes.Status400BadRequest, "SAML response validation failed"),
        PublicReason.PkceNotSupported => Emit(StatusCodes.Status400BadRequest, "The identity provider does not advertise the required PKCE (S256) support."),
        PublicReason.EmailNotVerified => Emit(StatusCodes.Status403Forbidden, "A verified email is required to log in."),
        PublicReason.AwaitingApproval => Emit(StatusCodes.Status403Forbidden, "Your account is not active. It is awaiting administrator approval."),
        // A new PublicReason member without a mapper entry fails loudly here, and the totality test
        // enumerating every member catches it before it can ship — never a fall-through.
        _ => throw new InvalidOperationException($"Unmapped public reason: {reason}"),
    };

    // The rate-limit 429, byte-identical to the pre-#474 direct emission at the controller: the same
    // plain-text body via Emit plus the machine-readable Retry-After. This is the ONLY place Retry-After
    // is set, so the single-error-emission-point invariant now covers the last login-path error too.
    private static ContentResult Throttle(int retryAfterSeconds, HttpResponse response)
    {
        response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);
        return Emit(StatusCodes.Status429TooManyRequests, RateLimitedMessage);
    }

    // Reproduces the controller's ReturnError shape exactly (ContentResult, text/plain), so every
    // converted call site is byte-identical on the wire.
    private static ContentResult Emit(int statusCode, string message) => new ContentResult
    {
        Content = message,
        ContentType = MediaTypeNames.Text.Plain,
        StatusCode = statusCode,
    };
}

using System;
using System.Net.Mime;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The single translation from a <see cref="LoginOutcome"/> to an HTTP response. Rejection bodies
/// are plain text and deliberately uniform per category, so a response does not reveal why it was
/// rejected beyond what the category already states publicly — the server log disambiguates. The
/// rate-limit 429 stays with the rate limiter until the filter step (Retry-After needs the response).
/// </summary>
internal static class LoginStatusMapper
{
    /// <summary>The uniform denial body for any rejected login — deliberately uninformative.</summary>
    internal const string PermissionDeniedMessage = "Error. Check permissions.";

    /// <summary>
    /// The body for an unresolved provider — one wording for both the unknown and the disabled case,
    /// so the two cannot be told apart (no provider-enumeration oracle). Shared with the controller's
    /// remaining direct provider-lookup rejections so the wording is defined once.
    /// </summary>
    internal const string NoMatchingProviderMessage = "No matching provider found";

    internal static ActionResult ToActionResult(LoginOutcome outcome) => outcome switch
    {
        LoginOutcome.Success success => new OkObjectResult(success.Session),
        LoginOutcome.Denied => Emit(StatusCodes.Status401Unauthorized, PermissionDeniedMessage),
        LoginOutcome.Rejected rejected => ToActionResult(rejected.Reason),
        // Unreachable while the sum stays closed, but the compiler cannot prove it; an impossible
        // case is a genuine server fault, so it throws (500) — never a default-accept.
        _ => throw new InvalidOperationException($"Unhandled login outcome: {outcome.GetType().Name}"),
    };

    private static ContentResult ToActionResult(PublicReason reason) => reason switch
    {
        PublicReason.UnknownProvider => Emit(StatusCodes.Status400BadRequest, NoMatchingProviderMessage),
        PublicReason.InvalidState => Emit(StatusCodes.Status400BadRequest, "Invalid or expired state"),
        PublicReason.AccountLinkForbidden => Emit(StatusCodes.Status403Forbidden, "SSO login is not permitted for this account."),
        PublicReason.SsoResponseInvalid => Emit(StatusCodes.Status400BadRequest, "SSO response validation failed"),
        PublicReason.SamlResponseInvalid => Emit(StatusCodes.Status400BadRequest, "SAML response validation failed"),
        PublicReason.PkceNotSupported => Emit(StatusCodes.Status400BadRequest, "The identity provider does not advertise the required PKCE (S256) support."),
        PublicReason.PkceUnverifiable => Emit(StatusCodes.Status400BadRequest, "The identity provider's PKCE (S256) support could not be verified."),
        // A new PublicReason member without a mapper entry fails loudly here, and the totality test
        // enumerating every member catches it before it can ship — never a fall-through.
        _ => throw new InvalidOperationException($"Unmapped public reason: {reason}"),
    };

    // Reproduces the controller's ReturnError shape exactly (ContentResult, text/plain), so every
    // converted call site is byte-identical on the wire.
    private static ContentResult Emit(int statusCode, string message) => new ContentResult
    {
        Content = message,
        ContentType = MediaTypeNames.Text.Plain,
        StatusCode = statusCode,
    };
}

// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Api;
using MediaBrowser.Common.Extensions;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>
/// The sso api controller.
/// </summary>
[ApiController]
[Route("[controller]")]
public class SSOController : ControllerBase
{
    // The uniform-rejection policy and its bodies live on LoginStatusMapper; the direct provider-lookup
    // rejections that stay in the controller reuse its NoMatchingProviderMessage so the wording is
    // defined once (#318).
    private const string NoMatchingProviderMessage = LoginStatusMapper.NoMatchingProviderMessage;

    // Display names for the audit log (the internal link-map mode tokens are the lowercase "oid"/"saml").
    private const string OpenIdProtocol = "OpenID";
    private const string SamlProtocol = "SAML";

    // Hard cap on the config-import request body (#161): a whole plugin configuration is small (kilobytes),
    // so 1 MiB is generous headroom while an oversized document is rejected fail-closed (413) before it is
    // parsed, rather than being deserialized into memory.
    private const long ConfigImportMaxBytes = 1024 * 1024;

    private readonly IUserManager _userManager;
    // The shared login-completion tail (#160, #318): resolve/adopt the link, build the session parameters,
    // mint under the revocation gate, audit, map to a LoginOutcome. The controller passes the
    // HttpContext-derived remote endpoint in and keeps no session/avatar field.
    private readonly LoginCompletionService _loginCompletion;
    // Kept so a hard revoke (Unregister) can also terminate the user's already-issued tokens (#440); the
    // minter takes its own reference for the login path.
    private readonly ISessionManager _sessionManager;
    private readonly IAuthorizationContext _authContext;
    private readonly ILogger<SSOController> _logger;
    private readonly ICryptoProvider _cryptoProvider;
    // Kept so the elevation-gated Test-connection endpoints (#163) can read a provider's OpenID discovery
    // through the SAME hardened reader the login uses; the shared login flow takes its own reference.
    private readonly IHttpClientFactory _httpClientFactory;

    // The account-linking workflow (resolve/adopt/create, legacy re-key, revoke); the controller keeps
    // the authz guards, the one-time-use replay/state consume, and the HTTP mapping (#318).
    private readonly CanonicalLinkService _canonicalLinks;

    // The SSO-only login enforcement (#165): the fail-closed last-admin guard, the per-user provider-id
    // sweep, and the reversible off-switch. The controller keeps the RequiresElevation guards, the actor
    // resolution, and the audit; the service keeps the account enumeration and the mode-flag writes.
    private readonly SsoOnlyLoginService _ssoOnly;
    // The OpenID login flow (#160, #318 step 12): challenge, redirect callback, session-minting
    // authenticate, and manual link. It owns the OpenID-specific process-wide caches (the authorize-state
    // store and the discovery-facts cache) as its own statics; the controller's OpenID endpoints apply the
    // shared rate-limit gate (SsoRateLimitGate) and delegate here. New'd per request like the other collaborators.
    private readonly Flows.OidcLoginService _oidc;
    // The SAML login flow (#160, #318 step 13): challenge, assertion-consumer callback, session-minting
    // authenticate, and manual link. It owns the SAML-specific process-wide caches (the replay cache and
    // the outstanding-AuthnRequest cache) as its own statics; the controller's SAML endpoints apply the
    // shared rate-limit gate (SsoRateLimitGate) and delegate here. New'd per request like the other collaborators.
    private readonly Flows.SamlLoginService _saml;

    // The shared per-client rate limiter and its opt-in check live in SsoRateLimitGate (#160, #318): the last
    // mutable process-wide static moved off the controller into the Shared tier, so the controller now holds
    // no mutable static state. The RateLimitCheck wrapper below supplies the request-scoped inputs.

    /// <summary>
    /// Initializes a new instance of the <see cref="SSOController"/> class.
    /// </summary>
    /// <param name="logger">Instance of the <see cref="ILogger{SSOController}"/> interface.</param>
    /// <param name="loggerFactory">Instance of the <see cref="ILoggerFactory"/> interface.</param>
    /// <param name="sessionManager">Instance of the <see cref="ISessionManager"/> interface.</param>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="userManager">Instance of the <see cref="IUserManager"/> interface.</param>
    /// <param name="cryptoProvider">Instance of the <see cref="ICryptoProvider"/> interface.</param>
    /// <param name="providerManager">Instance of the <see cref="IProviderManager"/> interface.</param>
    /// <param name="httpClientFactory">Instance of the <see cref="IHttpClientFactory"/> interface.</param>
    /// <param name="serverConfigurationManager">Instance of the <see cref="IServerConfigurationManager"/> interface.</param>
    public SSOController(
        ILogger<SSOController> logger,
        ILoggerFactory loggerFactory,
        ISessionManager sessionManager,
        IUserManager userManager,
        IAuthorizationContext authContext,
        ICryptoProvider cryptoProvider,
        IProviderManager providerManager,
        IHttpClientFactory httpClientFactory,
        IServerConfigurationManager serverConfigurationManager)
    {
        _userManager = userManager;
        _authContext = authContext;
        _cryptoProvider = cryptoProvider;
        _logger = logger;
        _sessionManager = sessionManager;
        _httpClientFactory = httpClientFactory;
        _canonicalLinks = new CanonicalLinkService(userManager, cryptoProvider, SSOPlugin.Instance.ConfigStore, logger);
        _ssoOnly = new SsoOnlyLoginService(userManager, SSOPlugin.Instance.ConfigStore, logger);
        var avatarService = new AvatarService(userManager, providerManager, serverConfigurationManager, logger, SsoHttp.UserAgent);
        var sessionMinter = new SessionMinter(userManager, avatarService, sessionManager, logger);
        _loginCompletion = new LoginCompletionService(_canonicalLinks, sessionMinter, _ssoOnly, SSOPlugin.Instance.ConfigStore, logger);
        _oidc = new Flows.OidcLoginService(_loginCompletion, _canonicalLinks, httpClientFactory, loggerFactory, logger);
        _saml = new Flows.SamlLoginService(_loginCompletion, _canonicalLinks, logger);
        _logger.LogInformation("SSO Controller initialized");
    }

    /// <summary>
    /// The GET endpoint for OpenID provider to callback to. Returns a webpage that parses client data and completes auth.
    /// </summary>
    /// <param name="provider">The ID of the provider which will use the callback information.</param>
    /// <param name="state">The current request state.</param>
    /// <returns>A webpage that will complete the client-side flow.</returns>
    // Actually a GET: https://github.com/IdentityModel/IdentityModel.OidcClient/issues/325
    [HttpGet("OID/r/{provider}")]
    [HttpGet("OID/redirect/{provider}")]
    public async Task<ActionResult> OidCallback(
        [FromRoute] string provider,
        [FromQuery] string state)
    {
        if (RateLimitCheck(SsoRateLimitClass.Callback) is { } throttled)
        {
            return BrowserErrorPage.Wrap(throttled, Request, Response);
        }

        // The OpenID redirect callback lives in the flow service (#160, #318): it validates the
        // browser-bound state, exchanges the code, validates the id_token and RFC 9207 response issuer,
        // applies the role gate, and renders the security-headered intermediate auth page on the response.
        // This endpoint is browser-navigated, so a plain-text rejection is restyled as an HTML page (#668).
        return BrowserErrorPage.Wrap(await _oidc.CallbackAsync(provider, state, Request, Response).ConfigureAwait(false), Request, Response);
    }

    /// <summary>
    /// Initiates the login flow for OpenID. This redirects the user to the auth provider.
    /// </summary>
    /// <param name="provider">The name of the provider.</param>
    /// <param name="isLinking">Whether or not this request is to link accounts (Rather than authenticate).</param>
    /// <returns>An asynchronous result for the authentication.</returns>
    [HttpGet("OID/p/{provider}")]
    [HttpGet("OID/start/{provider}")]
    public async Task<ActionResult> OidChallenge(string provider, [FromQuery] bool isLinking = false)
    {
        if (RateLimitCheck(SsoRateLimitClass.Challenge) is { } throttled)
        {
            return BrowserErrorPage.Wrap(throttled, Request, Response);
        }

        // The OpenID challenge lives in the flow service (#160, #318): it reads discovery, applies the
        // PKCE gate, prepares the authorization request, registers the browser-bound authorize state, and
        // redirects to the identity provider (setting the binding cookie on the response).
        // This endpoint is browser-navigated, so a plain-text rejection is restyled as an HTML page (#668).
        return BrowserErrorPage.Wrap(await _oidc.ChallengeAsync(provider, isLinking, Request, Response).ConfigureAwait(false), Request, Response);
    }

    /// <summary>
    /// RP-initiated OpenID logout (#727, SLO-2). Ends the CALLER's local Jellyfin session, then — when the
    /// caller has a captured OpenID session for this provider (Single Logout enabled) — redirects the browser
    /// to the identity provider's <c>end_session_endpoint</c> with the stored <c>id_token_hint</c>, so the IdP
    /// session is terminated too. Fail-safe: a missing/unsafe endpoint or a disabled feature degrades to a
    /// local-only logout (the browser returns to this server). Authenticated, and every action is scoped
    /// strictly to the caller's own user id — a user can only log THEMSELVES out.
    /// </summary>
    /// <param name="provider">The OpenID provider to end the session at.</param>
    /// <returns>A redirect to the IdP end-session URL, or to this server for a local-only logout.</returns>
    [Authorize]
    [HttpGet("OID/logout/{provider}")]
    public async Task<ActionResult> OidLogout(string provider)
    {
        var auth = await _authContext.GetAuthorizationInfo(HttpContext.Request).ConfigureAwait(false);

        // The caller's most recent captured OpenID session for this provider (an id_token distinguishes an
        // OpenID capture from a SAML one). Scoped to the caller's own user id, read under the config lock.
        // Best-effort with multiple concurrent sessions: "most recent" may differ from the exact session the
        // local Logout below ends, but both belong to the caller and the id_token_hint is a valid token for
        // the same subject at the same issuer, so RP-initiated logout is still correct — a within-user,
        // best-effort SLO, never a cross-user effect (FindByUser is user-id-scoped and empty for Guid.Empty).
        var match = SSOPlugin.Instance.ReadConfiguration(configuration =>
            SessionLogoutStore.FindByUser(configuration, auth.UserId)
                .FirstOrDefault(pair =>
                    string.Equals(pair.Value.Provider, provider, StringComparison.Ordinal)
                    && !string.IsNullOrEmpty(pair.Value.IdToken)));

        // End the caller's local Jellyfin session (their current token only), then drop the consumed entry so
        // the id_token is not retained past the logout.
        if (!string.IsNullOrEmpty(auth.Token))
        {
            await _sessionManager.Logout(auth.Token).ConfigureAwait(false);
        }

        if (match.Value is not null)
        {
            SSOPlugin.Instance.MutateConfiguration(configuration => SessionLogoutStore.Remove(configuration, match.Key));
        }

        var config = SSOPlugin.Instance.ReadConfiguration(configuration =>
            configuration.OidConfigs.TryGetValue(provider, out var oidConfig) ? oidConfig : null);

        // This server's canonical base — the allow-list root for the post-logout return URL, and the
        // local-only fallback target. Derived exactly as the login builds its own external URLs.
        var canonicalBase = CanonicalBaseUrl.Resolve(
            config?.BaseUrlOverride, Request.Scheme, Request.Host.Host, Request.Host.Port, Request.PathBase, config?.SchemeOverride, config?.PortOverride);

        string? endSessionUrl = null;
        if (match.Value is { } captured)
        {
            try
            {
                // Reveal the encrypted id_token only now, at the moment it is sent as the id_token_hint.
                endSessionUrl = OidcLogout.BuildEndSessionUrl(
                    captured.EndSessionEndpoint,
                    captured.Issuer,
                    SSOPlugin.Instance.Secrets.Reveal(captured.IdToken),
                    config?.OidClientId,
                    config?.PostLogoutRedirectUri,
                    canonicalBase);
            }
            catch (Exception ex)
            {
                // Fail-safe: the local logout already completed above. A reveal fault (a missing/corrupt
                // at-rest key, as TryReveal guards on the login path) or a build fault must degrade to a
                // local-only logout, never surface a 500 — honouring the endpoint's stated contract.
                _logger.LogError(ex, "Building the OpenID end-session redirect failed; the local logout stands and the browser returns to this server.");
            }
        }

        // Redirect to the IdP end-session URL (an absolute URL host-bound to the discovered issuer by
        // OidcLogout), or — local-only — back to this server via a LOCAL redirect. The local fallback must NOT
        // reuse the canonical base as an absolute target: with no Base URL Override that base is derived from
        // the request Host header, so a spoofed Host would turn the fallback into an open redirect. A local
        // ("~/") redirect is host-independent and ASP.NET Core rejects any non-local value outright.
        return endSessionUrl is null ? LocalRedirect("~/") : Redirect(endSessionUrl);
    }

    /// <summary>
    /// SP-initiated outbound SAML Single Logout (#727, SLO-3c). Ends the CALLER's local Jellyfin session, then
    /// — when Single Logout is enabled, the provider has a configured SLO endpoint, a signing key loads, and the
    /// caller has a captured SAML session with a NameID — redirects the browser to the identity provider's
    /// Single-Logout endpoint with a SIGNED <c>LogoutRequest</c>, so the IdP session is terminated too.
    /// Fail-safe: a missing SLO endpoint, a missing/unloadable signing key, or no captured session degrades to a
    /// local-only logout (a host-independent redirect back to this server) — none of those must ever break the
    /// local logout or 500. Authenticated, rate-limited, and every action is scoped strictly to the caller's own
    /// user id — a user can only log THEMSELVES out, and the LogoutRequest can only ever carry the caller's own
    /// NameID.
    /// </summary>
    /// <param name="provider">The SAML provider to end the session at.</param>
    /// <returns>A redirect to the IdP SLO URL, or to this server for a local-only logout.</returns>
    [Authorize]
    [HttpGet("SAML/logout/{provider}")]
    public async Task<ActionResult> SamlSpLogout(string provider)
    {
        // Deliberately NOT rate-limited, matching the authenticated OID/logout route: the Logout rate-limit
        // class guards the ANONYMOUS inbound SAML LogoutRequest endpoint (SLO-3b). Throttling this
        // [Authorize] self-logout would risk leaving the caller's own local session live under throttle —
        // a security action must always be able to end the caller's session, and the route already requires
        // a valid session to reach.
        var auth = await _authContext.GetAuthorizationInfo(HttpContext.Request).ConfigureAwait(false);

        // Read the Single Logout feature flag, the provider config, AND the caller's most recent captured SAML
        // session for this provider in one lock acquisition. Scoped to the caller's own user id (FindByUser is
        // user-id-scoped and empty for Guid.Empty), and filtered to a SAML capture — a SAML session carries no
        // id_token, so the Protocol tag distinguishes it from an OpenID capture for the same provider. The
        // captured Subject is the caller's own NameID; nothing here can read another user's session.
        var (singleLogoutEnabled, config, match) = SSOPlugin.Instance.ReadConfiguration(configuration =>
            (configuration.EnableSingleLogout,
             configuration.SamlConfigs.TryGetValue(provider, out var samlConfig) ? samlConfig : null,
             SessionLogoutStore.FindByUser(configuration, auth.UserId)
                 .FirstOrDefault(pair =>
                     string.Equals(pair.Value.Provider, provider, StringComparison.Ordinal)
                     && string.Equals(pair.Value.Protocol, SamlProtocol, StringComparison.Ordinal))));

        // End the caller's local Jellyfin session (their current token only) in EVERY path, then drop the
        // consumed entry so the captured session state is not retained past the logout.
        if (!string.IsNullOrEmpty(auth.Token))
        {
            await _sessionManager.Logout(auth.Token).ConfigureAwait(false);
        }

        if (match.Value is not null)
        {
            SSOPlugin.Instance.MutateConfiguration(configuration => SessionLogoutStore.Remove(configuration, match.Key));
        }

        // Build the signed LogoutRequest redirect only when everything the SP-initiated path needs is present:
        // the feature is on, the caller has a captured SAML session naming a NameID, the provider is configured
        // with an SLO endpoint, and a signing key loads. ANY missing piece — or any fault building/signing —
        // fails SAFE to a local-only logout, never a 500 (the local logout already completed above).
        string? sloRedirectUrl = null;
        if (singleLogoutEnabled && config is not null && match.Value is { } captured && !string.IsNullOrEmpty(captured.Subject))
        {
            try
            {
                sloRedirectUrl = BuildSamlSloRedirectUrl(config, captured);
            }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or CryptographicException or FormatException)
            {
                // Fail-safe: the local logout already stands. A missing/unloadable signing key
                // (InvalidOperationException/CryptographicException), a corrupt at-rest secret envelope
                // (FormatException), or a signer rejection (ArgumentException) degrades to a local-only logout
                // rather than surfacing a 500. Key material is never part of the message, so nothing sensitive
                // is logged.
                if (_logger.IsEnabled(LogLevel.Error))
                {
                    _logger.LogError("SAML SP-initiated logout for provider {Provider} could not build the signed LogoutRequest: {Reason}; the local logout stands and the browser returns to this server.", provider?.ReplaceLineEndings(string.Empty), ex.Message);
                }
            }
        }

        // Redirect to the IdP SLO URL (the SLO endpoint is validated as an absolute https URL at save), or —
        // local-only — back to this server via a LOCAL redirect. As with the OpenID logout, the local fallback
        // uses a host-independent "~/" redirect rather than a request-Host-derived absolute target, so a spoofed
        // Host can never turn the fallback into an open redirect.
        return sloRedirectUrl is null ? LocalRedirect("~/") : Redirect(sloRedirectUrl);
    }

    // Builds the signed SP-initiated LogoutRequest redirect URL for a captured SAML session (#727, SLO-3c), or
    // null when SP-initiated SLO is not configured (no SLO endpoint). Fail-closed on the signing key: a missing
    // or unloadable key returns null (the caller degrades to local-only) rather than sending an UNSIGNED
    // LogoutRequest — the SLO redirect binding requires a signature, so an unsigned downgrade is never emitted.
    // Reuses the outbound-signing infrastructure verbatim: the encrypted-at-rest signing key is revealed at the
    // point of use (mirroring the challenge), loaded through SamlSigningKey, and handed to the shared
    // SamlRedirectSigner via SamlLogoutRequestBuilder. The subject NameID and SessionIndex come only from the
    // caller's OWN captured session, so the request can never name another user.
    private static string? BuildSamlSloRedirectUrl(SamlConfig config, LogoutSession captured)
    {
        var sloEndpoint = config.SamlSloEndpoint?.Trim();
        if (string.IsNullOrEmpty(sloEndpoint))
        {
            return null;
        }

        // Reveal the encrypted-at-rest signing key only now, at the moment it signs. A missing/unloadable key
        // returns null (local-only), never an unsigned request.
        if (!SamlSigningKey.TryLoad(SSOPlugin.Instance.Secrets.Reveal(config.SamlSigningKeyPfx), out var signingCertificate))
        {
            return null;
        }

        using (signingCertificate)
        using (var signingKey = SamlSigningKey.GetSigningKey(signingCertificate))
        {
            if (signingKey is null)
            {
                return null;
            }

            var request = new SamlLogoutRequestBuilder(config.SamlClientId.Trim(), captured.Subject, captured.SessionIndex);
            return request.GetSignedRedirectUrl(sloEndpoint, relayState: null, signingKey);
        }
    }

    // Rejects a malformed canonical base-URL override (#139) at the OID/SAML Add endpoints. These persist
    // through MutateConfiguration, which passes the live configuration object, so they bypass the
    // config-page save-time validation in ProviderConfigStore.Save (which only runs for a fresh
    // incoming config). Without this, a malformed override set via the Add API would be persisted and then
    // silently fall back to the request Host at login. Throwing keeps it out of the store, so the
    // "rejected at every admin write path" invariant holds. Blank is valid (the feature is off).

    /// <summary>
    /// Rejects a malformed canonical base-URL override at the OID/SAML Add endpoints (#139), the door that
    /// mirrors the config-page save-time check for the Add path that bypasses it. A blank override is valid.
    /// </summary>
    /// <param name="baseUrlOverride">The override value posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The override is non-blank and not a valid absolute http(s) URL.</exception>
    internal static void RejectInvalidBaseUrlOverride(string? baseUrlOverride)
    {
        if (CanonicalBaseUrl.IsInvalidOverride(baseUrlOverride))
        {
            throw new ArgumentException("The Base URL override must be an absolute http(s) URL such as https://jellyfin.example.com, or left blank.", nameof(baseUrlOverride));
        }
    }

    // Rejects a non-loadable SAML signing certificate at the SAML/Add endpoint (#206), which persists
    // through MutateConfiguration and so bypasses the config-page save-time validation in
    // ProviderConfigValidator.Validate. Without this, a garbage certificate set via the Add API would be
    // persisted and then throw a CryptographicException on every callback (an unhandled 500). Blank is
    // valid (a half-configured provider).

    /// <summary>
    /// Rejects a non-loadable SAML signing certificate at the SAML/Add endpoint (#206), the Add-path
    /// counterpart to the config-page save-time certificate check. A blank certificate is valid.
    /// </summary>
    /// <param name="certificateStr">The Base64-encoded (DER) X.509 certificate posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The certificate is non-blank and not loadable.</exception>
    internal static void RejectInvalidSamlCertificate(string? certificateStr)
    {
        if (SamlCertificate.IsInvalid(certificateStr))
        {
            throw new ArgumentException("The SAML signing certificate must be a Base64-encoded (DER) X.509 certificate, or left blank.", nameof(certificateStr));
        }
    }

    // Rejects a non-loadable inbound secondary verification certificate at the SAML/Add endpoint (#491),
    // the same fail-closed door as the primary certificate guard above and for the same reason: a garbage
    // secondary would persist and then throw a CryptographicException on every callback (an unhandled
    // 500). It is the identity provider's PUBLIC certificate, so it is validated exactly like the primary.
    // Blank is valid (no overlap window configured).

    /// <summary>
    /// Rejects a non-loadable inbound secondary verification certificate at the SAML/Add endpoint (#491) —
    /// the identity provider's public certificate for a key-overlap window, validated like the primary. A
    /// blank value is valid (no overlap window configured).
    /// </summary>
    /// <param name="certificateStr">The Base64-encoded (DER) X.509 certificate posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The certificate is non-blank and not loadable.</exception>
    internal static void RejectInvalidSamlSecondaryCertificate(string? certificateStr)
    {
        if (SamlCertificate.IsInvalid(certificateStr))
        {
            throw new ArgumentException("The SAML secondary signing certificate must be a Base64-encoded (DER) X.509 certificate, or left blank.", nameof(certificateStr));
        }
    }

    // Rejects a non-loadable service-provider signing key at the SAML/Add endpoint (#167), the same
    // fail-closed door as the inbound certificate guard above: a garbage or private-key-less PKCS#12 set
    // here would persist and then fail every signed challenge. Blank is valid (signing simply stays off,
    // or the stored key is preserved on save).

    /// <summary>
    /// Rejects a non-loadable service-provider request signing key at the SAML/Add endpoint (#167). A blank
    /// key is valid (signing stays off, or the stored key is preserved on save).
    /// </summary>
    /// <param name="signingKeyPfx">The Base64-encoded PKCS#12 (PFX) signing key posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The key is non-blank and not a loadable PFX with an RSA or ECDSA private key.</exception>
    internal static void RejectInvalidSamlSigningKey(string? signingKeyPfx)
    {
        if (SamlSigningKey.IsInvalid(signingKeyPfx))
        {
            throw new ArgumentException("The SAML request signing key must be a Base64-encoded, unencrypted PKCS#12 (PFX) blob containing an RSA or ECDSA private key, or left blank.", nameof(signingKeyPfx));
        }
    }

    // Rejects a malformed SAML SLO endpoint (#727, SLO-3c) at the SAML/Add endpoint, the door that mirrors
    // the config-page save-time SLO-endpoint check in ProviderConfigValidator for the Add path that
    // bypasses it. It must be an absolute https URL — the redirect carries a signed LogoutRequest naming the
    // subject, so it must not traverse plaintext http. Reuses the same CanonicalBaseUrl.TryNormalize
    // absolute-URL predicate the Base URL override guard uses, narrowed to https. Blank is valid (no
    // SP-initiated Single Logout). The message stays generic (never echoes the caller's endpoint back).

    /// <summary>
    /// Rejects a malformed SAML SLO endpoint at the SAML/Add endpoint (#727, SLO-3c), the Add-path
    /// counterpart to the config-page save-time SLO-endpoint check. A blank endpoint is valid.
    /// </summary>
    /// <param name="sloEndpoint">The SAML SLO endpoint posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The endpoint is non-blank and not a valid absolute https URL.</exception>
    internal static void RejectInvalidSamlSloEndpoint(string? sloEndpoint)
    {
        if (!string.IsNullOrWhiteSpace(sloEndpoint)
            && (!CanonicalBaseUrl.TryNormalize(sloEndpoint, out var normalized)
                || !normalized.StartsWith("https://", StringComparison.Ordinal)))
        {
            throw new ArgumentException("The SAML SLO Endpoint must be an absolute https URL such as https://idp.example.com/slo, or left blank.", nameof(sloEndpoint));
        }
    }

    // Rejects a null provider body at the Add endpoints (#350). ASP.NET model binding hands a null
    // [FromBody] object for an empty or literal "null" JSON payload; storing it would put a null entry
    // in the config map that then NREs the config-page save (ServerManagedFields.Preserve). Reject at
    // the door so the store never holds a null provider — the same fail-closed posture as the other
    // Add-endpoint gates.

    /// <summary>
    /// Rejects a null provider body at the Add endpoints (#350), so a null or literal "null" JSON payload
    /// can never put a null entry in the config map that would later NRE the config-page save.
    /// </summary>
    /// <param name="config">The model-bound provider configuration body.</param>
    /// <exception cref="ArgumentException">The body is null.</exception>
    internal static void RejectNullProviderBody(object config)
    {
        if (config is null)
        {
            throw new ArgumentException("The provider configuration body must not be empty.", nameof(config));
        }
    }

    // Rejects a provider name containing URI-reserved or control characters when it would register a NEW
    // provider (#336, #360): the name is appended raw to the callback URLs handed to the identity provider
    // (the OIDC/SAML URL builders), so '%' breaks route decoding, '/' dead-ends the IdP redirect on a path no route
    // matches, control characters do not round-trip at all, and the other RFC 3986 delimiters invite
    // proxy/IdP misinterpretation. Updating an
    // EXISTING name stays allowed: its URL bytes are already registered at the IdP, and blocking the
    // update would strand the deployment behind a rename (encoding the built URLs instead is pinned
    // off by SsoUrlBuilderTests).

    /// <summary>
    /// Rejects a NEW provider name containing control characters, a backslash, or a URI-reserved character
    /// (#336, #360), because the name is appended raw to the callback URLs registered with the identity
    /// provider. Updating an existing name stays allowed so a deployment is not stranded behind a rename.
    /// </summary>
    /// <param name="provider">The provider name posted to the Add endpoint.</param>
    /// <param name="providerExists">Whether the name already names a registered provider; only new names are validated.</param>
    /// <exception cref="ArgumentException">The name is new and contains a forbidden character.</exception>
    internal static void RejectInvalidNewProviderName(string provider, bool providerExists)
    {
        if (!providerExists && ProviderNameValidator.IsInvalid(provider))
        {
            throw new ArgumentException("A new provider name must not contain control characters, a backslash, or any of % : / ? # [ ] @ ! $ & ' ( ) * + , ; = because the name becomes part of the callback URL registered with the identity provider.", nameof(provider));
        }
    }

    /// <summary>
    /// Adds an OpenID auth configuration. Requires administrator privileges. If the provider already exists, it will be removed and readded.
    /// </summary>
    /// <param name="provider">The name of the provider to add.</param>
    /// <param name="config">The OID configuration (deserialized from a JSON post).</param>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("OID/Add/{provider}")]
    public void OidAdd(string provider, [FromBody] OidConfig config)
    {
        RejectNullProviderBody(config);
        RejectInvalidBaseUrlOverride(config.BaseUrlOverride);
        // Reject a malformed generic permission-role mapping (#164) at the door, exactly like the base-URL
        // and certificate guards above: the Add endpoints persist through MutateConfiguration and so bypass
        // the config-page save-time validation. Reuses the one shared validator so every admin write path
        // agrees on what a valid mapping is.
        ProviderConfigValidator.ValidatePermissionRoleMappings(OpenIdProtocol, provider, config.PermissionRoleMappings);
        // Reject an invalid parental-rating mapping (#736) at the door too (negative score / no roles), like
        // the permission-role guard above — the Add endpoints bypass the config-page save-time validation.
        ProviderConfigValidator.ValidateParentalRatingMappings(OpenIdProtocol, provider, config.ParentalRatingRoleMappings);
        // Reject RequireAcr with no acr_values at the door too (#757): an empty allow-list would refuse every
        // login for the provider (a silent single-provider lockout). Mirrors the config-page/import validation
        // so this Add path — which persists through MutateConfiguration and bypasses the save-time Validate —
        // shares the same fail-closed guard.
        ProviderConfigValidator.ValidateAcrRequirement(provider, config);
        SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            // The name guard needs the under-lock existence check (#336) and runs before any mutation,
            // so a throw leaves the live configuration untouched and nothing is persisted.
            var providerExists = configuration.OidConfigs.TryGetValue(provider, out var existing);
            RejectInvalidNewProviderName(provider, providerExists);

            // Re-inject the server-managed fields this API cannot carry — CanonicalLinks ([JsonIgnore],
            // #157) and the write-only secret's blank-means-keep rule (#189) — through the one shared
            // ServerManagedFields.Preserve the config-page save also uses, so every write path agrees.
            if (providerExists)
            {
                ServerManagedFields.Preserve(config, existing);
            }

            configuration.OidConfigs[provider] = config;
        });
        SsoAudit.ProviderConfigured(_logger, OpenIdProtocol, provider);

        // Audit any disabled security check (#140), so enabling an escape hatch (DisableHttps,
        // DoNotValidateIssuerName, DoNotValidateEndpoints) via this API leaves a trace too.
        var insecure = OidcInsecureToggles.Enabled(config);
        if (insecure.Count > 0)
        {
            SsoAudit.InsecureOptionsEnabled(_logger, OpenIdProtocol, provider, insecure);
        }
    }

    /// <summary>
    /// Deletes an OpenID provider.
    /// </summary>
    /// <param name="provider">Name of provider to delete.</param>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Del/{provider}")]
    public void OidDel(string provider)
    {
        var removed = SSOPlugin.Instance.MutateConfiguration(configuration => configuration.OidConfigs.Remove(provider));
        if (removed)
        {
            SsoAudit.ProviderRemoved(_logger, OpenIdProtocol, provider);
        }
    }

    /// <summary>
    /// Lists the OpenID providers configured. Requires administrator privileges.
    /// </summary>
    /// <returns>The list of OpenID configurations.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Get")]
    public ActionResult OidProviders()
    {
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => SnapshotConfigs(c.OidConfigs)));
    }

    /// <summary>
    /// Lists the names of the enabled OpenID providers only. Intentionally anonymous — see the
    /// in-body rationale (#540).
    /// </summary>
    /// <returns>The list of enabled OpenID provider names.</returns>
    [HttpGet("OID/GetNames")]
    public ActionResult OidProviderNames()
    {
        // Only enabled providers are offered (#344): this endpoint drives the self-service linking page,
        // and a disabled provider cannot complete a link (the link leg fail-closes on Enabled, #343), so
        // offering it would render an add button that only ever fails. The filter is UX honesty, not the
        // gate — the server-side rejection stays the real defense in depth.
        // Materialize under the lock (#157/F-10): returning a live view lets the JSON formatter enumerate
        // it outside the lock, tearing against a concurrent provider add/remove.
        //
        // No [Authorize] here — deliberate, not an oversight (#540). SSOViewsController, which serves the
        // self-service linking page (linking.html/linking.js, the sole caller of this endpoint), carries no
        // [Authorize] of its own either, so the same provider-name list this endpoint returns is already
        // rendered into that page's visible DOM for an anonymous visitor. Gating GetNames would add no
        // confidentiality (the list is public via the page regardless) while breaking that page's render for
        // any caller who has not first authenticated — including the isLinking=false leg, which is how a
        // brand-new (not-yet-Jellyfin-authenticated) user discovers which providers they can sign in with.
        // Provider names are configuration, not secrets; the identity-provider connection itself (client
        // secret, signing keys) stays behind the elevation-gated OID/Get and SAML/Get.
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => EnabledProviderNames(c.OidConfigs)));
    }

    /// <summary>
    /// Lists the names of the enabled SAML providers only. Intentionally anonymous — see the
    /// in-body rationale (#540).
    /// </summary>
    /// <returns>The list of enabled SAML provider names.</returns>
    [HttpGet("SAML/GetNames")]
    public ActionResult SamlProviderNames()
    {
        // Enabled-only and materialized under the lock, as OID/GetNames does (#344, #157/F-10).
        // Anonymous by the same design as OID/GetNames above (#540) — same caller, same already-public
        // rendering, same rationale.
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => EnabledProviderNames(c.SamlConfigs)));
    }

    // Names of the enabled providers in a config map, materialized to a detached list (the caller holds
    // the config lock). Shared by both GetNames twins so the enabled-only rule lives in one place. A
    // null-valued entry is skipped rather than dereferenced (#538) — the same fail-closed convention
    // CanonicalLinkService already applies to these maps.
    private static List<string> EnabledProviderNames<TConfig>(SerializableDictionary<string, TConfig> configs)
        where TConfig : ProviderConfigBase =>
        configs.Where(kvp => kvp.Value is { Enabled: true }).Select(kvp => kvp.Key).ToList();

    /// <summary>
    /// Tests connectivity and basic config for a stored OpenID provider (#163). Requires administrator
    /// privileges. Reads the provider's discovery document through the SAME hardened reader the login uses
    /// and reports the issuer, endpoints and JWKS reachability — never the client secret. Deliberately
    /// elevation-gated (unlike the anonymous GetNames): the server fetches an admin-configured URL, so an
    /// unauthenticated caller must not be able to drive it as an SSRF probe.
    /// </summary>
    /// <param name="provider">The stored OpenID provider to test.</param>
    /// <returns>The non-secret test result, or 404 when the provider is not configured.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Test/{provider}")]
    public async Task<ActionResult> OidTest(string provider)
    {
        // Throttle after the elevation guard, before the outbound fetch (mirrors Unregister, #516): the
        // [Authorize] filter rejects a non-elevated caller before the body runs, so an unauthorized request
        // never reaches the limiter (no rate-limit oracle). Once past it, the shared "test" budget caps how
        // fast an authorized admin can drive the probe's outbound discovery fetch.
        if (RateLimitCheck(SsoRateLimitClass.Test) is { } throttled)
        {
            return throttled;
        }

        // Read the stored provider under the config lock, then hand it to the tester (the fetch and any
        // logging live there). The tester never reveals the client secret — discovery needs no credential.
        var config = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.TryGetValue(provider, out var cfg) ? cfg : null);
        if (config is null)
        {
            return NotFound(NoMatchingProviderMessage);
        }

        return Ok(await ProviderConnectionTester.TestOidcAsync(config, provider, _httpClientFactory, _logger).ConfigureAwait(false));
    }

    /// <summary>
    /// This is a debug endpoint to list all running OpenID flows. Requires administrator privileges.
    /// </summary>
    /// <returns>The list of OpenID flows in progress.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/States")]
    public ActionResult OidStates()
    {
        // Non-secret summaries only — the flow service projects the in-flight states to redacted summaries.
        return Ok(_oidc.StateSummaries());
    }

    /// <summary>
    /// This endpoint accepts JSON and will authorize the user from the device values passed from the client.
    /// </summary>
    /// <param name="provider">Name of provider to authenticate against.</param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    [HttpPost("OID/Auth/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> OidAuth(string provider, [FromBody] AuthResponse response)
    {
        if (RateLimitCheck(SsoRateLimitClass.Auth) is { } throttled)
        {
            return throttled;
        }

        // The session-minting authenticate leg lives in the flow service (#160, #318): it redeems the
        // browser-bound authorize state once and hands the verified identity to the shared completion tail.
        // The controller passes the presented binding cookie and the HttpContext-derived remote endpoint in,
        // keeping the flow tier HttpContext-free (#177).
        return await _oidc.AuthenticateAsync(
            provider,
            response,
            Request.Cookies[AuthorizeStateBinding.CookieName],
            () => HttpContext.GetNormalizedRemoteIP().ToString()).ConfigureAwait(false);
    }

    /// <summary>
    /// This is the callback for the SAML flow. This creates a webpage to complete auth.
    /// </summary>
    /// <param name="provider">The provider that is calling back.</param>
    /// <param name="relayState">
    ///    RelayState given in the original saml request. If it is equal to "linking",
    ///    We consider this to be a linking request.
    /// </param>
    /// <param name="formSamlResponse">
    ///    The SAMLResponse form field, model-bound so a non-form POST binds null (and is rejected)
    ///    instead of making Request.Form throw an unhandled 500 (#206).
    /// </param>
    /// <returns>A webpage that will complete the client-side flow.</returns>
    [HttpPost("SAML/p/{provider}")]
    [HttpPost("SAML/post/{provider}")]
    public ActionResult SamlCallback(string provider, [FromQuery] string? relayState = null, [FromForm(Name = "SAMLResponse")] string? formSamlResponse = null)
    {
        if (RateLimitCheck(SsoRateLimitClass.Callback) is { } throttled)
        {
            return BrowserErrorPage.Wrap(throttled, Request, Response);
        }

        // The SAML assertion-consumer callback lives in the flow service (#160, #318): it validates the
        // signed response and, on a passing role gate, renders the security-headered intermediate auth
        // page on the response.
        // This endpoint is browser-navigated, so a plain-text rejection is restyled as an HTML page (#668).
        return BrowserErrorPage.Wrap(_saml.Callback(provider, relayState, formSamlResponse, Request, Response), Request, Response);
    }

    /// <summary>
    /// Initializes the SAML flow. This will redirect the user to the SAML provider.
    /// </summary>
    /// <param name="provider">The provider to being the flow with.</param>
    /// <param name="isLinking">Whether this flow intends to link an account, or initiate auth.</param>
    /// <returns>A redirect to the SAML provider's auth page.</returns>
    [HttpGet("SAML/p/{provider}")]
    [HttpGet("SAML/start/{provider}")]
    public ActionResult SamlChallenge(string provider, [FromQuery] bool isLinking = false)
    {
        if (RateLimitCheck(SsoRateLimitClass.Challenge) is { } throttled)
        {
            return BrowserErrorPage.Wrap(throttled, Request, Response);
        }

        // The SAML challenge lives in the flow service (#160, #318): it builds the AuthnRequest, binds it
        // to the initiating browser (setting the binding cookie on the response), signs it when the
        // provider opts in (#167), and redirects to the identity provider.
        // This endpoint is browser-navigated, so a plain-text rejection is restyled as an HTML page (#668).
        return BrowserErrorPage.Wrap(_saml.Challenge(provider, isLinking, Request, Response), Request, Response);
    }

    /// <summary>
    /// Serves this service provider's SAML 2.0 metadata for <paramref name="provider"/> (#162). The
    /// request-free, canonical-Base-URL-only construction and its fail-closed rationale live on the single
    /// authoritative implementation, <see cref="SamlLoginService.Metadata"/>.
    /// </summary>
    /// <param name="provider">The SAML provider whose metadata to serve.</param>
    /// <returns>The SP metadata document, or a fail-closed rejection when the provider is unknown/disabled or its canonical Base URL is unconfigured.</returns>
    [HttpGet("SAML/metadata/{provider}")]
    public ActionResult SamlMetadata(string provider)
    {
        if (RateLimitCheck(SsoRateLimitClass.Metadata) is { } throttled)
        {
            return throttled;
        }

        // The SP metadata flow lives in the flow service (#160, #318): it resolves the entity id and
        // assertion-consumer URL from the configured canonical Base URL (never the request Host) and emits
        // the SPSSODescriptor, advertising the PUBLIC signing certificate only when request signing is on.
        return _saml.Metadata(provider);
    }

    /// <summary>
    /// Inbound IdP-initiated SAML Single Logout (#727, SLO-3b): accepts a signed <c>LogoutRequest</c> and
    /// revokes the linked Jellyfin sessions. This is the UNAUTHENTICATED, session-destructive surface — its
    /// only trust anchor is the request's XML signature against the provider's configured certificate(s), so
    /// it mirrors the login-side hardening (enveloped-signature + wrapping defense, weak-algorithm rejection,
    /// DTD-prohibited parse, replay one-time-use). POST-binding only (the <c>SAMLRequest</c> form field,
    /// Base64). Single Logout is opt-in and off by default: while it is off the whole surface rejects WITHOUT
    /// parsing. Every rejection — feature off, unknown provider, bad signature, replay, unknown subject — is
    /// the SAME uniform 400 with a fixed body, so the causes cannot be told apart (no oracle); only a
    /// validly-signed request that resolves at least one session returns 200.
    /// </summary>
    /// <param name="provider">The SAML provider the LogoutRequest arrived for.</param>
    /// <param name="samlRequest">The <c>SAMLRequest</c> form field (model-bound, so a non-form POST binds null and is rejected).</param>
    /// <param name="relayState">The optional <c>RelayState</c> form field, echoed on the signed <c>LogoutResponse</c> (#727, SLO-3c) when within the 80-byte SAML binding cap.</param>
    /// <returns>A signed <c>LogoutResponse</c> redirect (302) when a validated request revoked at least one session and the provider is configured to sign it, a bare 200 when it cannot be signed, or a uniform 400 otherwise.</returns>
    [HttpPost("SAML/Logout/{provider}")]
    public async Task<ActionResult> SamlLogout(string provider, [FromForm(Name = "SAMLRequest")] string? samlRequest = null, [FromForm(Name = "RelayState")] string? relayState = null)
    {
        if (RateLimitCheck(SsoRateLimitClass.Logout) is { } throttled)
        {
            return throttled;
        }

        // Read the feature flag AND the provider config in one lock acquisition. Single Logout is opt-in/off
        // by default: a disabled feature, an unknown provider, and a disabled provider all collapse to the ONE
        // uniform 400 below, and NONE of them parses the untrusted body — so the inbound signed-XML sink is
        // unreachable while the feature is off, and neither the feature state nor the provider set can be
        // probed apart.
        var (singleLogoutEnabled, config) = SSOPlugin.Instance.ReadConfiguration(configuration =>
            (configuration.EnableSingleLogout, configuration.SamlConfigs.TryGetValue(provider, out var samlConfig) ? samlConfig : null));

        if (!singleLogoutEnabled || config is not { Enabled: true })
        {
            return UniformLogoutRejection();
        }

        // Parse + signature/time-bound validate + one-time-use consume. On any failure the reason code is a
        // FIXED constant (never request-derived) written only to the audit trail; the caller sees the uniform
        // 400 with no branch-distinguishing detail.
        var validator = new SamlLogoutValidator();
        if (!validator.TryValidate(config, provider, samlRequest, DateTime.UtcNow, out var nameId, out var sessionIndexes, out var requestId, out var reasonCode))
        {
            SsoAudit.LogoutRejected(_logger, provider, reasonCode);
            return UniformLogoutRejection();
        }

        // Resolve the targeted sessions — strictly the SAME provider and subject (ordinal exact). This is the
        // blast-radius bound: FindByProviderSubject filters by (provider, subject), so a logout for one
        // subject can never touch another subject's or another provider's sessions. When the request names
        // SessionIndex element(s), keep only entries whose captured index is among them; a request with NO
        // SessionIndex targets every session of the subject (SAML core §3.7).
        var matches = SSOPlugin.Instance.ReadConfiguration(configuration =>
            SessionLogoutStore.FindByProviderSubject(configuration, provider, nameId, string.Empty));
        if (sessionIndexes.Count > 0)
        {
            matches = matches
                .Where(pair => sessionIndexes.Contains(pair.Value.SessionIndex ?? string.Empty, StringComparer.Ordinal))
                .ToList();
        }

        // A validated request resolving NO session is the "unknown-subject" case: render the SAME uniform 400
        // as a validation failure. An anonymous attacker can never produce a valid signature to reach here, so
        // this discloses nothing; only the trusted IdP (which already knows its own subjects) can distinguish
        // it from a 200, which is acceptable.
        if (matches.Count == 0)
        {
            SsoAudit.LogoutRejected(_logger, provider, "no_matching_session");
            return UniformLogoutRejection();
        }

        // Revoke the tokens of each DISTINCT matched user. RevokeUserTokens is USER-scoped — Jellyfin exposes
        // no per-token revoke — so a SessionIndex-scoped request still revokes the whole matched user's tokens;
        // that is honest and safe (a logout can only ever end sessions, never grant or link). A revoke fault
        // for one user must NOT abort the loop (availability fail-safe): the remaining users are still logged
        // out, and a faulted user's store entry is LEFT in place (not consumed) so nothing is silently dropped.
        var succeeded = new HashSet<Guid>();
        foreach (var userId in matches.Select(pair => pair.Value.UserId).Distinct())
        {
            try
            {
                await _sessionManager.RevokeUserTokens(userId, null).ConfigureAwait(false);
                succeeded.Add(userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Revoking tokens during SAML logout failed for one user; the remaining matched users are still logged out.");
            }
        }

        // Remove only the entries whose user was actually revoked, so a transient revoke fault leaves that
        // user's entry for a later retry/prune rather than dropping it.
        var consumedKeys = matches.Where(pair => succeeded.Contains(pair.Value.UserId)).Select(pair => pair.Key).ToList();
        if (consumedKeys.Count > 0)
        {
            SSOPlugin.Instance.MutateConfiguration(configuration =>
            {
                foreach (var key in consumedKeys)
                {
                    SessionLogoutStore.Remove(configuration, key);
                }
            });
        }

        // Fail-closed on the destructive action itself: a 200 must mean at least one user was ACTUALLY logged
        // out. Sessions matched but EVERY revoke faulted (succeeded.Count == 0) means no token was invalidated
        // and the user stays authenticated — so we must NOT tell the IdP the logout succeeded. Audit the fault
        // and return the uniform 400; the matched entries were left in the store above (nothing was consumed),
        // so a retry can still act. This is the fail-CLOSED half of the per-user fail-SAFE loop: one user's
        // fault does not abort the others (availability), but zero successful revokes is never reported as done.
        if (succeeded.Count == 0)
        {
            SsoAudit.LogoutRejected(_logger, provider, "revoke_failed");
            return UniformLogoutRejection();
        }

        SsoAudit.LogoutRequested(_logger, provider, succeeded.Count);

        // SLO-3c: answer the IdP with a SIGNED LogoutResponse so its Single-Logout loop completes, redirecting
        // the browser to the IdP SLO endpoint. Emitted ONLY here — on the success path, after a validated
        // request actually revoked a session — so no rejection can ever produce a signed status-bearing
        // response (every failure above keeps the uniform 400, no cause oracle). Fail-SAFE: when no SLO
        // endpoint or signing key is configured, or the build/sign faults, fall back to the bare 200 — the
        // revocation already stands, and a missing response is degraded interop, never a 500 or an unsigned
        // downgrade. The redirect target is the save-validated absolute-https SamlSloEndpoint (never
        // request-derived), so it cannot be an open redirect.
        string? responseRedirectUrl = null;
        try
        {
            responseRedirectUrl = BuildSamlLogoutResponseRedirectUrl(config, requestId, relayState);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or CryptographicException or FormatException)
        {
            if (_logger.IsEnabled(LogLevel.Error))
            {
                _logger.LogError("SAML inbound logout for provider {Provider} could not build the signed LogoutResponse: {Reason}; the revocation stands and the endpoint answers 200.", provider?.ReplaceLineEndings(string.Empty), ex.Message);
            }
        }

        return responseRedirectUrl is null ? Ok() : Redirect(responseRedirectUrl);
    }

    // Builds the signed outbound SAML LogoutResponse redirect URL answering a validated inbound LogoutRequest
    // (#727, SLO-3c), or null when the response cannot be signed (no SLO endpoint, or no loadable signing key).
    // Fail-closed on the signing key exactly like BuildSamlSloRedirectUrl: a missing/unloadable key returns
    // null (the endpoint degrades to a bare 200) rather than emitting an UNSIGNED response — the redirect
    // binding mandates a signature, so an unsigned downgrade is never sent. Reuses the outbound-signing stack
    // verbatim (revealed-at-use key via SamlSigningKey, the shared SamlRedirectSigner via
    // SamlLogoutResponseBuilder). InResponseTo/Destination are bound to the validated request and the trusted
    // configured endpoint; the inbound RelayState is echoed only when within the 80-byte SAML binding cap.
    private static string? BuildSamlLogoutResponseRedirectUrl(SamlConfig config, string requestId, string? relayState)
    {
        var sloEndpoint = config.SamlSloEndpoint?.Trim();
        if (string.IsNullOrEmpty(sloEndpoint))
        {
            return null;
        }

        // Without an SP entity id there is no valid Issuer for the response. Fail-safe to null (the endpoint
        // degrades to a bare 200) rather than emit a malformed empty-Issuer response — and this also removes
        // any NullReferenceException risk from Trim() on a null-deserialized SamlClientId.
        var issuer = config.SamlClientId?.Trim();
        if (string.IsNullOrEmpty(issuer))
        {
            return null;
        }

        if (!SamlSigningKey.TryLoad(SSOPlugin.Instance.Secrets.Reveal(config.SamlSigningKeyPfx), out var signingCertificate))
        {
            return null;
        }

        using (signingCertificate)
        using (var signingKey = SamlSigningKey.GetSigningKey(signingCertificate))
        {
            if (signingKey is null)
            {
                return null;
            }

            // Echo the inbound RelayState only when it is within the SAML HTTP binding's 80-BYTE cap
            // (saml-bindings-2.0 §3.4.3) — measured in UTF-8 bytes, not UTF-16 chars, so a multi-byte value
            // cannot slip over the wire limit; anything longer is non-conformant and dropped, not reflected.
            var echoedRelayState = !string.IsNullOrEmpty(relayState) && System.Text.Encoding.UTF8.GetByteCount(relayState) <= 80 ? relayState : null;

            var response = new SamlLogoutResponseBuilder(issuer, requestId, sloEndpoint);
            return response.GetSignedRedirectUrl(sloEndpoint, echoedRelayState, signingKey);
        }
    }

    // The single uniform rejection for the inbound SAML logout endpoint: one fixed 400 body for every
    // rejection cause (feature off, unknown/disabled provider, bad signature, replay, unknown subject), so no
    // branch-distinguishing detail leaks to the caller. Plain text, mirroring LoginStatusMapper's Emit shape.
    private static ContentResult UniformLogoutRejection() => new ContentResult
    {
        Content = "SAML logout request could not be processed",
        ContentType = MediaTypeNames.Text.Plain,
        StatusCode = StatusCodes.Status400BadRequest,
    };

    /// <summary>
    /// Adds a SAML configuration. If the provider already exists, overwrite it.
    /// </summary>
    /// <param name="provider">The provider name to add.</param>
    /// <param name="newConfig">The SAML configuration object (deserialized) from JSON.</param>
    /// <returns>The success result.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SAML/Add/{provider}")]
    public OkResult SamlAdd(string provider, [FromBody] SamlConfig newConfig)
    {
        RejectNullProviderBody(newConfig);
        RejectInvalidBaseUrlOverride(newConfig.BaseUrlOverride);
        RejectInvalidSamlSloEndpoint(newConfig.SamlSloEndpoint);
        RejectInvalidSamlCertificate(newConfig.SamlCertificate);
        RejectInvalidSamlSecondaryCertificate(newConfig.SamlSecondaryCertificate);
        RejectInvalidSamlSigningKey(newConfig.SamlSigningKeyPfx);
        RejectInvalidSamlSigningKey(newConfig.SamlRolloverSigningKeyPfx);
        // Reject a malformed generic permission-role mapping (#164) at the door, as OidAdd does.
        ProviderConfigValidator.ValidatePermissionRoleMappings(SamlProtocol, provider, newConfig.PermissionRoleMappings);
        ProviderConfigValidator.ValidateParentalRatingMappings(SamlProtocol, provider, newConfig.ParentalRatingRoleMappings);
        SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            // The name guard needs the under-lock existence check (#336) and runs before any mutation,
            // so a throw leaves the live configuration untouched and nothing is persisted.
            var providerExists = configuration.SamlConfigs.TryGetValue(provider, out var existing);
            RejectInvalidNewProviderName(provider, providerExists);

            // Preserve the server-managed canonical links (#157), as OidAdd does, through the shared
            // ServerManagedFields.Preserve: the posted config never carries them ([JsonIgnore]), so
            // re-inject the live map before the wholesale replace so an API save cannot wipe links.
            if (providerExists)
            {
                ServerManagedFields.Preserve(newConfig, existing);
            }

            configuration.SamlConfigs[provider] = newConfig;
        });
        SsoAudit.ProviderConfigured(_logger, SamlProtocol, provider);

        // Mirror OidAdd (#140/#672): a SAML provider added with a default-on protection disabled
        // (DoNotValidateAudience) leaves the same auditable [SSO Audit] trace an OpenID escape hatch does.
        var insecure = SamlInsecureToggles.Enabled(newConfig);
        if (insecure.Count > 0)
        {
            SsoAudit.InsecureOptionsEnabled(_logger, SamlProtocol, provider, insecure);
        }

        return Ok();
    }

    /// <summary>
    /// Deletes a provider from the configuration with a given ID.
    /// </summary>
    /// <param name="provider">The ID of the provider to delete.</param>
    /// <returns>The success result.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SAML/Del/{provider}")]
    public OkResult SamlDel(string provider)
    {
        var removed = SSOPlugin.Instance.MutateConfiguration(configuration => configuration.SamlConfigs.Remove(provider));
        if (removed)
        {
            SsoAudit.ProviderRemoved(_logger, SamlProtocol, provider);
        }

        return Ok();
    }

    /// <summary>
    /// Returns a list of all SAML providers configured. Requires administrator privileges.
    /// </summary>
    /// <returns>A list of all of the Saml providers available.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SAML/Get")]
    public ActionResult SamlProviders()
    {
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => SnapshotConfigs(c.SamlConfigs)));
    }

    /// <summary>
    /// Tests basic config for a stored SAML provider (#163). Requires administrator privileges. Parses the
    /// configured PUBLIC identity-provider signing certificate and reports its non-secret facts — never the
    /// service-provider signing key. There is no SAML metadata-URL field, so this makes no network call.
    /// Elevation-gated like the other SAML admin endpoints.
    /// </summary>
    /// <param name="provider">The stored SAML provider to test.</param>
    /// <returns>The non-secret test result, or 404 when the provider is not configured.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SAML/Test/{provider}")]
    public ActionResult SamlTest(string provider)
    {
        var config = SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs.TryGetValue(provider, out var cfg) ? cfg : null);
        if (config is null)
        {
            return NotFound(NoMatchingProviderMessage);
        }

        return Ok(ProviderConnectionTester.TestSaml(config));
    }

    /// <summary>
    /// Parses SAML identity-provider metadata into the provider-configuration values an administrator would
    /// otherwise hand-copy — the SSO endpoint and the signing certificate(s) — from EITHER a server-fetched
    /// URL or pasted XML (#735). Requires administrator privileges and is deliberately elevation-gated: the
    /// server fetches an admin-supplied URL, so — like <see cref="OidTest"/> — an unauthenticated caller must
    /// not be able to drive it as an SSRF probe (the fetch also routes through the SSRF-hardened outbound
    /// client, which refuses a private/loopback address). The metadata XML is parsed with fail-closed
    /// hardening (no DTD/XXE, size-bounded). It RETURNS the parsed values for the admin to review and save; it
    /// applies nothing itself, and returns the IdP entityID for reference only (it is NOT the SP SamlClientId).
    /// The request body is size-capped and the endpoint is throttled after the elevation guard.
    /// </summary>
    /// <param name="request">Exactly one of a metadata URL or pasted metadata XML.</param>
    /// <returns>The parsed import values, or 400 when the input or metadata is invalid.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SAML/ImportMetadata")]
    [RequestSizeLimit(ConfigImportMaxBytes)]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> SamlImportMetadata([FromBody] SamlMetadataImportRequest request)
    {
        // Throttle after the elevation guard, before the outbound fetch (mirrors OidTest): the [Authorize]
        // filter rejects a non-elevated caller before the body runs, so an unauthorized request never reaches
        // the limiter or the fetch — no SSRF probe, no rate-limit oracle.
        if (RateLimitCheck(SsoRateLimitClass.Test) is { } throttled)
        {
            return throttled;
        }

        if (request is null)
        {
            return BadRequest("The metadata-import request is missing or is not valid JSON.");
        }

        try
        {
            var import = await SamlMetadataImporter.ImportAsync(_httpClientFactory, request.Url, request.Xml, HttpContext.RequestAborted).ConfigureAwait(false);
            return Ok(import);
        }
        catch (SamlMetadataException ex)
        {
            // The message is an admin-facing fixed string (no IdP/library detail); nothing was applied.
            return BadRequest(ex.Message);
        }
    }

    /// <summary>
    /// Exports the whole plugin configuration as a redacted, importable document (#161). Requires
    /// administrator privileges, like the other config endpoints — the document lists every provider's
    /// settings. The redaction is the config's OWN JSON-boundary withholding, reused: the provider secrets
    /// (OidSecret, the SAML signing keys) are serialized as null by their WriteOnlySecretConverter (#189) and
    /// the server-managed canonical-link maps are dropped by [JsonIgnore] (#157/#186), so the document carries
    /// no plaintext secret, no <c>ssoenc:</c> envelope, and no link map. The at-rest data-encryption key
    /// (sso-secret.key) lives in a separate file and is never part of the configuration object at all.
    /// </summary>
    /// <returns>The redacted export document.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Config/Export")]
    public ActionResult ExportConfig()
    {
        // Snapshot under the config lock; the JSON formatter redacts the secrets and links as it serializes
        // the returned document (the same withholding OID/Get relies on), after the lock is released.
        return Ok(SSOPlugin.Instance.ReadConfiguration(ConfigExport.Build));
    }

    /// <summary>
    /// Imports a configuration export document into this instance (#161). Requires administrator privileges.
    /// The import is a fail-closed MERGE: the document is validated through the same ProviderConfigValidator
    /// the config-page save uses, and only if the whole document is valid is it merged — atomically, through
    /// MutateConfiguration — reusing ServerManagedFields.Preserve so a redacted (blank) secret keeps this
    /// instance's stored secret and the server-managed links/issuers are never wiped. A provider new to this
    /// instance arrives with a blank secret and fails its login closed until an administrator re-enters it.
    /// The request body is size-capped so an oversized document is rejected before it is parsed.
    /// </summary>
    /// <param name="document">The export document to import.</param>
    /// <returns>No content on success, or 400 when the document is missing, unsupported, or invalid.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("Config/Import")]
    [RequestSizeLimit(ConfigImportMaxBytes)]
    [Consumes(MediaTypeNames.Application.Json)]
    public ActionResult ImportConfig([FromBody] ConfigExportDocument document)
    {
        if (document is null)
        {
            return BadRequest("The configuration import document is missing or is not valid JSON.");
        }

        try
        {
            // Validate-then-merge lives in the Config helper; the mutation persists only if it returns without
            // throwing (an invalid document throws inside the lambda, so MutateConfiguration persists nothing).
            // The break-glass resolver lets Apply run the SSO-only activation guard fail-closed on the import
            // path (#165, T-T2): a document asserting SSO-only with no surviving admin login path is rejected.
            SSOPlugin.Instance.MutateConfiguration(configuration => ConfigImport.Apply(configuration, document, _ssoOnly.DescribeBreakGlass));
        }
        catch (ArgumentException ex)
        {
            // The validator and the import throw ArgumentException for a hostile/malformed document (a bad
            // Base URL override, an unloadable certificate/key, a reserved-character provider name, an
            // unsupported version). Strip line endings from the echoed message so it cannot split a log line.
            return BadRequest(ex.Message?.ReplaceLineEndings(string.Empty));
        }

        // Audit the import and any provider that arrived with a security check disabled (#140), so importing
        // an escape hatch (DisableHttps, DoNotValidateIssuerName, …) leaves the same trace a form save would.
        var oidCount = document.Configuration?.OidConfigs?.Count ?? 0;
        var samlCount = document.Configuration?.SamlConfigs?.Count ?? 0;
        SsoAudit.ConfigImported(_logger, oidCount, samlCount);
        if (document.Configuration?.OidConfigs is { } oidConfigs)
        {
            foreach (var kvp in oidConfigs)
            {
                if (kvp.Value is null)
                {
                    continue;
                }

                var insecure = OidcInsecureToggles.Enabled(kvp.Value);
                if (insecure.Count > 0)
                {
                    SsoAudit.InsecureOptionsEnabled(_logger, OpenIdProtocol, kvp.Key, insecure);
                }
            }
        }

        // A mistaken or hostile import that disables a default-on SAML protection (DoNotValidateAudience)
        // must leave the same [SSO Audit] trace the OpenID escape hatches above do (#672) — the import path
        // is exactly one of the failure scenarios that issue calls out.
        if (document.Configuration?.SamlConfigs is { } samlConfigs)
        {
            foreach (var kvp in samlConfigs)
            {
                if (kvp.Value is null)
                {
                    continue;
                }

                var insecure = SamlInsecureToggles.Enabled(kvp.Value);
                if (insecure.Count > 0)
                {
                    SsoAudit.InsecureOptionsEnabled(_logger, SamlProtocol, kvp.Key, insecure);
                }
            }
        }

        return NoContent();
    }

    /// <summary>
    /// This endpoint accepts JSON and will authorize the user from the device values passed from the client.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    [HttpPost("SAML/Auth/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> SamlAuth(string provider, [FromBody] AuthResponse response)
    {
        if (RateLimitCheck(SsoRateLimitClass.Auth) is { } throttled)
        {
            return throttled;
        }

        // The SAML session-minting authenticate leg lives in the flow service (#160, #318): it redeems the
        // one-time login-outcome token the ACS callback minted (#251; since #528 the token is the only
        // accepted shape), correlates the carried InResponseTo to an AuthnRequest this server issued (browser
        // binding), and hands the already-verified identity to the shared completion tail. The controller
        // passes the presented binding cookie and the HttpContext-derived remote endpoint in, keeping the flow
        // tier HttpContext-free (#177).
        return await _saml.AuthenticateAsync(
            provider,
            response,
            Request.Cookies[AuthorizeStateBinding.SamlCookieName],
            () => HttpContext.GetNormalizedRemoteIP().ToString()).ConfigureAwait(false);
    }

    /// <summary>
    /// Removes a user from SSO auth and switches it back to another auth provider. Requires administrator privileges.
    /// </summary>
    /// <param name="username">The username to switch to the new provider.</param>
    /// <param name="provider">The new provider to switch to.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("Unregister/{username}")]
    public async Task<ActionResult> Unregister(string username, [FromBody] string provider)
    {
        // Throttle after the elevation guard, before any work (#516): the [Authorize] filter rejects a
        // non-elevated caller before the body runs, so an unauthorized request is refused (401/403) and never
        // reaches — or is judged by — the limiter (no rate-limit oracle). Once past it, the shared gate caps
        // how fast an authorized admin can drive this heavy revoke, which removes the user's canonical links
        // everywhere, persists a provider switch, and revokes the user's active sessions (#440). Its own
        // "unregister" class carries an independent budget, so it neither starves nor is starved by the
        // link/unlink write surface's "link" bucket (#382) or the anonymous login flows.
        if (RateLimitCheck(SsoRateLimitClass.Unregister) is { } throttled)
        {
            return throttled;
        }

        var user = _userManager.GetUserByName(username);
        if (user is null)
        {
            return NotFound();
        }

        // SSO login resolves through the per-provider CanonicalLinks maps, not AuthenticationProviderId,
        // so revoking SSO means removing this user's canonical links from every provider — otherwise the
        // account would still sign in via SSO (#213). Done under the config lock. NOTE: with a provider's
        // AllowExistingAccountLink enabled, the same-named account can be re-adopted on the next SSO login,
        // so a hard revoke there also needs the local account disabled or renamed; with the fail-closed
        // default (adoption off) the revoke is durable.
        var revoked = _canonicalLinks.RemoveUserEverywhere(user.Id);

        // Switch the account back to the requested auth provider and PERSIST it — the previous version set
        // this in memory only and never called UpdateUserAsync, so the switch was silently discarded.
        user.AuthenticationProviderId = provider;
        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        // Terminate the user's already-established sessions so a hard revoke also invalidates tokens minted
        // before it (#440). Removing the links only fails FUTURE logins closed; a token issued earlier stays
        // valid until it expires. Scoped strictly to this one user's id; null revokes all of their tokens
        // (including the caller's own, when an admin unregisters their own account — the durable revoke above
        // is why that is safe). Runs LAST, after the link removal and provider switch are both persisted, so
        // if the revoke throws the unregister is already complete rather than left half-done. Complement to
        // the #232 in-flight re-check, not a substitute: this kills existing sessions, #232 closes the mint race.
        await _sessionManager.RevokeUserTokens(user.Id, null).ConfigureAwait(false);

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation("Unregistered SSO for user {UserId}: removed {Count} canonical link(s) and revoked active tokens.", user.Id, revoked);
        }

        return Ok();
    }

    /// <summary>
    /// Reports the current SSO-only login state (#165): whether the mode is on, which account is the
    /// designated break-glass admin, and whether that designation still satisfies the fail-closed survivor
    /// guard. Requires administrator privileges. Read-only — it changes nothing.
    /// </summary>
    /// <returns>The SSO-only login status.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SSO-Only/Status")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult SsoOnlyStatus()
    {
        var (disablePasswordLogin, breakGlassAdmin) = SSOPlugin.Instance.ReadConfiguration(
            configuration => (configuration.DisablePasswordLogin, configuration.BreakGlassAdminUsername));

        // The guard is evaluated live against the current account state so the page can warn if the
        // break-glass admin was deleted, demoted, disabled, or lost its password after activation (T-D2).
        var guardSatisfied = SsoOnlyLoginGuard.Evaluate(breakGlassAdmin, _ssoOnly.DescribeBreakGlass(breakGlassAdmin))
            == SsoOnlyGuardVerdict.Allow;

        return Ok(new
        {
            DisablePasswordLogin = disablePasswordLogin,
            BreakGlassAdminUsername = breakGlassAdmin,
            GuardSatisfied = guardSatisfied,
        });
    }

    /// <summary>
    /// Turns SSO-only login on (#165), designating <paramref name="breakGlassAdminUsername"/> as the account
    /// whose native password login is never disabled. Requires administrator privileges. Fail-closed: the
    /// last-admin guard runs first, and unless the designated account is an existing, enabled administrator
    /// that still has a password, the activation is refused with a clear, non-enumerating message and nothing
    /// is changed. On success every non-exempt account is repointed off the password provider and the
    /// transition is audited.
    /// </summary>
    /// <param name="breakGlassAdminUsername">The administrator account to keep password-capable as the break-glass door.</param>
    /// <returns>Ok on activation, or 400 with the refusal reason when the guard rejects it.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SSO-Only/Enable")]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> EnableSsoOnly([FromBody] string breakGlassAdminUsername)
    {
        var actor = await ResolveActorAsync().ConfigureAwait(false);
        var outcome = await _ssoOnly.TryEnableAsync(breakGlassAdminUsername).ConfigureAwait(false);
        if (outcome.Verdict != SsoOnlyGuardVerdict.Allow)
        {
            // Fail closed: a blocked lockout attempt is audited (reason CODE only, no roster) and refused.
            SsoAudit.SsoOnlyLoginActivationRefused(_logger, actor, outcome.Verdict.ToString());
            return BadRequest(SsoOnlyLoginGuard.PublicRefusalMessage);
        }

        SsoAudit.SsoOnlyLoginEnabled(_logger, actor, outcome.BreakGlassAdmin, outcome.RepointedCount);
        return Ok();
    }

    /// <summary>
    /// Turns SSO-only login off (#165), the reversible no-SSO off-switch: it restores native password
    /// routing for every account the mode repointed, WITHOUT resetting or exposing any password. Requires
    /// administrator privileges. Audited on the transition.
    /// </summary>
    /// <returns>Ok once password routing is restored.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SSO-Only/Disable")]
    public async Task<ActionResult> DisableSsoOnly()
    {
        var actor = await ResolveActorAsync().ConfigureAwait(false);
        var restored = await _ssoOnly.DisableAsync().ConfigureAwait(false);
        SsoAudit.SsoOnlyLoginDisabled(_logger, actor, restored);
        return Ok();
    }

    /// <summary>
    /// Sets or changes the designated break-glass administrator (#165) — the account SSO-only mode never
    /// repoints. Requires administrator privileges. Fail-closed: the target must be an existing, enabled
    /// administrator that still has a password (the exemption can never point at a non-admin, so it cannot
    /// grant admin — T-E1); an unqualified target is refused and nothing changes. To change the designation
    /// while the mode is on, disable it first (every other admin has already been repointed off the password
    /// provider, so no other account can satisfy the "usable password" guard), then re-designate and re-enable.
    /// Audited.
    /// </summary>
    /// <param name="username">The administrator account to designate as the break-glass admin.</param>
    /// <returns>Ok on success, or 400 with the refusal reason when the target does not qualify.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SSO-Only/BreakGlassAdmin")]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> DesignateBreakGlassAdmin([FromBody] string username)
    {
        var actor = await ResolveActorAsync().ConfigureAwait(false);
        var outcome = _ssoOnly.TryDesignateBreakGlass(username);
        if (outcome.Verdict != SsoOnlyGuardVerdict.Allow)
        {
            SsoAudit.SsoOnlyLoginActivationRefused(_logger, actor, outcome.Verdict.ToString());
            return BadRequest(SsoOnlyLoginGuard.PublicRefusalMessage);
        }

        SsoAudit.BreakGlassAdminDesignated(_logger, actor, outcome.BreakGlassAdmin);
        return Ok();
    }

    // Resolves the elevated caller's own username for the audit "actor" field, fail-soft: every SSO-Only
    // endpoint sits behind [Authorize(RequiresElevation)], so the caller is an administrator, but an
    // unresolved authorization info still yields a non-null placeholder rather than throwing — the audit
    // line must never be the thing that fails a security-relevant transition.
    private async Task<string> ResolveActorAsync()
    {
        var auth = await _authContext.GetAuthorizationInfo(HttpContext.Request).ConfigureAwait(false);
        return auth?.User?.Username ?? "unknown";
    }

    /// <summary>
    /// Create a canonical link for a given user. Must be performed by the user being changed, or admin.
    /// </summary>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="provider">The name of the provider to link to a jellyfin account.</param>
    /// <param name="jellyfinUserId">The user ID within jellyfin to link to the provider.</param>
    /// <param name="authResponse">The client information to authenticate the user with.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize]
    [HttpPost("{mode}/Link/{provider}/{jellyfinUserId}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> AddCanonicalLink([FromRoute] string mode, [FromRoute] string provider, [FromRoute] Guid jellyfinUserId, [FromBody] AuthResponse authResponse)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "User is not allowed to link SSO providers.");
        }

        // Throttle after the caller-authz guard (#382): the 403 stays first so an unauthorized caller is
        // refused before the limiter is consulted (no rate-limit oracle), then the shared gate caps how fast
        // an authorized caller can drive the config-XML disk writes this write surface performs. "link" is a
        // distinct endpoint class, so its budget is independent of the anonymous login flows.
        if (RateLimitCheck(SsoRateLimitClass.Link) is { } throttled)
        {
            return throttled;
        }

        return ParseMode(mode) switch
        {
            ProviderMode.Saml => SamlLink(provider, jellyfinUserId, authResponse),
            ProviderMode.Oid => OidLink(provider, jellyfinUserId, authResponse),
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };
    }

    /// <summary>
    /// Unregisters a given mapping from id within provider to user.
    /// </summary>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="provider">The name of the provider from which the link should be removed.</param>
    /// <param name="jellyfinUserId">The user ID within jellyfin to unlink from the provider.</param>
    /// <param name="canonicalName">The provider-side canonical name (the identity's stable subject for OpenID, or the SAML NameID) whose link to the Jellyfin user should be removed.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize]
    [HttpDelete("{mode}/Link/{provider}/{jellyfinUserId}/{canonicalName}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> DeleteCanonicalLink([FromRoute] string mode, [FromRoute] string provider, [FromRoute] Guid jellyfinUserId, [FromRoute] string canonicalName)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Current user is not allowed to unlink SSO providers for user ID.");
        }

        // Throttle after the caller-authz guard (#382): a name-miss DELETE still runs a full persist under the
        // global config lock, so this endpoint is capped too. It shares the "link" budget with AddCanonicalLink
        // — one bucket per client for the whole link/unlink write surface — while the 403 stays first.
        if (RateLimitCheck(SsoRateLimitClass.Link) is { } throttled)
        {
            return throttled;
        }

        var removal = _canonicalLinks.TryRemoveLink(ParseMode(mode), provider, canonicalName, jellyfinUserId);

        // Terminate the user's already-issued tokens ONLY when this unlink removed their LAST canonical SSO
        // link (#468) — the terminal "can no longer SSO in at all" state that matches the hard-lockdown
        // posture of Unregister (#440). Removing the links only fails FUTURE logins closed; a token minted
        // before the unlink stays valid until it expires, so a security-motivated unlink of a compromised
        // identity must also kill live sessions. A user who unlinks a SECONDARY provider while still holding
        // another link keeps a working SSO identity, so revoking there would be a self-inflicted mass-logout
        // with no security gain — the availability-preserving choice is to revoke only at the last link
        // (UserRetainsAnyLink evaluated atomically with the removal). Scoped strictly to this one user id;
        // null revokes all of their tokens (including the caller's own, when an admin unlinks their own last
        // link — the durable removal above is why that is safe). Runs AFTER the removal is persisted, so a
        // revoke that throws leaves the unlink already complete rather than half-done. Per-provider disable
        // deliberately does NOT revoke: Jellyfin attributes no live session to the originating SSO provider
        // (RevokeUserTokens is per user id, not per provider), so revoking on disable would be an unscoped
        // mass-logout of every linked user's password and other-provider sessions too (#468).
        if (removal is { Result: CanonicalLinkRemoveResult.Removed, UserRetainsAnyLink: false })
        {
            await _sessionManager.RevokeUserTokens(jellyfinUserId, null).ConfigureAwait(false);
            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogInformation("Removed the last SSO link for user {UserId} and revoked their active tokens.", jellyfinUserId);
            }
        }

        return removal.Result switch
        {
            CanonicalLinkRemoveResult.Removed => Ok(),
            CanonicalLinkRemoveResult.NotFound => NotFound("No SSO link is registered for that canonical name."),
            CanonicalLinkRemoveResult.Mismatch => StatusCode(StatusCodes.Status409Conflict, "jellyfin UID does not match id registered to that canonical name."),
            CanonicalLinkRemoveResult.UnknownProvider => BadRequest(NoMatchingProviderMessage),
            _ => throw new InvalidOperationException($"Unhandled canonical-link remove result: {removal.Result}"),
        };
    }

    /// <summary>
    /// Gets all the saml links for a user.
    /// </summary>
    /// <param name="jellyfinUserId">The user ID within jellyfin for which to return the links.</param>
    /// <returns>A dictionary of provider : link mappings.</returns>
    [Authorize]
    [HttpGet("saml/links/{jellyfinUserId}")]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult<SerializableDictionary<string, IEnumerable<string>>>> GetSamlLinksByUser(Guid jellyfinUserId)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Non-admin is not allowed to query other user's mappings.");
        }

        return _canonicalLinks.LinksByUser(ProviderMode.Saml, jellyfinUserId);
    }

    /// <summary>
    /// Gets all the oid links for a user.
    /// </summary>
    /// <param name="jellyfinUserId">The user ID within jellyfin for which to return the links.</param>
    /// <returns>A dictionary of provider : link mappings.</returns>
    [Authorize]
    [HttpGet("oid/links/{jellyfinUserId}")]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult<SerializableDictionary<string, IEnumerable<string>>>> GetOidLinksByUser(Guid jellyfinUserId)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Non-admin is not allowed to query other user's mappings.");
        }

        return _canonicalLinks.LinksByUser(ProviderMode.Oid, jellyfinUserId);
    }

    // A shallow copy of a provider map, taken under the config lock so the admin list endpoints
    // serialize a detached snapshot rather than the live dictionary (#157/F-10): a concurrent
    // provider add/remove cannot then modify the collection mid-serialization. The provider objects
    // are shared, but their CanonicalLinks are [JsonIgnore] (never serialized), and the only other
    // in-place write on the hot path is the NewPath bool flipped by a challenge — a scalar write that
    // cannot tear a JSON serialization or throw "collection modified".
    private static SerializableDictionary<string, TValue> SnapshotConfigs<TValue>(SerializableDictionary<string, TValue> source)
    {
        var copy = new SerializableDictionary<string, TValue>();
        foreach (var kvp in source)
        {
            copy[kvp.Key] = kvp.Value;
        }

        return copy;
    }

    /// <summary>
    /// Validate a saml link request and create the link if it is valid.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="jellyfinUserId">
    ///   The ID of the account to be linked to the provider.
    ///   Must be performed by this user, or an admin.
    /// </param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    // The SAML manual-link redeem (validate the signed response, consume its one-time-use assertion id,
    // create the link on the NameID) lives on the flow service; the controller keeps the caller-authz
    // guard (AddCanonicalLink) and hands the request in (#160). The former [Consumes]/[Produces] on this
    // private helper were inert (AddCanonicalLink owns the content negotiation, #393).
    private ActionResult SamlLink(string provider, Guid jellyfinUserId, AuthResponse response) =>
        _saml.Link(provider, jellyfinUserId, response, Request);

    /// <summary>
    /// Validate an OIDC link request and create the link if it is valid.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="jellyfinUserId">
    ///   The ID of the account to be linked to the provider.
    ///   Must be performed by this user, or an admin.
    /// </param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    // The OID link redeem (which consumes the flow service's authorize state) lives on the flow service;
    // the controller keeps the caller-authz guard (AddCanonicalLink) and hands the binding cookie in. Both
    // flow services now map the write result through the shared FlowResponses home (#160). The former
    // [Consumes]/[Produces] were inert on this private helper (#393).
    private ActionResult OidLink(string provider, Guid jellyfinUserId, AuthResponse response) =>
        _oidc.Link(provider, jellyfinUserId, response, Request.Cookies[AuthorizeStateBinding.CookieName]);

    // Parse the {mode} route token once, at the HTTP boundary (#369): every link endpoint routes its raw
    // route string through here, so the protocol is validated in exactly one place and the typed
    // ProviderMode is threaded inward — no inner layer re-parses or re-compares the string. Fail closed: an
    // unknown token throws (an ArgumentException, surfacing as the same rejection the two former divergent
    // ToLower()/ToLowerInvariant() dispatches produced), never defaulting to a protocol.
    private static ProviderMode ParseMode(string mode) =>
        ProviderModeParser.TryParse(mode, out var parsed)
            ? parsed
            : throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'", nameof(mode));

    // Fronts a rate-limited endpoint with the shared per-client gate (#128, #160, #382, #516): null when the
    // request may proceed, else the throttled outcome the single mapper renders (#474). The anonymous login
    // endpoints pass their class (challenge/callback/auth); the authenticated link/unlink write surface passes
    // "link" after its own authz guard, and the admin SSO-revoke passes "unregister" after its elevation
    // guard. The gate owns the one process-wide limiter and the whole check (config read,
    // IP classifier, endpoint-class keying, the #195 observability signal); this wrapper only supplies the
    // three request-scoped inputs it needs — the endpoint class, the connection's remote address, and the
    // response the retry-delay header is set on — so the controller keeps no rate-limit state of its own.
    private ActionResult? RateLimitCheck(string endpointClass) =>
        SsoRateLimitGate.Check(endpointClass, HttpContext.Connection.RemoteIpAddress, _logger, Response);
}

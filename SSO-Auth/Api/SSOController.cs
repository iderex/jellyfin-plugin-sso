using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Mime;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using Jellyfin.Plugin.SSO_Auth.Helpers;
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

namespace Jellyfin.Plugin.SSO_Auth.Api;

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

    // The account-linking workflow (resolve/adopt/create, legacy re-key, revoke); the controller keeps
    // the authz guards, the one-time-use replay/state consume, and the HTTP mapping (#318).
    private readonly CanonicalLinkService _canonicalLinks;
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
        _canonicalLinks = new CanonicalLinkService(userManager, cryptoProvider, SSOPlugin.Instance.ConfigStore, logger);
        var avatarService = new AvatarService(userManager, providerManager, serverConfigurationManager, logger, SsoHttp.UserAgent);
        var sessionMinter = new SessionMinter(userManager, avatarService, sessionManager, logger);
        _loginCompletion = new LoginCompletionService(_canonicalLinks, sessionMinter, logger);
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
        if (RateLimitCheck("callback") is { } throttled)
        {
            return throttled;
        }

        // The OpenID redirect callback lives in the flow service (#160, #318): it validates the
        // browser-bound state, exchanges the code, validates the id_token and RFC 9207 response issuer,
        // applies the role gate, and renders the security-headered intermediate auth page on the response.
        return await _oidc.CallbackAsync(provider, state, Request, Response).ConfigureAwait(false);
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
        if (RateLimitCheck("challenge") is { } throttled)
        {
            return throttled;
        }

        // The OpenID challenge lives in the flow service (#160, #318): it reads discovery, applies the
        // PKCE gate, prepares the authorization request, registers the browser-bound authorize state, and
        // redirects to the identity provider (setting the binding cookie on the response).
        return await _oidc.ChallengeAsync(provider, isLinking, Request, Response).ConfigureAwait(false);
    }

    // Rejects a malformed canonical base-URL override (#139) at the OID/SAML Add endpoints. These persist
    // through MutateConfiguration, which passes the live configuration object, so they bypass the
    // config-page save-time validation in ProviderConfigStore.Save (which only runs for a fresh
    // incoming config). Without this, a malformed override set via the Add API would be persisted and then
    // silently fall back to the request Host at login. Throwing keeps it out of the store, so the
    // "rejected at every admin write path" invariant holds. Blank is valid (the feature is off).
    internal static void RejectInvalidBaseUrlOverride(string baseUrlOverride)
    {
        if (CanonicalBaseUrl.IsInvalidOverride(baseUrlOverride))
        {
            throw new ArgumentException("The Base URL override must be an absolute http(s) URL such as https://jellyfin.example.com, or left blank.");
        }
    }

    // Rejects a non-loadable SAML signing certificate at the SAML/Add endpoint (#206), which persists
    // through MutateConfiguration and so bypasses the config-page save-time validation in
    // ProviderConfigValidator.Validate. Without this, a garbage certificate set via the Add API would be
    // persisted and then throw a CryptographicException on every callback (an unhandled 500). Blank is
    // valid (a half-configured provider).
    internal static void RejectInvalidSamlCertificate(string certificateStr)
    {
        if (SamlCertificate.IsInvalid(certificateStr))
        {
            throw new ArgumentException("The SAML signing certificate must be a Base64-encoded (DER) X.509 certificate, or left blank.");
        }
    }

    // Rejects a non-loadable service-provider signing key at the SAML/Add endpoint (#167), the same
    // fail-closed door as the inbound certificate guard above: a garbage or private-key-less PKCS#12 set
    // here would persist and then fail every signed challenge. Blank is valid (signing simply stays off,
    // or the stored key is preserved on save).
    internal static void RejectInvalidSamlSigningKey(string signingKeyPfx)
    {
        if (SamlSigningKey.IsInvalid(signingKeyPfx))
        {
            throw new ArgumentException("The SAML request signing key must be a Base64-encoded, unencrypted PKCS#12 (PFX) blob containing an RSA or ECDSA private key, or left blank.");
        }
    }

    // Rejects a null provider body at the Add endpoints (#350). ASP.NET model binding hands a null
    // [FromBody] object for an empty or literal "null" JSON payload; storing it would put a null entry
    // in the config map that then NREs the config-page save (ServerManagedFields.Preserve). Reject at
    // the door so the store never holds a null provider — the same fail-closed posture as the other
    // Add-endpoint gates.
    internal static void RejectNullProviderBody(object config)
    {
        if (config is null)
        {
            throw new ArgumentException("The provider configuration body must not be empty.");
        }
    }

    // Rejects a provider name containing URI-reserved or control characters when it would register a NEW
    // provider (#336, #360): the name is appended raw to the callback URLs handed to the identity provider
    // (SsoUrlBuilder), so '%' breaks route decoding, '/' dead-ends the IdP redirect on a path no route
    // matches, control characters do not round-trip at all, and the other RFC 3986 delimiters invite
    // proxy/IdP misinterpretation. Updating an
    // EXISTING name stays allowed: its URL bytes are already registered at the IdP, and blocking the
    // update would strand the deployment behind a rename (encoding the built URLs instead is pinned
    // off by SsoUrlBuilderTests).
    internal static void RejectInvalidNewProviderName(string provider, bool providerExists)
    {
        if (!providerExists && ProviderNameValidator.IsInvalid(provider))
        {
            throw new ArgumentException("A new provider name must not contain control characters, a backslash, or any of % : / ? # [ ] @ ! $ & ' ( ) * + , ; = because the name becomes part of the callback URL registered with the identity provider.");
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
    /// Lists the names of the enabled OpenID providers only.
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
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => EnabledProviderNames(c.OidConfigs)));
    }

    /// <summary>
    /// Lists the names of the enabled SAML providers only.
    /// </summary>
    /// <returns>The list of enabled SAML provider names.</returns>
    [HttpGet("SAML/GetNames")]
    public ActionResult SamlProviderNames()
    {
        // Enabled-only and materialized under the lock, as OID/GetNames does (#344, #157/F-10).
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => EnabledProviderNames(c.SamlConfigs)));
    }

    // Names of the enabled providers in a config map, materialized to a detached list (the caller holds
    // the config lock). Shared by both GetNames twins so the enabled-only rule lives in one place.
    private static List<string> EnabledProviderNames<TConfig>(SerializableDictionary<string, TConfig> configs)
        where TConfig : ProviderConfigBase =>
        configs.Where(kvp => kvp.Value.Enabled).Select(kvp => kvp.Key).ToList();

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
        if (RateLimitCheck("auth") is { } throttled)
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
    public ActionResult SamlCallback(string provider, [FromQuery] string relayState = null, [FromForm(Name = "SAMLResponse")] string formSamlResponse = null)
    {
        if (RateLimitCheck("callback") is { } throttled)
        {
            return throttled;
        }

        // The SAML assertion-consumer callback lives in the flow service (#160, #318): it validates the
        // signed response and, on a passing role gate, renders the security-headered intermediate auth
        // page on the response.
        return _saml.Callback(provider, relayState, formSamlResponse, Request, Response);
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
        if (RateLimitCheck("challenge") is { } throttled)
        {
            return throttled;
        }

        // The SAML challenge lives in the flow service (#160, #318): it builds the AuthnRequest, binds it
        // to the initiating browser (setting the binding cookie on the response), signs it when the
        // provider opts in (#167), and redirects to the identity provider.
        return _saml.Challenge(provider, isLinking, Request, Response);
    }

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
        RejectInvalidSamlCertificate(newConfig.SamlCertificate);
        RejectInvalidSamlSigningKey(newConfig.SamlSigningKeyPfx);
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
        if (RateLimitCheck("auth") is { } throttled)
        {
            return throttled;
        }

        // The SAML session-minting authenticate leg lives in the flow service (#160, #318): it validates
        // the signed response, correlates it to an AuthnRequest this server issued (browser binding),
        // enforces the login allow-list and one-time replay consume, and hands the verified identity to the
        // shared completion tail. The controller passes the presented binding cookie and the
        // HttpContext-derived remote endpoint in, keeping the flow tier HttpContext-free (#177).
        return await _saml.AuthenticateAsync(
            provider,
            response,
            Request.Cookies[AuthorizeStateBinding.SamlCookieName],
            Request,
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
        if (RateLimitCheck("unregister") is { } throttled)
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

        _logger.LogInformation("Unregistered SSO for user {UserId}: removed {Count} canonical link(s) and revoked active tokens.", user.Id, revoked);

        return Ok();
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
        if (RateLimitCheck("link") is { } throttled)
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
        if (RateLimitCheck("link") is { } throttled)
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
            _logger.LogInformation("Removed the last SSO link for user {UserId} and revoked their active tokens.", jellyfinUserId);
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
            : throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'");

    // Fronts a rate-limited endpoint with the shared per-client gate (#128, #160, #382, #516): null when the
    // request may proceed, else the throttled outcome the single mapper renders (#474). The anonymous login
    // endpoints pass their class (challenge/callback/auth); the authenticated link/unlink write surface passes
    // "link" after its own authz guard, and the admin SSO-revoke passes "unregister" after its elevation
    // guard. The gate owns the one process-wide limiter and the whole check (config read,
    // IP classifier, endpoint-class keying, the #195 observability signal); this wrapper only supplies the
    // three request-scoped inputs it needs — the endpoint class, the connection's remote address, and the
    // response the retry-delay header is set on — so the controller keeps no rate-limit state of its own.
    private ActionResult RateLimitCheck(string endpointClass) =>
        SsoRateLimitGate.Check(endpointClass, HttpContext.Connection.RemoteIpAddress, _logger, Response);
}

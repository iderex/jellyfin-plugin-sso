using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
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
    // shared rate-limit gate below and delegate here. New'd per request like the other collaborators.
    private readonly Flows.OidcLoginService _oidc;

    // One-time-use tracking for consumed SAML assertion IDs (replay protection).
    private static readonly SamlReplayCache SamlReplays = new SamlReplayCache();

    // Outstanding SAML AuthnRequest IDs, for InResponseTo correlation of solicited responses (#156).
    private static readonly SamlRequestCache SamlRequests = new SamlRequestCache();

    // How long an issued SAML AuthnRequest ID stays valid for correlation — the interactive leg
    // (challenge -> IdP login/MFA -> POST back -> mint), matching the OpenID authorize-state lifetime the
    // flow service keeps.
    private static readonly TimeSpan SamlRequestLifetime = TimeSpan.FromMinutes(15);

    // Opt-in per-client rate limiter over the anonymous SSO flow endpoints (#128).
    private static readonly SsoRateLimiter RateLimiter = new SsoRateLimiter();

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
    public async Task<ActionResult> OidPost(
        [FromRoute] string provider,
        [FromQuery] string state) // Although this is a GET function, this function is called `Post` for consistency with SAML
    {
        if (RateLimitCheck("callback") is { } throttled)
        {
            return throttled;
        }

        // The OpenID redirect callback lives in the flow service (#160, #318): it validates the
        // browser-bound state, exchanges the code, validates the id_token and RFC 9207 response issuer,
        // applies the role gate, and renders the security-headered intermediate auth page (passed in).
        return await _oidc.CallbackAsync(provider, state, Request, HtmlAuthPage).ConfigureAwait(false);
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

    // Test-only: clears the outstanding-SAML-request cache so a prior test's seeded or in-flight entry
    // (e.g. one left behind by a signature-failing response that returns before the consume) cannot leak
    // into the next test. Same test-only surface as OidcLoginService.ResetOidStateForTests (internal,
    // InternalsVisibleTo).
    internal static void ResetSamlRequestsForTests() => SamlRequests.Clear();

    // Test-only seed of an outstanding SAML AuthnRequest so a test can exercise SamlAuth's browser
    // binding (#415) — normally populated by the SamlChallenge redirect leg — without deriving the
    // random request id from the emitted AuthnRequest. Same test-only surface as SeedOidStateForTests
    // (internal, InternalsVisibleTo, no endpoint/DI); never reachable in production.
    internal static void SeedSamlRequestForTests(string provider, string requestId, string bindingId, DateTime expiryUtc) =>
        SamlRequests.Register(ProviderScopedKey.For(provider, requestId), bindingId, expiryUtc, DateTime.UtcNow, clientKey: null, out _);

    // Reads a provider's config under the config lock, so an anonymous login-path lookup does not race an
    // admin Add/Del mutating the live provider dictionary in place — a Dictionary read-during-write is
    // undefined behaviour in .NET (throw, misread, or a spin on a corrupted chain during a resize) (#252).
    // Returns null for an unknown provider so call sites branch on a null check instead of catching
    // KeyNotFoundException as control flow (#241). An uncontended lock is nanoseconds; it is only held long
    // during a first-login/admin persist, which is exactly when a consistent read matters. (The OpenID twin
    // moved into the flow service with the OID flow, #160.)
    private static SamlConfig FindSamlConfig(string provider) =>
        SSOPlugin.Instance.ReadConfiguration(configuration => configuration.SamlConfigs.TryGetValue(provider, out var config) ? config : null);

    // Resolves whether this challenge uses the "new", more descriptive redirect path, and records that
    // as server-managed runtime state on the provider config. A non-linking challenge derives the
    // spelling from the request path (a `.../start/...` route means the new path) and stores it through
    // `record`, so a later linking flow — which cannot know which redirect path the identity provider
    // has registered — reuses the last login's spelling. A linking challenge only reads the stored
    // value and records nothing. `record` is passed because OidConfig and SamlConfig do not share a
    // base type. (See ExpectedAcsUrls for the same reason this value is remembered across requests.)
    private bool ResolveChallengeNewPath(bool currentNewPath, bool isLinking, Action<bool> record)
    {
        if (isLinking)
        {
            return currentNewPath;
        }

        var newPath = ChallengePath.IsNewPath(Request.Path.Value);
        record(newPath);
        return newPath;
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
            throw new ArgumentException("The SAML request signing key must be a Base64-encoded, unencrypted PKCS#12 (PFX) blob containing an RSA private key, or left blank.");
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
    /// Lists the OpenID providers names only.
    /// </summary>
    /// <returns>The list of OpenID configurations.</returns>
    [HttpGet("OID/GetNames")]
    public ActionResult OidProviderNames()
    {
        // Materialize the keys under the lock (#157/F-10): returning the live KeyCollection lets the
        // JSON formatter enumerate it outside the lock, tearing against a concurrent provider add/remove.
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.Keys.ToList()));
    }

    /// <summary>
    /// Lists the SAML providers names only.
    /// </summary>
    /// <returns>The list of SAML provider names.</returns>
    [HttpGet("SAML/GetNames")]
    public ActionResult SamlProviderNames()
    {
        // Materialize under the lock (#157/F-10), as OID/GetNames does.
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs.Keys.ToList()));
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
    public ActionResult SamlPost(string provider, [FromQuery] string relayState = null, [FromForm(Name = "SAMLResponse")] string formSamlResponse = null)
    {
        if (RateLimitCheck("callback") is { } throttled)
        {
            return throttled;
        }

        // Unknown and disabled providers share one rejection so neither can be probed apart — this
        // retires the unique "No active providers found" wording that distinguished the disabled case
        // (a disabled provider now short-circuits before the relayState log line).
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        bool isLinking = string.Equals(relayState, "linking", StringComparison.Ordinal);

        // relayState is attacker-controllable; strip line endings inline at the log call to prevent
        // log forging (structured logging alone does not sanitize a newline-bearing value).
        _logger.LogInformation(
            "SAML request has relayState of {RelayState}",
            relayState?.ReplaceLineEndings(string.Empty));

        // Bind SAMLResponse via [FromForm] rather than reading Request.Form directly: a non-form
        // content-type binds null (the form value provider is skipped, so Request.Form is never
        // touched and cannot throw the InvalidOperationException that escaped as a 500, #206), and a
        // null body is rejected the same way as any other malformed response — a clean 400.
        if (!SamlResponseLoader.TryParse(config.SamlCertificate, formSamlResponse, out var samlResponse)
            || !IsSamlResponseValid(samlResponse, config, provider))
        {
            // A malformed response (non-base64, malformed XML, prohibited DOCTYPE) fails TryLoad and
            // is rejected the same way an invalid one is — a clean 4xx, never an unhandled 500 (#199).
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        if (SamlLoginPolicy.IsLoginAllowed(samlResponse.GetCustomAttributes("Role"), config.Roles))
        {
            return HtmlAuthPage(nonce =>
                WebResponse.Generator(
                    data: Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(samlResponse.Xml)),
                    provider: provider,
                    baseUrl: GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride),
                    mode: "SAML",
                    nonce: nonce,
                    isLinking: isLinking));
        }

        _logger.LogWarning(
            "SAML user: {UserId} has insufficient roles: {@Roles}. Expected any one of: {@ExpectedRoles}",
            samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty),
            samlResponse.GetCustomAttributes("Role").Select(r => r?.ReplaceLineEndings(string.Empty)),
            config.Roles);
        return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
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

        // Unknown and disabled providers share one rejection so neither can be probed apart, and the
        // answer no longer depends on host middleware mapping a thrown ArgumentException (#318).
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        bool newPath = ResolveChallengeNewPath(config.NewPath, isLinking, value => config.NewPath = value);

        string redirectUri = SsoUrlBuilder.SamlAcsUrl(GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride), newPath, provider);
        string relayState = null;
        if (isLinking)
        {
            relayState = "linking";
        }

        var request = new SamlAuthnRequest(
            config.SamlClientId.Trim(),
            redirectUri);

        // Bind this login to the initiating browser (#415): mint a binding id, set it as a cookie, and
        // record it against the request id so the session-mint endpoint (SamlAuth) can require the
        // response's browser to be the one that started the flow — closing the SP-initiated forced-login
        // / session-fixation vector, the SAML analogue of #326. Only for login flows: the linking
        // callback (SamlLink) is a separate flow that does not consume the outstanding request, so a
        // linking registration would only leave an id to expire unused. Registration now happens for
        // every login challenge (not only under ValidateInResponseTo), so the binding is enforced for
        // every SOLICITED login this plugin initiated — the case ValidateInResponseTo alone left open.
        // It does NOT bind an unsolicited (IdP-initiated) response, which carries no matching request;
        // fully closing forced login for an IdP that issues unsolicited responses additionally requires
        // ValidateInResponseTo (which refuses them). Because the cookie is __Host-/Secure, the browser
        // only returns it over HTTPS — SP-initiated SAML now needs HTTPS at the browser edge, as OIDC
        // already does.
        if (!isLinking)
        {
            var bindingId = AuthorizeStateBinding.NewId();

            // The client key bounds how much of the request cache one source can occupy (#327); a
            // proxy/private source normalizes to null and is exempt.
            var clientKey = SsoRateLimiter.NormalizeClientKey(HttpContext.Connection.RemoteIpAddress);
            if (!SamlRequests.Register(
                    ProviderScopedKey.For(provider, request.Id),
                    bindingId,
                    DateTime.UtcNow + SamlRequestLifetime,
                    DateTime.UtcNow,
                    clientKey,
                    out var shouldWarnCapacity))
            {
                // The per-client sub-cap or the global cap refused this login's outstanding-request
                // entry (#327). Fail closed HERE rather than redirect to the IdP for a login that could
                // then only be refused at the callback (no correlation entry). The store throttles the
                // capacity warning to one signal per interval so a flood cannot amplify into log volume
                // (CWE-400) — parity with the OpenID challenge refusal.
                if (shouldWarnCapacity)
                {
                    _logger.LogWarning("SAML request refused for provider {Provider}: the per-client sub-cap or the outstanding-request cache is at capacity (warning throttled).", provider?.ReplaceLineEndings(string.Empty));
                }

                return ReturnError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
            }

            Response.Cookies.Append(
                AuthorizeStateBinding.SamlCookieName,
                bindingId,
                AuthorizeStateBinding.CookieOptions(SamlRequestLifetime));
        }

        string redirectUrl;
        try
        {
            redirectUrl = BuildChallengeRedirectUrl(config, request, relayState);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or CryptographicException)
        {
            // Signing is enabled for this provider but the request could not be signed: the key is
            // missing/unusable (InvalidOperationException), the endpoint is empty (ArgumentException from
            // the signer), or the platform key store refused the signing operation (CryptographicException).
            // ANY of these fails closed with a clean 500 — never a silent unsigned request — rather than
            // escaping as a raw host 500. The key material is not part of the message, so nothing sensitive
            // is logged.
            _logger.LogError("SAML challenge for provider {Provider} could not sign the AuthnRequest: {Reason}", provider?.ReplaceLineEndings(string.Empty), ex.Message);
            return ReturnError(StatusCodes.Status500InternalServerError, "Could not start login; the SAML request signing key is misconfigured.");
        }

        return Redirect(redirectUrl);
    }

    // Builds the redirect URL to the identity provider, signing the outgoing AuthnRequest when the provider
    // opts in (#167). Fail-closed: signing enabled but the signing key missing/unloadable throws, so the
    // caller returns an error rather than silently sending an unsigned request — an operator who turned
    // signing on never gets a silent downgrade. Default off is byte-for-byte the previous unsigned URL.
    private static string BuildChallengeRedirectUrl(SamlConfig config, SamlAuthnRequest request, string relayState)
    {
        var endpoint = config.SamlEndpoint.Trim();
        if (!config.SignAuthnRequests)
        {
            return request.GetRedirectUrl(endpoint, relayState);
        }

        if (!SamlSigningKey.TryLoad(config.SamlSigningKeyPfx, out var signingCertificate))
        {
            throw new InvalidOperationException("Outgoing SAML request signing is enabled but the signing key could not be loaded.");
        }

        using (signingCertificate)
        using (var signingKey = signingCertificate.GetRSAPrivateKey())
        {
            if (signingKey is null)
            {
                throw new InvalidOperationException("Outgoing SAML request signing is enabled but the signing key has no RSA private key.");
            }

            return request.GetSignedRedirectUrl(endpoint, relayState, signingKey);
        }
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

        // Unknown and disabled providers share one rejection so neither can be probed apart — this
        // unifies the previously JSON unknown-provider body and the disabled provider's 500.
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        if (!SamlResponseLoader.TryParse(config.SamlCertificate, response?.Data, out var samlResponse)
            || !IsSamlResponseValid(samlResponse, config, provider))
        {
            // Malformed input is rejected the same way an invalid response is — clean 4xx, not 500 (#199).
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // Correlate the response to an AuthnRequest this server issued (#156, #415), and enforce the
        // browser binding for a solicited login. A NON-EMPTY InResponseTo means the response claims to
        // answer a request this server issued, so it must actually correlate to a live outstanding
        // request AND carry that request's binding cookie — anything less fails closed. Crucially, a
        // non-empty InResponseTo whose entry is gone (expired past the 15-minute window, evicted at the
        // cap, lost to a restart or a non-sticky multi-node hop) is a LOST correlation, not an
        // unsolicited response: treating it as unsolicited would let a signature-valid response mint a
        // session with no binding check when ValidateInResponseTo is off, which is exactly the
        // forced-login bypass the binding exists to close (login validity must never default to true).
        //
        // The binding is checked AFTER the atomic claim (unlike the OpenID state, #326) and that is safe:
        // the response already passed signature validation above and the InResponseTo is read from that
        // validated document, so an attacker cannot mint a signature-valid response carrying a victim's
        // request id to burn their outstanding entry. The cookie is checked here (the same-origin auth
        // endpoint), not at the cross-site ACS POST which would not carry a SameSite=Lax cookie.
        var inResponseTo = samlResponse.GetInResponseTo();
        if (!string.IsNullOrEmpty(inResponseTo))
        {
            var requestKey = ProviderScopedKey.For(provider, inResponseTo);
            if (!SamlRequests.TryConsume(requestKey, DateTime.UtcNow, out var storedBindingId)
                || !AuthorizeStateBinding.Matches(storedBindingId, Request.Cookies[AuthorizeStateBinding.SamlCookieName]))
            {
                _logger.LogWarning("SAML login denied: a solicited response did not correlate to a live outstanding request from the initiating browser (binding mismatch, expiry, or lost correlation).");
                return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
            }
        }
        else if (config.ValidateInResponseTo)
        {
            // No InResponseTo at all: a genuinely unsolicited (IdP-initiated) response. It is refused
            // only when the opt-in solicited-only mode is on; otherwise it proceeds — unchanged and
            // non-breaking for IdP-initiated deployments. The rejection is a client-caused 400 in the
            // uniform SAML body, never a 500, and the diagnosis stays in the warning log.
            _logger.LogWarning("SAML login denied: the response was not solicited by this server (no InResponseTo).");
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // Enforce the login allow-list here too, not only at the assertion-consumer page: a caller
        // can POST an assertion straight to this session-minting endpoint and skip the page, so
        // checking it only there would be fail-open.
        if (!SamlLoginPolicy.IsLoginAllowed(samlResponse.GetCustomAttributes("Role"), config.Roles))
        {
            _logger.LogWarning(
                "SAML user: {UserId} has insufficient roles at the session-minting endpoint; login denied.",
                samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty));
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
        }

        // Enforce one-time use so a captured assertion cannot be replayed to mint another session.
        // Enforced only here (the session-minting endpoint), not at the SAML/post ACS which merely
        // renders the intermediate page, so the two-step post-then-auth flow consumes the id once. A
        // replay is a client-caused 400 in the uniform SAML body — it no longer discloses the replay
        // cache to the attacker who replayed, and the log-side diagnosis is unchanged.
        if (!TryConsumeSamlReplay(samlResponse, provider))
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // Derive the authorize-state privileges (admin, Live TV, Live TV management, folders) from
        // the assertion's roles and the provider configuration. Login validity was already decided
        // above by SamlLoginPolicy and the username is the assertion's NameID, so neither is derived
        // here.
        var derived = SamlAuthorizeStateBuilder.Build(samlResponse.GetCustomAttributes("Role"), config);

        // Fail closed (#95): an assertion without a usable NameID carries no identity to log in —
        // reject it as an invalid login instead of failing downstream on a null canonical name.
        // Whitespace-only counts as unresolved (Jellyfin's username validation rejects it anyway).
        var nameId = samlResponse.GetNameID();
        if (string.IsNullOrWhiteSpace(nameId))
        {
            _logger.LogWarning("SAML login denied: the assertion resolved no NameID.");
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
        }

        // All SAML validation has now passed — signature, time bounds, audience, recipient, InResponseTo
        // correlation, the login allow-list, replay one-time-use, and the non-empty-NameID guard — so this
        // is the point at which the response becomes a fully-verified SAML identity (#473). SAML keys the
        // link directly on the NameID (subject and username are the same value; no migration path needed)
        // and carries no email_verified claim, so the verified-email gate is not applicable
        // (AdoptionGate.None); the resolver's unconditional admin-adoption refusal (#218) still applies.
        // From here the SAML and OpenID paths are one.
        return await _loginCompletion.CompleteAsync(
            VerifiedIdentity.FromValidatedSaml(provider, nameId, derived),
            response,
            config,
            AdoptionGate.None,
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

        switch (mode.ToLower())
        {
            case "saml":
                return SamlLink(provider, jellyfinUserId, authResponse);
            case "oid":
                return OidLink(provider, jellyfinUserId, authResponse);
            default:
                throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'");
        }
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

        var removeResult = _canonicalLinks.TryRemoveLink(mode, provider, canonicalName, jellyfinUserId);
        return removeResult switch
        {
            CanonicalLinkRemoveResult.Removed => Ok(),
            CanonicalLinkRemoveResult.NotFound => NotFound("No SSO link is registered for that canonical name."),
            CanonicalLinkRemoveResult.Mismatch => StatusCode(StatusCodes.Status409Conflict, "jellyfin UID does not match id registered to that canonical name."),
            CanonicalLinkRemoveResult.UnknownProvider => BadRequest(NoMatchingProviderMessage),
            _ => throw new InvalidOperationException($"Unhandled canonical-link remove result: {removeResult}"),
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

        return _canonicalLinks.LinksByUser("saml", jellyfinUserId);
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

        return _canonicalLinks.LinksByUser("oid", jellyfinUserId);
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
    // No [Consumes]/[Produces]: ASP.NET Core honors content-negotiation filters only on public action
    // methods, and this is a private helper invoked directly from AddCanonicalLink, which carries its
    // own. The attributes were inert metadata here (#393).
    private ActionResult SamlLink(string provider, Guid jellyfinUserId, AuthResponse response)
    {
        // A disabled provider must neither create a link nor consume the assertion's one-time-use ID
        // (#343): an administrator disabling a provider takes effect immediately for linking, and the
        // unknown and disabled cases share one response so neither can be probed apart.
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        if (!SamlResponseLoader.TryParse(config.SamlCertificate, response?.Data, out var samlResponse)
            || !IsSamlResponseValid(samlResponse, config, provider))
        {
            // Malformed input is rejected the same way an invalid response is — clean 4xx, not 500 (#199).
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // Enforce one-time use here too (#219): without it, a captured, still-valid assertion could be
        // replayed to bind its NameID to the caller's account. The linking flow issues no AuthnRequest,
        // so InResponseTo is not correlated here — the replay cache is the applicable one-time-use
        // control. A replay is a client-caused 400 in the uniform SAML body, never a 500, and no longer
        // discloses the replay cache to the attacker who replayed.
        if (!TryConsumeSamlReplay(samlResponse, provider))
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        string providerUserId = samlResponse.GetNameID();

        return MapWrite(_canonicalLinks.TryCreateLink("saml", provider, providerUserId, jellyfinUserId));
    }

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
    // No [Consumes]/[Produces]: inert on a private helper (see SamlLink) — AddCanonicalLink owns the
    // content negotiation (#393). The OID link redeem (which consumes the flow service's authorize state)
    // lives on the flow service; the controller keeps the caller-authz guard (AddCanonicalLink) and the
    // write-result-to-HTTP mapping it shares with SamlLink (#160).
    private ActionResult OidLink(string provider, Guid jellyfinUserId, AuthResponse response) =>
        _oidc.Link(provider, jellyfinUserId, response, Request.Cookies[AuthorizeStateBinding.CookieName], MapWrite);

    // The HTTP boundary for a manual link creation: maps the service's closed write result to a response.
    // The empty-key and unknown-provider refusals keep distinct bodies (the service checks the empty key
    // first), and an unhandled result throws rather than silently returning a wrong status.
    private ActionResult MapWrite(CanonicalLinkWriteResult result) => result switch
    {
        CanonicalLinkWriteResult.Created => NoContent(),
        CanonicalLinkWriteResult.EmptyKey => BadRequest("The SSO login did not resolve an identity."),
        CanonicalLinkWriteResult.UnknownProvider => BadRequest(NoMatchingProviderMessage),
        _ => throw new InvalidOperationException($"Unhandled canonical-link write result: {result}"),
    };

    // Applies the opt-in per-client rate limit (#128) on an anonymous flow endpoint: null when the
    // request may proceed, else the throttled outcome rendered by the single mapper (#474). Reads the
    // settings under the config lock; an unattributable or non-public client is never throttled (fail
    // open, availability over throttling). Keys on RemoteIpAddress only — proxy attribution is the
    // host's job (Jellyfin's "Known proxies" setting resolves the real client into it); see
    // SsoRateLimiter.NormalizeClientKey. The endpoint class (challenge/callback/auth) is part of
    // the key so one login — which hits all three — gets the full budget at each stage rather
    // than a third of it, keeping the default generous for shared egress addresses (NAT/CGNAT).
    private ActionResult RateLimitCheck(string endpointClass)
    {
        var (enabled, maxAttempts, windowSeconds) = SSOPlugin.Instance.ReadConfiguration(
            c => (c.EnableRateLimit, c.RateLimitMaxAttempts, c.RateLimitWindowSeconds));
        if (!enabled || windowSeconds < 1)
        {
            // maxAttempts < 1 is handled inside IsAllowed (it disables the limiter there).
            return null;
        }

        var key = SsoRateLimiter.NormalizeClientKey(HttpContext.Connection.RemoteIpAddress);
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
            _logger.LogWarning("SSO rate limit engaged on the anonymous login endpoints: {Count} request(s) throttled since the last notice; further notices are suppressed for at least a minute.", throttledCount);
        }

        // The rejection is expressed as a LoginOutcome and rendered by the single mapper (#474): the
        // status, plain-text body and the retry-delay header all originate there, so the controller no
        // longer emits a bare rate-limit ContentResult or sets the delay header itself.
        return LoginStatusMapper.ToActionResult(new LoginOutcome.Throttled(retryAfterSeconds), Response);
    }

    // Consumes the SAML assertion's ID against the provider-scoped replay cache for one-time use.
    // Returns false when the assertion was already used (or carries no ID — a missing ID stays empty,
    // so TryConsume fails closed). The key is scoped by provider so two IdPs emitting the same assertion
    // ID cannot block each other. Shared by SamlAuth (session mint) and SamlLink (account linking, #219).
    private bool TryConsumeSamlReplay(SamlResponse samlResponse, string provider)
    {
        var samlNow = DateTime.UtcNow;
        var replayRetention = SamlReplayCache.ComputeRetention(samlNow, samlResponse.GetNotOnOrAfter());
        var assertionId = samlResponse.GetAssertionId();
        var replayKey = ProviderScopedKey.For(provider, assertionId);
        return SamlReplays.TryConsume(replayKey, replayRetention, samlNow);
    }

    // Validates the SAML response and, on failure, logs the declared signature algorithm plus the
    // weak-algorithm remediation hint. This lets an operator tell a rejected SHA-1 signature - the
    // expected post-upgrade lockout of a legacy IdP - apart from a bad certificate, an expired
    // assertion, or an audience mismatch, all of which otherwise surface as the same opaque error.
    private bool IsSamlResponseValid(SamlResponse samlResponse, SamlConfig config, string provider)
    {
        if (!ValidateSaml(samlResponse, config))
        {
            // The algorithm URI is identity-provider-controlled; strip line endings inline at the log
            // call to prevent log forging (a helper-boundary sanitizer is not recognized by CodeQL).
            _logger.LogWarning(
                "SAML response validation failed (signature algorithm: {Algorithm}). SHA-1 is rejected; if that is the identity provider's algorithm, reconfigure it to sign with RSA/ECDSA-SHA-256 or stronger.",
                samlResponse.GetSignatureAlgorithm()?.ReplaceLineEndings(string.Empty));
            return false;
        }

        // Endpoint binding (#156, opt-in): the signed assertion must be addressed to this service
        // provider's assertion-consumer URL, so an assertion minted for a different endpoint (or a
        // different SP sharing the identity provider) cannot be presented here.
        if (config.ValidateRecipient
            && !SamlRecipientValidator.IsBound(samlResponse.GetRecipient(), samlResponse.GetDestination(), ExpectedAcsUrls(config, provider)))
        {
            _logger.LogWarning("SAML response rejected: the assertion Recipient or Response Destination does not match this server's assertion-consumer URL.");
            return false;
        }

        return true;
    }

    // The assertion-consumer URLs this service provider advertises for the provider — the same value
    // SamlChallenge puts in the AuthnRequest's AssertionConsumerServiceURL, so a signed Recipient (or
    // Destination) must equal one. Both the new ("post") and legacy ("p") path spellings are returned:
    // config.NewPath is process-wide mutable state a concurrent challenge can flip, and the Recipient
    // reflects whichever the AuthnRequest advertised at challenge time, so accepting either avoids
    // rejecting a valid login on a path-form flip; both are this provider's own ACS URLs.
    //
    // The host comes from GetRequestBase. With BaseUrlOverride set (#139) it is the pinned canonical
    // host, so this binding is exact regardless of the request Host. Without it the host is the request
    // Host, so the binding is only as strong as host resolution: behind a reverse proxy, configure
    // Jellyfin's Known/Trusted Proxies (or set BaseUrlOverride) so the Host cannot be spoofed, or an
    // attacker controlling the Host can make the expected URL match a captured assertion's Recipient
    // (defense-in-depth, not a hard guarantee).
    private string[] ExpectedAcsUrls(SamlConfig config, string provider) =>
        SsoUrlBuilder.SamlExpectedAcsUrls(GetRequestBase(config.SchemeOverride, config.PortOverride, config.BaseUrlOverride), provider);

    // Validates a SAML response: signature + time bounds always, plus AudienceRestriction binding to
    // this SP unless explicitly opted out. Expected audience is the configured SamlAudience, falling
    // back to the SamlClientId (SP entity id). Both are trimmed so the comparison matches the trimmed
    // Issuer sent in the AuthnRequest, and an empty SamlAudience falls through to the client id.
    internal static bool ValidateSaml(SamlResponse samlResponse, SamlConfig config)
    {
        if (config.DoNotValidateAudience)
        {
            return samlResponse.IsValid();
        }

        var expected = config.SamlAudience?.Trim();
        if (string.IsNullOrEmpty(expected))
        {
            expected = config.SamlClientId?.Trim();
        }

        return samlResponse.IsValid(expected);
    }

    // Thin wrapper feeding the live request values into the pure CanonicalBaseUrl.Resolve decision (#242).
    private string GetRequestBase(string schemeOverride = null, int? portOverride = null, string baseUrlOverride = null) =>
        CanonicalBaseUrl.Resolve(baseUrlOverride, Request.Scheme, Request.Host.Host, Request.Host.Port, Request.PathBase, schemeOverride, portOverride);

    private static ContentResult ReturnError(int code, string message)
    {
        var errorResult = new ContentResult();
        errorResult.Content = message;
        errorResult.ContentType = MediaTypeNames.Text.Plain;
        errorResult.StatusCode = code;
        return errorResult;
    }

    // Returns the rendered auth page as HTML with defensive response headers. The page carries the
    // one-time state token / signed assertion and completes the login from an inline script, so it
    // must not be framed (clickjacking), MIME-sniffed, cached, or leak its URL via Referer. A strict
    // Content-Security-Policy locks it to a single nonce'd inline script and style and same-origin
    // fetch/frame; the same per-response nonce is threaded into the rendered page via the delegate.
    private ContentResult HtmlAuthPage(Func<string, string> render)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        Response.Headers.ContentSecurityPolicy = AuthPageCsp.Build(nonce);
        Response.Headers["X-Frame-Options"] = "DENY";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers.CacheControl = "no-store";
        return Content(render(nonce), MediaTypeNames.Text.Html);
    }
}

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Mime;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;
using Jellyfin.Plugin.SSO_Auth.Helpers;
using MediaBrowser.Common.Api;
using MediaBrowser.Controller.Authentication;
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
    // Client-facing error messages: unresolved provider names, and the generic denial for any
    // rejected login (deliberately uniform so the response does not reveal why it was rejected).
    private const string NoMatchingProviderMessage = "No matching provider found";
    private const string ProviderDoesNotExistMessage = "Provider does not exist";
    private const string PermissionDeniedMessage = "Error. Check permissions.";

    // Display names for the audit log (the internal link-map mode tokens are the lowercase "oid"/"saml").
    private const string OpenIdProtocol = "OpenID";
    private const string SamlProtocol = "SAML";

    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly IAuthorizationContext _authContext;
    private readonly ILogger<SSOController> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly IProviderManager _providerManager;
    private readonly IServerConfigurationManager _serverConfigurationManager;
    private readonly IHttpClientFactory _httpClientFactory;
    // Concurrent requests add to, enumerate, and prune this map (OidChallenge / OidAuth /
    // OidLink / Invalidate); a plain Dictionary corrupts or throws under that interleaving.
    private static readonly ConcurrentDictionary<string, TimedAuthorizeState> StateManager = new ConcurrentDictionary<string, TimedAuthorizeState>();

    // How long an in-flight OpenID authorize state may live before it is rejected/pruned. This now
    // bounds the whole interactive leg (OidChallenge -> IdP login/MFA/consent -> callback -> mint),
    // so it must accommodate a real user completing MFA, not just a fast round trip.
    private static readonly TimeSpan StateLifetime = TimeSpan.FromMinutes(15);

    // One-time-use tracking for consumed SAML assertion IDs (replay protection).
    private static readonly SamlReplayCache SamlReplays = new SamlReplayCache();

    // Single canonical User-Agent for the plugin's outbound HTTP (discovery, avatar fetch),
    // computed once since the assembly version does not change at runtime.
    private static readonly string UserAgentString =
        $"Jellyfin-Plugin-SSO-Auth +{System.Diagnostics.FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).FileVersion} (https://github.com/iderex/jellyfin-plugin-sso)";

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
        _sessionManager = sessionManager;
        _userManager = userManager;
        _authContext = authContext;
        _cryptoProvider = cryptoProvider;
        _logger = logger;
        _loggerFactory = loggerFactory;
        _providerManager = providerManager;
        _serverConfigurationManager = serverConfigurationManager;
        _httpClientFactory = httpClientFactory;
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
        OidConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.OidConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        if (config.Enabled)
        {
            if (string.IsNullOrEmpty(state))
            {
                return BadRequest("Missing state");
            }

            if (!StateManager.TryGetValue(state, out var timedState)
                || !AuthStateStore.IsCurrentFor(timedState, provider, DateTime.Now, StateLifetime))
            {
                // Unknown, expired, or minted for a different provider — reject so a state issued
                // for one provider cannot be validated on another's callback. (No removal: the value
                // is an unguessable CSPRNG token, and expiry pruning is handled by the sweep.)
                return BadRequest("Invalid or expired state");
            }

            var oidcClient = CreateCallbackOidcClient(config, provider);
            var currentState = timedState.State;
            var result = await oidcClient.ProcessResponseAsync(Request.QueryString.Value, currentState).ConfigureAwait(false);

            if (result.IsError)
            {
                return ReturnError(StatusCodes.Status400BadRequest, $"Error logging in: {result.Error} - {result.ErrorDescription}");
            }

            // Derive the authorize-state values (username, validity, admin, Live TV, folders, avatar)
            // from the verified login's claims and the provider configuration, then apply them to the
            // fresh authorize state (its derivation fields are still at their defaults at this point).
            var derived = OidcAuthorizeStateBuilder.Build(result.User.Claims, config);

            // Fail closed (#155): a valid OpenID login must resolve a stable subject to key the account
            // link on. sub is an OIDC Core MUST and (post-#134) the id_token validator has verified the
            // token, so a missing sub means a non-conformant provider — reject rather than fall back to
            // keying on the mutable username.
            if (derived.Valid && string.IsNullOrWhiteSpace(derived.Subject))
            {
                _logger.LogWarning("OpenID login denied for provider {Provider}: the id_token carried no 'sub' claim to key the account link on.", provider?.ReplaceLineEndings(string.Empty));
                return ReturnError(StatusCodes.Status401Unauthorized, PermissionDeniedMessage);
            }

            timedState.Username = derived.Username;
            timedState.Subject = derived.Subject;
            timedState.Valid = derived.Valid;
            timedState.Admin = derived.Admin;
            timedState.EnableLiveTv = derived.EnableLiveTv;
            timedState.EnableLiveTvManagement = derived.EnableLiveTvManagement;
            timedState.Folders = derived.Folders;
            timedState.AvatarURL = derived.AvatarUrl;

            bool isLinking = timedState.IsLinking;

            if (timedState.Valid)
            {
                _logger.LogInformation("Is request linking: {IsLinking}", isLinking);
                return HtmlAuthPage(WebResponse.Generator(data: state, provider: provider, baseUrl: GetRequestBase(config.SchemeOverride, config.PortOverride), mode: "OID", isLinking: isLinking));
            }
            else
            {
                _logger.LogWarning(
                    "OpenID login denied for {Username}: no role matched the allow-list, or the login resolved no username. Claims: {@Claims}. Roles expected (any one of): {@ExpectedClaims}",
                    timedState.Username?.ReplaceLineEndings(string.Empty),
                    result.User.Claims.Select(o => new { Type = o.Type?.ReplaceLineEndings(string.Empty), Value = o.Value?.ReplaceLineEndings(string.Empty) }),
                    config.Roles);

                return ReturnError(StatusCodes.Status401Unauthorized, PermissionDeniedMessage);
            }
        }

        // If the config doesn't have an active provider matching the request, show an error
        return BadRequest(NoMatchingProviderMessage);
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
        Invalidate();
        OidConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.OidConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            throw new ArgumentException(ProviderDoesNotExistMessage);
        }

        if (config.Enabled)
        {
            bool newPath = config.NewPath;
            if (!isLinking)
            {
                newPath = Request.Path.Value.Contains("/start/", StringComparison.InvariantCultureIgnoreCase);
                config.NewPath = newPath;
            }

            string redirectUri = GetRequestBase(config.SchemeOverride, config.PortOverride) + $"/sso/OID/{(newPath ? "redirect" : "r")}/" + provider;

            var oidcClient = CreateOidcClient(config, redirectUri, string.Join(" ", config.OidScopes.Prepend("openid profile")));
            var state = await oidcClient.PrepareLoginAsync().ConfigureAwait(false);

            if (state.IsError)
            {
                return ReturnError(StatusCodes.Status400BadRequest, $"Error preparing login: {state.Error} - {state.ErrorDescription}");
            }

            // IsLinking tracks whether this is a linking request rather than a login. The state value
            // is a fresh CSPRNG token, so a collision is effectively impossible; log if it ever occurs
            // instead of silently proceeding to a callback that would then fail with "invalid state".
            if (!StateManager.TryAdd(state.State, new TimedAuthorizeState(state, DateTime.Now) { IsLinking = isLinking, Provider = provider }))
            {
                _logger.LogWarning("OpenID authorize-state collision for provider {Provider}; login not started.", provider?.ReplaceLineEndings(string.Empty));
                return ReturnError(StatusCodes.Status500InternalServerError, "Could not start login due to a state collision; please retry.");
            }

            return Redirect(state.StartUrl);
        }

        throw new ArgumentException(ProviderDoesNotExistMessage);
    }

    // Builds the OidcClient that both the challenge and the callback use. Pure mechanical assembly:
    // the redirect URI and the scope string are the only two inputs the endpoints derive differently,
    // so the caller supplies them. Constructed in the same order as before the extraction, so a null
    // OidEndpoint still fails at the same point (the Uri constructor, after the options object).
    private OidcClient CreateOidcClient(OidConfig config, string redirectUri, string scope)
    {
        var options = new OidcClientOptions
        {
            Authority = config.OidEndpoint?.Trim(),
            ClientId = config.OidClientId?.Trim(),
            ClientSecret = config.OidSecret?.Trim(),
            RedirectUri = redirectUri,
            Scope = scope,
            DisablePushedAuthorization = config.DisablePushedAuthorization,
            LoggerFactory = _loggerFactory,
            LoadProfile = !config.DoNotLoadProfile,
            HttpClientFactory = o =>
            {
                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgentString);
                return client;
            }
        };
        var oidEndpointUri = new Uri(config.OidEndpoint?.Trim());
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(oidEndpointUri.GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.ValidateEndpoints = !config.DoNotValidateEndpoints; // For Google and other providers with different endpoints
        options.Policy.Discovery.RequireHttps = !config.DisableHttps;
        options.Policy.Discovery.ValidateIssuerName = !config.DoNotValidateIssuerName;

        // OidcClient 7.x validates nothing about the id_token unless a validator is supplied (its
        // fallback only base64-decodes the payload). Signature validation is required and has no
        // config toggle: an unvalidated id_token is a forgeable login (#134).
        options.Policy.RequireIdentityTokenSignature = true;
        options.IdentityTokenValidator = new OidcIdTokenValidator();
        return new OidcClient(options);
    }

    // Callback-side client: the redirect URI is rebuilt from the callback's own route (the IdP calls
    // back on exactly the route the authorization request advertised), so the token request's
    // redirect_uri matches the authorization request's as RFC 6749 requires (#98). A null scopes
    // array is tolerated here but not on the challenge side — a pre-existing asymmetry deliberately
    // preserved.
    private OidcClient CreateCallbackOidcClient(OidConfig config, string provider)
    {
        var scopes = config.OidScopes == null ? new string[2] : config.OidScopes;
        var redirectUri = GetRequestBase(config.SchemeOverride, config.PortOverride) + $"/sso/OID/{OidcCallbackPath.RedirectSegment(Request.Path.Value)}/" + provider;
        return CreateOidcClient(config, redirectUri, string.Join(" ", scopes.Prepend("openid profile")));
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
        SSOPlugin.Instance.MutateConfiguration(configuration => configuration.OidConfigs[provider] = config);
        SsoAudit.ProviderConfigured(_logger, OpenIdProtocol, provider);
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
        return Ok(SSOPlugin.Instance.Configuration.OidConfigs);
    }

    /// <summary>
    /// Lists the OpenID providers names only.
    /// </summary>
    /// <returns>The list of OpenID configurations.</returns>
    [HttpGet("OID/GetNames")]
    public ActionResult OidProviderNames()
    {
        return Ok(SSOPlugin.Instance.Configuration.OidConfigs.Keys);
    }

    /// <summary>
    /// Lists the SAML providers names only.
    /// </summary>
    /// <returns>The list of OpenID configurations.</returns>
    [HttpGet("SAML/GetNames")]
    public ActionResult SamlProviderNames()
    {
        return Ok(SSOPlugin.Instance.Configuration.SamlConfigs.Keys);
    }

    /// <summary>
    /// This is a debug endpoint to list all running OpenID flows. Requires administrator privileges.
    /// </summary>
    /// <returns>The list of OpenID flows in progress.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/States")]
    public ActionResult OidStates()
    {
        // Project to a non-secret summary. The raw store holds the authorize-state token and the
        // PKCE code_verifier / nonce; those must never be serialized out, even to an admin.
        var summary = StateManager.Values.Select(s => new
        {
            s.Provider,
            s.Created,
            s.Valid,
            s.IsLinking,
        });
        return Ok(summary);
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
        if (string.IsNullOrEmpty(response?.Data))
        {
            return BadRequest("Missing data");
        }

        OidConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.OidConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        // The store is keyed by the authorize-state token, which is exactly response.Data, so look it
        // up directly (O(1), no full-store scan) and atomically claim it with TryRemove(KeyValuePair):
        // only the request that wins the removal proceeds, so one state mints at most one session even
        // under concurrent posts.
        if (config.Enabled
            && StateManager.TryGetValue(response.Data, out var timedState)
            && AuthStateStore.IsRedeemableBy(timedState, response.Data, provider, DateTime.Now, StateLifetime)
            && StateManager.TryRemove(new KeyValuePair<string, TimedAuthorizeState>(response.Data, timedState)))
        {
            Guid userId;
            try
            {
                userId = await CreateCanonicalLinkAndUserIfNotExist("oid", provider, timedState.Subject, timedState.Username, config.AllowExistingAccountLink).ConfigureAwait(false);
            }
            catch (AccountLinkForbiddenException)
            {
                return StatusCode(StatusCodes.Status403Forbidden, "SSO login is not permitted for this account.");
            }

            var authenticationResult = await Authenticate(new SessionParameters
            {
                UserId = userId,
                IsAdmin = timedState.Admin,
                EnableAuthorization = config.EnableAuthorization,
                EnableAllFolders = config.EnableAllFolders,
                EnabledFolders = timedState.Folders.ToArray(),
                EnableLiveTv = timedState.EnableLiveTv,
                EnableLiveTvManagement = timedState.EnableLiveTvManagement,
                AuthResponse = response,
                DefaultProvider = config.DefaultProvider?.Trim(),
                AvatarUrl = timedState.AvatarURL,
            }).ConfigureAwait(false);
            SsoAudit.LoginSucceeded(_logger, OpenIdProtocol, provider, timedState.Username, timedState.Admin);
            return Ok(authenticationResult);
        }

        return Problem("Something went wrong");
    }

    /// <summary>
    /// This is the callback for the SAML flow. This creates a webpage to complete auth.
    /// </summary>
    /// <param name="provider">The provider that is calling back.</param>
    /// <param name="relayState">
    ///    RelayState given in the original saml request. If it is equal to "linking",
    ///    We consider this to be a linking request.
    /// </param>
    /// <returns>A webpage that will complete the client-side flow.</returns>
    [HttpPost("SAML/p/{provider}")]
    [HttpPost("SAML/post/{provider}")]
    public ActionResult SamlPost(string provider, [FromQuery] string relayState = null)
    {
        SamlConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.SamlConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        bool isLinking = string.Equals(relayState, "linking", StringComparison.Ordinal);

        // relayState is attacker-controllable; strip line endings inline at the log call to prevent
        // log forging (structured logging alone does not sanitize a newline-bearing value).
        _logger.LogInformation(
            "SAML request has relayState of {RelayState}",
            relayState?.ReplaceLineEndings(string.Empty));

        if (config.Enabled)
        {
            var samlResponse = new Response(config.SamlCertificate, Request.Form["SAMLResponse"]);

            if (!IsSamlResponseValid(samlResponse, config))
            {
                return Problem("SAML response validation failed");
            }

            if (SamlLoginPolicy.IsLoginAllowed(samlResponse.GetCustomAttributes("Role"), config.Roles))
            {
                return HtmlAuthPage(
                    WebResponse.Generator(
                        data: Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(samlResponse.Xml)),
                        provider: provider,
                        baseUrl: GetRequestBase(config.SchemeOverride, config.PortOverride),
                        mode: "SAML",
                        isLinking: isLinking));
            }

            _logger.LogWarning(
                "SAML user: {UserId} has insufficient roles: {@Roles}. Expected any one of: {@ExpectedRoles}",
                samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty),
                samlResponse.GetCustomAttributes("Role").Select(r => r?.ReplaceLineEndings(string.Empty)),
                config.Roles);
            return ReturnError(StatusCodes.Status401Unauthorized, PermissionDeniedMessage);
        }

        return ReturnError(StatusCodes.Status400BadRequest, "No active providers found");
    }

    /// <summary>
    /// Initializes the SAML flow. This will redirect the user to the SAML provider.
    /// </summary>
    /// <param name="provider">The provider to being the flow with.</param>
    /// <param name="isLinking">Whether this flow intends to link an account, or initiate auth.</param>
    /// <returns>A redirect to the SAML provider's auth page.</returns>
    [HttpGet("SAML/p/{provider}")]
    [HttpGet("SAML/start/{provider}")]
    public RedirectResult SamlChallenge(string provider, [FromQuery] bool isLinking = false)
    {
        SamlConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.SamlConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            throw new ArgumentException(ProviderDoesNotExistMessage);
        }

        if (config.Enabled)
        {
            bool newPath = config.NewPath;
            if (!isLinking)
            {
                newPath = Request.Path.Value.Contains("/start/", StringComparison.InvariantCultureIgnoreCase);
                config.NewPath = newPath;
            }

            string redirectUri = GetRequestBase(config.SchemeOverride, config.PortOverride) + $"/sso/SAML/{(newPath ? "post" : "p")}/" + provider;
            string relayState = null;
            if (isLinking)
            {
                relayState = "linking";
            }

            var request = new AuthRequest(
                config.SamlClientId.Trim(),
                redirectUri);

            return Redirect(request.GetRedirectUrl(config.SamlEndpoint.Trim(), relayState));
        }

        throw new ArgumentException(ProviderDoesNotExistMessage);
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
        SSOPlugin.Instance.MutateConfiguration(configuration => configuration.SamlConfigs[provider] = newConfig);
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
        return Ok(SSOPlugin.Instance.Configuration.SamlConfigs);
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
        SamlConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.SamlConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        if (config.Enabled)
        {
            var samlResponse = new Response(config.SamlCertificate, response.Data);

            if (!IsSamlResponseValid(samlResponse, config))
            {
                return Problem("SAML response validation failed");
            }

            // Enforce the login allow-list here too, not only at the assertion-consumer page: a caller
            // can POST an assertion straight to this session-minting endpoint and skip the page, so
            // checking it only there would be fail-open.
            if (!SamlLoginPolicy.IsLoginAllowed(samlResponse.GetCustomAttributes("Role"), config.Roles))
            {
                _logger.LogWarning(
                    "SAML user: {UserId} has insufficient roles at the session-minting endpoint; login denied.",
                    samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty));
                return ReturnError(StatusCodes.Status401Unauthorized, PermissionDeniedMessage);
            }

            // Enforce one-time use so a captured assertion cannot be replayed to mint another session.
            // Enforced only here (the session-minting endpoint), not at the SAML/post ACS which merely
            // renders the intermediate page, so the two-step post-then-auth flow consumes the id once.
            var samlNow = DateTime.UtcNow;
            var replayRetention = SamlReplayCache.ComputeRetention(samlNow, samlResponse.GetNotOnOrAfter());

            // Scope the replay key by provider so two IdPs that happen to emit the same assertion ID
            // cannot block each other; a missing ID stays empty so TryConsume still fails closed.
            var assertionId = samlResponse.GetAssertionId();
            var replayKey = string.IsNullOrEmpty(assertionId) ? assertionId : provider + "\n" + assertionId;
            if (!SamlReplays.TryConsume(replayKey, replayRetention, samlNow))
            {
                return Problem("SAML assertion has already been used");
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
                return ReturnError(StatusCodes.Status401Unauthorized, PermissionDeniedMessage);
            }

            Guid userId;
            try
            {
                // SAML keys the link directly on the NameID, which is already the stable subject
                // identifier — key and account name are the same value (no migration path needed).
                userId = await CreateCanonicalLinkAndUserIfNotExist("saml", provider, nameId, nameId, config.AllowExistingAccountLink).ConfigureAwait(false);
            }
            catch (AccountLinkForbiddenException)
            {
                return StatusCode(StatusCodes.Status403Forbidden, "SSO login is not permitted for this account.");
            }

            var authenticationResult = await Authenticate(new SessionParameters
            {
                UserId = userId,
                IsAdmin = derived.Admin,
                EnableAuthorization = config.EnableAuthorization,
                EnableAllFolders = config.EnableAllFolders,
                EnabledFolders = derived.Folders.ToArray(),
                EnableLiveTv = derived.EnableLiveTv,
                EnableLiveTvManagement = derived.EnableLiveTvManagement,
                AuthResponse = response,
                DefaultProvider = config.DefaultProvider?.Trim(),
                AvatarUrl = null,
            }).ConfigureAwait(false);
            SsoAudit.LoginSucceeded(_logger, SamlProtocol, provider, nameId, derived.Admin);
            return Ok(authenticationResult);
        }

        return Problem("Something went wrong");
    }

    /// <summary>
    /// Removes a user from SSO auth and switches it back to another auth provider. Requires administrator privileges.
    /// </summary>
    /// <param name="username">The username to switch to the new provider.</param>
    /// <param name="provider">The new provider to switch to.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("Unregister/{username}")]
    public ActionResult Unregister(string username, [FromBody] string provider)
    {
        User user = _userManager.GetUserByName(username);
        user.AuthenticationProviderId = provider;

        return Ok();
    }

    // Applies a mutation to a provider's canonical-links map on the LIVE configuration, reassigning the
    // map so a lazily-created (previously-null) one is persisted. Runs inside MutateConfiguration, so the
    // whole read-modify-write is serialized and concurrent first-logins cannot lose each other's links.
    private static void MutateLinks(PluginConfiguration configuration, string mode, string provider, Action<SerializableDictionary<string, Guid>> mutate)
    {
        switch (mode.ToLowerInvariant())
        {
            case "saml":
            {
                var providerConfig = configuration.SamlConfigs[provider];
                var links = providerConfig.CanonicalLinks;
                mutate(links);
                providerConfig.CanonicalLinks = links;
                break;
            }

            case "oid":
            {
                var providerConfig = configuration.OidConfigs[provider];
                var links = providerConfig.CanonicalLinks;
                mutate(links);
                providerConfig.CanonicalLinks = links;
                break;
            }

            default:
                throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'");
        }
    }

    // The provider's canonical-links map; callers must hold the config lock (ReadConfiguration /
    // MutateConfiguration) while touching it.
    private static SerializableDictionary<string, Guid> GetLinks(PluginConfiguration configuration, string mode, string provider)
    {
        return mode.ToLowerInvariant() switch
        {
            "saml" => configuration.SamlConfigs[provider].CanonicalLinks,
            "oid" => configuration.OidConfigs[provider].CanonicalLinks,
            _ => throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'"),
        };
    }

    private async Task<Guid> CreateCanonicalLinkAndUserIfNotExist(string mode, string provider, string canonicalKey, string username, bool allowExistingAccountLink)
    {
        // Defense in depth (#95, #155): a login that resolved no stable identity key (OpenID sub /
        // SAML NameID) or no username must never create, adopt, or look up an account. Both callbacks
        // reject such logins before calling here; this belt keeps the invariant if a caller forgets.
        if (string.IsNullOrWhiteSpace(canonicalKey) || string.IsNullOrWhiteSpace(username))
        {
            throw new AccountLinkForbiddenException("The SSO login did not resolve an identity; refusing to create or link an account.");
        }

        // The link is keyed on the stable identity. A legacy OpenID link (#155) was keyed on the
        // mutable username instead; when no subject-keyed link exists yet but a legacy one resolves,
        // adopt and re-key it — the one login that migrates reuses the exact decision the old
        // name-keyed lookup would have made, then locks it to the subject so a later provider-side
        // rename cannot detach it. Only OpenID differs key from name; SAML passes key == name.
        // Both candidates are read in ONE pass under the config lock: with separate reads, a
        // concurrent login's migration could commit between them, so this login would see the subject
        // key before the re-key and the legacy key after it, resolve neither, and bounce a legitimate
        // user off the adoption gate with a spurious 403. A link whose target user was deleted counts
        // as absent (dangling links are dead, not identities).
        var (subjectLink, legacyLink) = SSOPlugin.Instance.ReadConfiguration(configuration =>
        {
            var links = GetLinks(configuration, mode, provider);
            Guid? bySubject = links.TryGetValue(canonicalKey, out var s) && _userManager.GetUserById(s) != null
                ? s : null;
            Guid? byName = bySubject is null
                && !string.Equals(canonicalKey, username, StringComparison.Ordinal)
                && links.TryGetValue(username, out var n) && _userManager.GetUserById(n) != null
                ? n : (Guid?)null;
            return (bySubject, byName);
        });

        var (linkedUserId, migrateLegacy) = AccountLinkResolver.ResolveCanonicalLink(subjectLink, legacyLink);
        if (migrateLegacy)
        {
            MigrateCanonicalLinkKey(mode, provider, username, canonicalKey);
            _logger.LogInformation(
                "Migrated {Mode}/{Provider} canonical link from the legacy username key to the stable subject key.",
                mode,
                provider?.ReplaceLineEndings(string.Empty));
        }

        // Adoption of a pre-existing unlinked account still matches on the display name.
        Guid? existingAccountUserId = _userManager.GetUserByName(username)?.Id;

        var decision = AccountLinkResolver.Resolve(linkedUserId, existingAccountUserId, allowExistingAccountLink);
        switch (decision.Action)
        {
            case AccountLinkAction.UseExistingLink:
                return decision.UserId;

            case AccountLinkAction.AdoptExistingAccount:
                CreateCanonicalLink(mode, provider, decision.UserId, canonicalKey);
                SsoAudit.AccountAdopted(_logger, string.Equals(mode, "oid", StringComparison.Ordinal) ? OpenIdProtocol : SamlProtocol, provider, username);
                return decision.UserId;

            case AccountLinkAction.CreateNewAccount:
                _logger.LogInformation("SSO user {Name} doesn't exist, creating...", username.ReplaceLineEndings(string.Empty));
                var user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
                user.AuthenticationProviderId = GetType().FullName;
                // https://jonathancrozier.com/blog/how-to-generate-a-cryptographically-secure-random-string-in-dot-net-with-c-sharp
                user.Password = _cryptoProvider.CreatePasswordHash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))).ToString();
                CreateCanonicalLink(mode, provider, user.Id, canonicalKey);
                return user.Id;

            case AccountLinkAction.RejectNameTaken:
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: a pre-existing unlinked Jellyfin account exists and AllowExistingAccountLink is disabled for this provider.",
                    username.ReplaceLineEndings(string.Empty),
                    mode,
                    provider?.ReplaceLineEndings(string.Empty));
                throw new AccountLinkForbiddenException();

            default:
                throw new InvalidOperationException($"Unhandled account-link action: {decision.Action}");
        }
    }

    // Re-keys a canonical link from oldKey to newKey inside the config lock (#155 legacy migration).
    // Idempotent under concurrency: if oldKey is already gone (a concurrent login migrated first) the
    // move is a no-op, and a LIVE newKey entry is never overwritten — only a dangling one (its target
    // user deleted), which would otherwise block the hand-off on every subsequent login.
    private void MigrateCanonicalLinkKey(string mode, string provider, string oldKey, string newKey)
    {
        SSOPlugin.Instance.MutateConfiguration(configuration =>
            MutateLinks(configuration, mode, provider, links =>
            {
                if (links.TryGetValue(oldKey, out var userId)
                    && (!links.TryGetValue(newKey, out var existing) || _userManager.GetUserById(existing) == null))
                {
                    links.Remove(oldKey);
                    links[newKey] = userId;
                }
            }));
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
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId, true).ConfigureAwait(false))
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
    /// <param name="canonicalName">The user ID within jellyfin to unlink.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize]
    [HttpDelete("{mode}/Link/{provider}/{jellyfinUserId}/{canonicalName}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> DeleteCanonicalLink([FromRoute] string mode, [FromRoute] string provider, [FromRoute] Guid jellyfinUserId, [FromRoute] string canonicalName)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId, true).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Current user is not allowed to unlink SSO providers for user ID.");
        }

        var mismatch = false;
        var found = false;
        try
        {
            SSOPlugin.Instance.MutateConfiguration(configuration => MutateLinks(configuration, mode, provider, links =>
            {
                if (!links.TryGetValue(canonicalName, out var linkedId))
                {
                    return;
                }

                found = true;
                if (linkedId != jellyfinUserId)
                {
                    mismatch = true;
                    return;
                }

                links.Remove(canonicalName);
            }));
        }
        catch (KeyNotFoundException)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        if (!found)
        {
            return NotFound("No SSO link is registered for that canonical name.");
        }

        if (mismatch)
        {
            return StatusCode(StatusCodes.Status409Conflict, "jellyfin UID does not match id registered to that canonical name.");
        }

        return Ok();
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
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId, true).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Non-admin is not allowed to query other user's mappings.");
        }

        var mappings = new SerializableDictionary<string, IEnumerable<string>>();
        var providerList = SSOPlugin.Instance.Configuration.SamlConfigs;

        foreach (var providerName in providerList.Keys)
        {
            var canonLinks = providerList[providerName].CanonicalLinks;
            var canonKeys = from link in canonLinks where link.Value == jellyfinUserId select link.Key;
            mappings[providerName] = canonKeys;
        }

        return mappings;
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
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId, true).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Non-admin is not allowed to query other user's mappings.");
        }

        var mappings = new SerializableDictionary<string, IEnumerable<string>>();
        var providerList = SSOPlugin.Instance.Configuration.OidConfigs;

        foreach (var providerName in providerList.Keys)
        {
            var canonLinks = providerList[providerName].CanonicalLinks;
            var canonKeys = from link in canonLinks where link.Value == jellyfinUserId select link.Key;
            mappings[providerName] = canonKeys;
        }

        return mappings;
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
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    private ActionResult SamlLink(string provider, Guid jellyfinUserId, AuthResponse response)
    {
        SamlConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.SamlConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        var samlResponse = new Response(config.SamlCertificate, response.Data);

        if (!IsSamlResponseValid(samlResponse, config))
        {
            return Problem("SAML response validation failed");
        }

        string providerUserId = samlResponse.GetNameID();

        return CreateCanonicalLink("saml", provider, jellyfinUserId, providerUserId);
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
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    private ActionResult OidLink(string provider, Guid jellyfinUserId, AuthResponse response)
    {
        if (string.IsNullOrEmpty(response?.Data))
        {
            return BadRequest("Missing data");
        }

        try
        {
            // Touch the indexer only to verify the provider exists; it throws if it does not.
            _ = SSOPlugin.Instance.Configuration.OidConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        // Keyed O(1) lookup + atomic claim (see OidAuth): consume the state so one verified identity
        // cannot be linked repeatedly and cannot then be reused to mint a session.
        if (StateManager.TryGetValue(response.Data, out var timedState)
            && AuthStateStore.IsRedeemableBy(timedState, response.Data, provider, DateTime.Now, StateLifetime)
            && StateManager.TryRemove(new KeyValuePair<string, TimedAuthorizeState>(response.Data, timedState)))
        {
            // Manual linking keys on the stable subject (#155), matching the auto-login path, so a
            // later provider-side rename does not orphan the link the user just created.
            return CreateCanonicalLink("oid", provider, jellyfinUserId, timedState.Subject);
        }

        return Problem("Something went wrong!");
    }

    private ActionResult CreateCanonicalLink(string mode, string provider, Guid jellyfinUserId, string providerUserId)
    {
        // Fail closed (#95), linking-side choke point: an SSO identity that did not resolve must not
        // create a link — a null key would throw inside the config mutation (500), and an empty or
        // whitespace key would persist a dead link no login can ever redeem.
        if (string.IsNullOrWhiteSpace(providerUserId))
        {
            return BadRequest("The SSO login did not resolve an identity.");
        }

        try
        {
            SSOPlugin.Instance.MutateConfiguration(configuration =>
                MutateLinks(configuration, mode, provider, links => links[providerUserId] = jellyfinUserId));
        }
        catch (KeyNotFoundException)
        {
            return BadRequest(NoMatchingProviderMessage);
        }

        return NoContent();
    }

    /// <summary>
    /// Mints a Jellyfin session for a resolved SSO login: applies the granted permissions and the
    /// optional avatar/default-provider updates to the user, then authenticates the client.
    /// </summary>
    /// <param name="parameters">The resolved user, granted privileges, and client identity.</param>
    private async Task<AuthenticationResult> Authenticate(SessionParameters parameters)
    {
        User user = _userManager.GetUserById(parameters.UserId);
        if (user is null)
        {
            // Fail closed: the account resolved for this SSO login no longer exists (e.g. it was
            // deleted between resolution and this call), so no session may be minted for it.
            throw new AuthenticationException("SSO authentication aborted: the target user does not exist.");
        }

        if (parameters.EnableAuthorization)
        {
            user.SetPermission(PermissionKind.IsAdministrator, parameters.IsAdmin);
            user.SetPermission(PermissionKind.EnableAllFolders, parameters.EnableAllFolders);
            if (!parameters.EnableAllFolders)
            {
                user.SetPreference(PreferenceKind.EnabledFolders, parameters.EnabledFolders);
            }
        }

        await TrySetUserAvatarAsync(user, parameters.AvatarUrl).ConfigureAwait(false);

        user.SetPermission(PermissionKind.EnableLiveTvAccess, parameters.EnableLiveTv);
        user.SetPermission(PermissionKind.EnableLiveTvManagement, parameters.EnableLiveTvManagement);

        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        var authRequest = new AuthenticationRequest();
        authRequest.UserId = user.Id;
        authRequest.Username = user.Username;
        authRequest.App = parameters.AuthResponse.AppName;
        authRequest.AppVersion = parameters.AuthResponse.AppVersion;
        authRequest.DeviceId = parameters.AuthResponse.DeviceID;
        authRequest.DeviceName = parameters.AuthResponse.DeviceName;
        _logger.LogInformation("Auth request created...");
        if (!string.IsNullOrEmpty(parameters.DefaultProvider))
        {
            user.AuthenticationProviderId = parameters.DefaultProvider;
            await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
            _logger.LogInformation("Set default login provider to {DefaultProvider}", parameters.DefaultProvider);
        }

        return await _sessionManager.AuthenticateDirect(authRequest).ConfigureAwait(false);
    }

    // Fetches the avatar and sets it as the user's profile image. Best-effort by design: any fetch or
    // save failure is logged and the login proceeds without the avatar; only the URL guard and the
    // SSRF-safe transport are security-relevant, and they fail closed (no fetch).
    private async Task TrySetUserAvatarAsync(User user, string avatarUrl)
    {
        if (avatarUrl is null)
        {
            return;
        }

        if (!AvatarUrlValidator.IsAllowedUrl(avatarUrl, out var avatarUri))
        {
            _logger.LogWarning("Refusing to fetch avatar from disallowed URL: {AvatarUrl}", avatarUrl.ReplaceLineEndings(string.Empty));
            return;
        }

        try
        {
            // Route every connection (including redirect targets) through a callback that rejects
            // private/loopback addresses, closing the SSRF and DNS-rebinding vectors. Redirects stay
            // enabled (many avatar URLs redirect) but are bounded, each hop is IP-validated, and both
            // the request and the download are bounded.
            using var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 5,
                ConnectCallback = AvatarConnectCallback,

                // A system proxy would be the connection target, so the ConnectCallback would
                // validate the proxy's address rather than the avatar host's - bypassing the guard.
                UseProxy = false,
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgentString);

            // ResponseHeadersRead so the body is streamed, not fully buffered, before ReadCappedAsync
            // enforces the size limit; otherwise the cap runs only after the whole download is in memory.
            using var avatarResponse = await client.GetAsync(avatarUri, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            avatarResponse.EnsureSuccessStatusCode();

            // Media types are case-insensitive (RFC 7231); use the parsed type with parameters stripped.
            var mediaType = avatarResponse.Content.Headers.ContentType?.MediaType;
            if (string.IsNullOrEmpty(mediaType) || !mediaType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Content type of avatar URL is not an image, got: " + (mediaType ?? "(none)"));
            }

            const long MaxAvatarBytes = 10 * 1024 * 1024;
            if (avatarResponse.Content.Headers.ContentLength > MaxAvatarBytes)
            {
                throw new InvalidOperationException("Avatar exceeds the maximum allowed size.");
            }

            var extension = mediaType.Split('/')[^1];
            using var stream = await ReadCappedAsync(avatarResponse, MaxAvatarBytes).ConfigureAwait(false);

            var userDataPath =
                Path.Combine(
                    _serverConfigurationManager.ApplicationPaths.UserConfigurationDirectoryPath,
                    user.Username);
            if (user.ProfileImage is not null)
            {
                await _userManager.ClearProfileImageAsync(user).ConfigureAwait(false);
            }

            user.ProfileImage = new ImageInfo(Path.Combine(userDataPath, "profile" + extension));

            await _providerManager.SaveImage(stream, mediaType, user.ProfileImage.Path)
                .ConfigureAwait(false);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Failed to fetch or save the SSO avatar.");
        }
    }

    private static void Invalidate()
    {
        AuthStateStore.InvalidateExpired(StateManager, DateTime.Now, StateLifetime);
    }

    // Validates the SAML response and, on failure, logs the declared signature algorithm plus the
    // weak-algorithm remediation hint. This lets an operator tell a rejected SHA-1 signature - the
    // expected post-upgrade lockout of a legacy IdP - apart from a bad certificate, an expired
    // assertion, or an audience mismatch, all of which otherwise surface as the same opaque error.
    private bool IsSamlResponseValid(Response samlResponse, SamlConfig config)
    {
        if (ValidateSaml(samlResponse, config))
        {
            return true;
        }

        // The algorithm URI is identity-provider-controlled; strip line endings inline at the log
        // call to prevent log forging (a helper-boundary sanitizer is not recognized by CodeQL).
        _logger.LogWarning(
            "SAML response validation failed (signature algorithm: {Algorithm}). SHA-1 is rejected; if that is the identity provider's algorithm, reconfigure it to sign with RSA/ECDSA-SHA-256 or stronger.",
            samlResponse.GetSignatureAlgorithm()?.ReplaceLineEndings(string.Empty));
        return false;
    }

    // Validates a SAML response: signature + time bounds always, plus AudienceRestriction binding to
    // this SP unless explicitly opted out. Expected audience is the configured SamlAudience, falling
    // back to the SamlClientId (SP entity id). Both are trimmed so the comparison matches the trimmed
    // Issuer sent in the AuthnRequest, and an empty SamlAudience falls through to the client id.
    internal static bool ValidateSaml(Response samlResponse, SamlConfig config)
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

    // Resolves the target host and connects only to a non-blocked (public) address, so a hostname that
    // resolves to an internal address - including via DNS rebinding on a redirect hop - cannot be reached.
    private static async ValueTask<Stream> AvatarConnectCallback(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);

        // Try every non-blocked address in turn (a per-address connect fallback for dual-stack /
        // multi-record hosts, since supplying a ConnectCallback replaces the handler's built-in one),
        // connecting to the validated IP rather than the hostname so a DNS rebind cannot redirect the
        // connection to an internal address.
        Exception lastError = null;
        var attempted = false;
        foreach (var address in addresses)
        {
            if (AvatarUrlValidator.IsBlockedAddress(address))
            {
                continue;
            }

            attempted = true;
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            var connected = false;
            try
            {
                await socket.ConnectAsync(address, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false);
                connected = true;
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                lastError = ex;
            }
            finally
            {
                // Dispose unless ownership passed to the returned NetworkStream. Runs on the
                // cancellation path too, where the catch filter is skipped and the socket would leak.
                if (!connected)
                {
                    socket.Dispose();
                }
            }
        }

        if (attempted)
        {
            throw new HttpRequestException("Could not connect to any allowed address for the avatar host.", lastError);
        }

        throw new HttpRequestException("Avatar host resolves only to blocked addresses.");
    }

    // Copies the response body into memory, aborting if it exceeds the cap, so a hostile endpoint cannot
    // exhaust resources with an unbounded (or Content-Length-lying) download.
    private static async ValueTask<MemoryStream> ReadCappedAsync(HttpResponseMessage response, long maxBytes)
    {
        var buffer = new MemoryStream();
        var source = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        await using (source.ConfigureAwait(false))
        {
            var chunk = new byte[81920];
            long total = 0;
            int read;
            while ((read = await source.ReadAsync(chunk).ConfigureAwait(false)) > 0)
            {
                total += read;
                if (total > maxBytes)
                {
                    await buffer.DisposeAsync().ConfigureAwait(false);
                    throw new InvalidOperationException("Avatar exceeds the maximum allowed size.");
                }

                await buffer.WriteAsync(chunk.AsMemory(0, read)).ConfigureAwait(false);
            }
        }

        buffer.Position = 0;
        return buffer;
    }

    private string GetRequestBase(string schemeOverride = null, int? portOverride = null)
    {
        int requestPort;

        if (portOverride != null)
        {
            requestPort = portOverride.Value;
        }
        else
        {
            requestPort = Request.Host.Port ?? -1;
        }

        if ((requestPort == 80 && string.Equals(Request.Scheme, "http", StringComparison.OrdinalIgnoreCase)) || (requestPort == 443 && string.Equals(Request.Scheme, "https", StringComparison.OrdinalIgnoreCase)))
        {
            requestPort = -1;
        }

        if (!string.Equals(schemeOverride, "http", StringComparison.Ordinal) && !string.Equals(schemeOverride, "https", StringComparison.Ordinal))
        {
            schemeOverride = null;
        }

        return new UriBuilder
        {
            Scheme = schemeOverride ?? Request.Scheme,
            Host = Request.Host.Host,
            Port = requestPort,
            Path = Request.PathBase
        }.ToString().TrimEnd('/');
    }

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
    // must not be framed (clickjacking), MIME-sniffed, cached, or leak its URL via Referer. A
    // Content-Security-Policy is intentionally NOT set here: the page relies on an inline script and
    // style, so a safe CSP needs per-response nonces threaded into WebResponse.Generator — tracked
    // separately (it needs a real-server check that the login page still runs).
    private ContentResult HtmlAuthPage(string html)
    {
        Response.Headers["X-Frame-Options"] = "DENY";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers.CacheControl = "no-store";
        return Content(html, MediaTypeNames.Text.Html);
    }
}

/// <summary>
/// The data the client should pass back to the API.
/// </summary>
public class AuthResponse
{
    /// <summary>
    /// Gets or sets the device ID of the client.
    /// </summary>
    public string DeviceID { get; set; }

    /// <summary>
    /// Gets or sets the device name of the client.
    /// </summary>
    public string DeviceName { get; set; }

    /// <summary>
    /// Gets or sets the app name of the client.
    /// </summary>
    public string AppName { get; set; }

    /// <summary>
    /// Gets or sets the app version of the client.
    /// </summary>
    public string AppVersion { get; set; }

    /// <summary>
    /// Gets or sets the auth data of the client (for authorizing the response).
    /// </summary>
    public string Data { get; set; }
}

/// <summary>
/// A manager for OpenID to manage the state of the clients.
/// </summary>
public class TimedAuthorizeState
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TimedAuthorizeState"/> class.
    /// </summary>
    /// <param name="state">The AuthorizeState to time.</param>
    /// <param name="created">When this state was created.</param>
    public TimedAuthorizeState(AuthorizeState state, DateTime created)
    {
        State = state;
        Created = created;
        Valid = false;
        Admin = false;
        IsLinking = false;
        EnableLiveTv = false;
        EnableLiveTvManagement = false;
        AvatarURL = null;
    }

    /// <summary>
    /// Gets or sets the Authorization State of the client.
    /// </summary>
    public AuthorizeState State { get; set; }

    /// <summary>
    /// Gets or sets the provider that minted this state. A state may only be consumed on the same
    /// provider's endpoints, so it cannot be replayed against another provider's login/role gate.
    /// </summary>
    public string Provider { get; set; }

    /// <summary>
    /// Gets or sets when this object was created to time it out.
    /// </summary>
    public DateTime Created { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user is valid.
    /// </summary>
    public bool Valid { get; set; }

    /// <summary>
    /// Gets or sets the user tied to the state.
    /// </summary>
    public string Username { get; set; }

    /// <summary>
    /// Gets or sets the stable subject identifier (OpenID "sub") that keys the account link (#155).
    /// Unlike <see cref="Username"/> it does not change when the identity provider renames the user.
    /// Null for SAML, whose NameID plays the same role directly.
    /// </summary>
    public string Subject { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user is an administrator.
    /// </summary>
    public bool Admin { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the state is
    /// tied to a linking flow (instead of a login flow).
    /// </summary>
    public bool IsLinking { get; set; }

    /// <summary>
    /// Gets or sets the folders the user is allowed access to.
    /// </summary>
    public List<string> Folders { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user is allowed to view live TV.
    /// </summary>
    public bool EnableLiveTv { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user is allowed to manage live TV.
    /// </summary>
    public bool EnableLiveTvManagement { get; set; }

    /// <summary>
    /// Gets or sets the user avatar url.
    /// </summary>
    public string AvatarURL { get; set; }
}

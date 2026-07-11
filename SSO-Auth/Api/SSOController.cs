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
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SSO_Auth.Lib;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The sso api controller.
/// </summary>
[ApiController]
[Route("[controller]")]
public class SSOController : ControllerBase
{
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

    // Splits the role-claim path on dots that are not escaped with a backslash ("a.b\.c" -> "a", "b.c").
    // Compiled once and reused: it runs for every claim on every login (hot path), so it must not be
    // recompiled per call. The match timeout is defense-in-depth on the match input: the pattern is
    // fixed and linear (a fixed-width lookbehind plus a literal dot) so it cannot backtrack into a
    // timeout, but the cap guarantees role parsing can never block the login path.
    private static readonly Regex RoleClaimSplitRegex =
        new Regex(@"(?<!\\)\.", RegexOptions.Compiled, TimeSpan.FromSeconds(1));

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
            return BadRequest("No matching provider found");
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

            var scopes = config.OidScopes == null ? new string[2] : config.OidScopes;
            var options = new OidcClientOptions
            {
                Authority = config.OidEndpoint?.Trim(),
                ClientId = config.OidClientId?.Trim(),
                ClientSecret = config.OidSecret?.Trim(),
                RedirectUri = GetRequestBase(config.SchemeOverride, config.PortOverride) + $"/sso/OID/{(Request.Path.Value.Contains("/start/", StringComparison.InvariantCultureIgnoreCase) ? "redirect" : "r")}/" + provider,
                Scope = string.Join(" ", scopes.Prepend("openid profile")),
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
            var oidcClient = new OidcClient(options);
            var currentState = timedState.State;
            var result = await oidcClient.ProcessResponseAsync(Request.QueryString.Value, currentState).ConfigureAwait(false);

            if (result.IsError)
            {
                return ReturnError(StatusCodes.Status400BadRequest, $"Error logging in: {result.Error} - {result.ErrorDescription}");
            }

            if (!config.EnableFolderRoles && config.EnabledFolders != null)
            {
                timedState.Folders = new List<string>(config.EnabledFolders);
            }
            else
            {
                timedState.Folders = new List<string>();
            }

            timedState.EnableLiveTv = config.EnableLiveTv;
            timedState.EnableLiveTvManagement = config.EnableLiveTvManagement;

            if (config.AvatarUrlFormat is not null)
            {
                timedState.AvatarURL = result.User.Claims.Aggregate(
                    config.AvatarUrlFormat,
                    (s, claim) => s.Contains($"@{{{claim.Type}}}") ? s.Replace($"@{{{claim.Type}}}", claim.Value) : s);
            }

            // The role-claim path depends only on config.RoleClaim, so process it once here rather
            // than per claim. The regex splits on dots not escaped with a backslash ("a.b.c" ->
            // a, b, c; "a.b\.c" -> a, b.c), then the escaped "\." are normalized back to ".".
            string[] roleClaimSegments = string.IsNullOrEmpty(config.RoleClaim)
                ? Array.Empty<string>()
                : RoleClaimSplitRegex.Split(config.RoleClaim.Trim())
                    .Select(segment => segment.Replace("\\.", "."))
                    .ToArray();

            foreach (var claim in result.User.Claims)
            {
                if (claim.Type == (config.DefaultUsernameClaim?.Trim() ?? "preferred_username"))
                {
                    timedState.Username = claim.Value;
                    if (config.Roles == null || config.Roles.Length == 0)
                    {
                        timedState.Valid = true;
                    }
                }

                // Role processing
                if (roleClaimSegments.Any())
                {
                    if (claim.Type == roleClaimSegments[0])
                    {
                        List<string> roles;
                        // If we are not using JSON values, just use the raw info from the claim value
                        if (roleClaimSegments.Length == 1)
                        {
                            roles = new List<string> { claim.Value };
                        }
                        else
                        {
                            // We recursively traverse through the JSON data for the roles and parse it
                            var json = JsonConvert.DeserializeObject<IDictionary<string, object>>(claim.Value);
                            if (json is null)
                            {
                                roles = new List<string>();
                            }
                            else
                            {
                                bool missingSegment = false;
                                for (int i = 1; i < roleClaimSegments.Length - 1; i++)
                                {
                                    var segment = roleClaimSegments[i];
                                    if (!json.TryGetValue(segment, out var nextToken) || nextToken is not JObject nextObject)
                                    {
                                        missingSegment = true;
                                        break;
                                    }

                                    json = nextObject.ToObject<IDictionary<string, object>>();
                                    if (json is null)
                                    {
                                        missingSegment = true;
                                        break;
                                    }
                                }

                                if (missingSegment || !json.TryGetValue(roleClaimSegments[^1], out var rolesToken) || rolesToken is not JArray rolesArray)
                                {
                                    roles = new List<string>();
                                }
                                else
                                {
                                    // The final step is to take the JSON and turn it from a dictionary into a string
                                    roles = rolesArray.ToObject<List<string>>();
                                }
                            }
                        }

                        foreach (string role in roles)
                        {
                            // Check if allowed to login based on roles
                            if (config.Roles != null && config.Roles.Any())
                            {
                                foreach (string validRoles in config.Roles)
                                {
                                    if (role.Equals(validRoles))
                                    {
                                        timedState.Valid = true;
                                    }
                                }
                            }

                            // Check if admin based on roles
                            if (config.AdminRoles != null && config.AdminRoles.Any())
                            {
                                foreach (string validAdminRoles in config.AdminRoles)
                                {
                                    if (role.Equals(validAdminRoles))
                                    {
                                        timedState.Admin = true;
                                    }
                                }
                            }

                            // Get allowed folders from roles
                            if (config.EnableFolderRoles)
                            {
                                foreach (FolderRoleMap folderRoleMap in config.FolderRoleMapping)
                                {
                                    if (role.Equals(folderRoleMap.Role?.Trim()))
                                    {
                                        timedState.Folders.AddRange(folderRoleMap.Folders);
                                    }
                                }
                            }

                            if (config.EnableLiveTvRoles)
                            {
                                // Check if allowed Live TV based on roles
                                if (config.LiveTvRoles != null && config.LiveTvRoles.Any())
                                {
                                    foreach (string validLiveTvRoles in config.LiveTvRoles)
                                    {
                                        if (role.Equals(validLiveTvRoles))
                                        {
                                            timedState.EnableLiveTv = true;
                                        }
                                    }
                                }

                                // Check if allowed Live TV management based on roles
                                if (config.LiveTvManagementRoles != null && config.LiveTvManagementRoles.Any())
                                {
                                    foreach (string validLiveTvManagementRoles in config.LiveTvManagementRoles)
                                    {
                                        if (role.Equals(validLiveTvManagementRoles))
                                        {
                                            timedState.EnableLiveTvManagement = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // If the provider doesn't support the preferred username claim, then use the sub claim
            if (!timedState.Valid)
            {
                foreach (var claim in result.User.Claims)
                {
                    if (claim.Type == "sub")
                    {
                        timedState.Username = claim.Value;
                        if (config.Roles.Length == 0)
                        {
                            timedState.Valid = true;
                        }
                    }
                }
            }

            bool isLinking = timedState.IsLinking;

            if (timedState.Valid)
            {
                _logger.LogInformation($"Is request linking: {isLinking}");
                return Content(WebResponse.Generator(data: state, provider: provider, baseUrl: GetRequestBase(config.SchemeOverride, config.PortOverride), mode: "OID", isLinking: isLinking), MediaTypeNames.Text.Html);
            }
            else
            {
                _logger.LogWarning(
                    "OpenID user {Username} has one or more incorrect role claims: {@Claims}. Expected any one of: {@ExpectedClaims}",
                    timedState.Username,
                    result.User.Claims.Select(o => new { o.Type, o.Value }),
                    config.Roles);

                return ReturnError(StatusCodes.Status401Unauthorized, "Error. Check permissions.");
            }
        }

        // If the config doesn't have an active provider matching the requeset, show an error
        return BadRequest("No matching provider found");
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
            throw new ArgumentException("Provider does not exist");
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

            var options = new OidcClientOptions
            {
                Authority = config.OidEndpoint?.Trim(),
                ClientId = config.OidClientId?.Trim(),
                ClientSecret = config.OidSecret?.Trim(),
                RedirectUri = redirectUri,
                Scope = string.Join(" ", config.OidScopes.Prepend("openid profile")),
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
            var oidcClient = new OidcClient(options);
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

        throw new ArgumentException("Provider does not exist");
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
    }

    /// <summary>
    /// Deletes an OpenID provider.
    /// </summary>
    /// <param name="provider">Name of provider to delete.</param>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Del/{provider}")]
    public void OidDel(string provider)
    {
        SSOPlugin.Instance.MutateConfiguration(configuration => configuration.OidConfigs.Remove(provider));
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
            return BadRequest("No matching provider found");
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
                userId = await CreateCanonicalLinkAndUserIfNotExist("oid", provider, timedState.Username, config.AllowExistingAccountLink).ConfigureAwait(false);
            }
            catch (AccountLinkForbiddenException)
            {
                return StatusCode(StatusCodes.Status403Forbidden, "SSO login is not permitted for this account.");
            }

            var authenticationResult = await Authenticate(
                userId,
                timedState.Admin,
                config.EnableAuthorization,
                config.EnableAllFolders,
                timedState.Folders.ToArray(),
                timedState.EnableLiveTv,
                timedState.EnableLiveTvManagement,
                response,
                config.DefaultProvider?.Trim(),
                timedState.AvatarURL)
                .ConfigureAwait(false);
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
            return BadRequest("No matching provider found");
        }

        bool isLinking = relayState == "linking";

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
                return Content(
                        WebResponse.Generator(
                            data: Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(samlResponse.Xml)),
                            provider: provider,
                            baseUrl: GetRequestBase(config.SchemeOverride, config.PortOverride),
                            mode: "SAML",
                            isLinking: isLinking),
                        MediaTypeNames.Text.Html);
            }

            _logger.LogWarning(
                "SAML user: {UserId} has insufficient roles: {@Roles}. Expected any one of: {@ExpectedRoles}",
                samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty),
                samlResponse.GetCustomAttributes("Role"),
                config.Roles);
            return ReturnError(StatusCodes.Status401Unauthorized, "Error. Check permissions.");
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
            throw new ArgumentException("Provider does not exist");
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

        throw new ArgumentException("Provider does not exist");
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
        SSOPlugin.Instance.MutateConfiguration(configuration => configuration.SamlConfigs.Remove(provider));
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
            return BadRequest("No matching provider found");
        }

        if (config.Enabled)
        {
            bool isAdmin = false;
            bool liveTv = config.EnableLiveTv;
            bool liveTvManagement = config.EnableLiveTvManagement;
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
                return ReturnError(StatusCodes.Status401Unauthorized, "Error. Check permissions.");
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

            List<string> folders;
            if (!config.EnableFolderRoles && config.EnabledFolders != null)
            {
                folders = new List<string>(config.EnabledFolders);
            }
            else
            {
                folders = new List<string>();
            }

            foreach (string role in samlResponse.GetCustomAttributes("Role"))
            {
                if (config.AdminRoles != null)
                {
                    foreach (string allowedRole in config.AdminRoles)
                    {
                        if (allowedRole.Equals(role))
                        {
                            isAdmin = true;
                        }
                    }
                }

                if (config.EnableFolderRoles)
                {
                    if (config.FolderRoleMapping != null)
                    {
                        foreach (FolderRoleMap folderRoleMap in config.FolderRoleMapping)
                        {
                            if (folderRoleMap.Role.Equals(role))
                            {
                                folders.AddRange(folderRoleMap.Folders);
                            }
                        }
                    }
                }

                if (config.EnableLiveTvRoles)
                {
                    if (config.LiveTvRoles != null)
                    {
                        foreach (string allowedLiveTvRole in config.LiveTvRoles)
                        {
                            if (allowedLiveTvRole.Equals(role))
                            {
                                liveTv = true;
                            }
                        }
                    }

                    if (config.LiveTvManagementRoles != null)
                    {
                        foreach (string allowedLiveTvManagementRole in config.LiveTvManagementRoles)
                        {
                            if (allowedLiveTvManagementRole.Equals(role))
                            {
                                liveTvManagement = true;
                            }
                        }
                    }
                }
            }

            Guid userId;
            try
            {
                userId = await CreateCanonicalLinkAndUserIfNotExist("saml", provider, samlResponse.GetNameID(), config.AllowExistingAccountLink).ConfigureAwait(false);
            }
            catch (AccountLinkForbiddenException)
            {
                return StatusCode(StatusCodes.Status403Forbidden, "SSO login is not permitted for this account.");
            }

            var authenticationResult = await Authenticate(
                userId,
                isAdmin,
                config.EnableAuthorization,
                config.EnableAllFolders,
                folders.ToArray(),
                liveTv,
                liveTvManagement,
                response,
                config.DefaultProvider?.Trim(),
                null)
                .ConfigureAwait(false);
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

    // Looks up a canonical link under the config lock, so the read cannot tear against a concurrent write.
    private static Guid? TryGetCanonicalLink(string mode, string provider, string canonicalName)
    {
        return SSOPlugin.Instance.ReadConfiguration(configuration =>
        {
            var links = mode.ToLowerInvariant() switch
            {
                "saml" => configuration.SamlConfigs[provider].CanonicalLinks,
                "oid" => configuration.OidConfigs[provider].CanonicalLinks,
                _ => throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'"),
            };
            return links.TryGetValue(canonicalName, out var id) ? id : (Guid?)null;
        });
    }

    private async Task<Guid> CreateCanonicalLinkAndUserIfNotExist(string mode, string provider, string canonicalName, bool allowExistingAccountLink)
    {
        // An identity already linked to a still-existing account is keyed on the canonical name;
        // a dangling link (user since deleted) is treated as no link.
        Guid? linkedUserId = null;
        var linked = TryGetCanonicalLink(mode, provider, canonicalName);
        if (linked.HasValue && _userManager.GetUserById(linked.Value) != null)
        {
            linkedUserId = linked;
        }

        Guid? existingAccountUserId = _userManager.GetUserByName(canonicalName)?.Id;

        var decision = AccountLinkResolver.Resolve(linkedUserId, existingAccountUserId, allowExistingAccountLink);
        switch (decision.Action)
        {
            case AccountLinkAction.UseExistingLink:
                return decision.UserId;

            case AccountLinkAction.AdoptExistingAccount:
                CreateCanonicalLink(mode, provider, decision.UserId, canonicalName);
                return decision.UserId;

            case AccountLinkAction.CreateNewAccount:
                _logger.LogInformation("SSO user {Name} doesn't exist, creating...", canonicalName?.ReplaceLineEndings(string.Empty));
                var user = await _userManager.CreateUserAsync(canonicalName).ConfigureAwait(false);
                user.AuthenticationProviderId = GetType().FullName;
                // https://jonathancrozier.com/blog/how-to-generate-a-cryptographically-secure-random-string-in-dot-net-with-c-sharp
                user.Password = _cryptoProvider.CreatePasswordHash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))).ToString();
                CreateCanonicalLink(mode, provider, user.Id, canonicalName);
                return user.Id;

            case AccountLinkAction.RejectNameTaken:
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: a pre-existing unlinked Jellyfin account exists and AllowExistingAccountLink is disabled for this provider.",
                    canonicalName?.ReplaceLineEndings(string.Empty),
                    mode,
                    provider?.ReplaceLineEndings(string.Empty));
                throw new AccountLinkForbiddenException();

            default:
                throw new InvalidOperationException($"Unhandled account-link action: {decision.Action}");
        }
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
            return BadRequest("No matching provider found");
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
            return BadRequest("No matching provider found");
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

        OidConfig config;
        try
        {
            config = SSOPlugin.Instance.Configuration.OidConfigs[provider];
        }
        catch (KeyNotFoundException)
        {
            return BadRequest("No matching provider found");
        }

        // Keyed O(1) lookup + atomic claim (see OidAuth): consume the state so one verified identity
        // cannot be linked repeatedly and cannot then be reused to mint a session.
        if (StateManager.TryGetValue(response.Data, out var timedState)
            && AuthStateStore.IsRedeemableBy(timedState, response.Data, provider, DateTime.Now, StateLifetime)
            && StateManager.TryRemove(new KeyValuePair<string, TimedAuthorizeState>(response.Data, timedState)))
        {
            return CreateCanonicalLink("oid", provider, jellyfinUserId, timedState.Username);
        }

        return Problem("Something went wrong!");
    }

    private ActionResult CreateCanonicalLink(string mode, string provider, Guid jellyfinUserId, string providerUserId)
    {
        try
        {
            SSOPlugin.Instance.MutateConfiguration(configuration =>
                MutateLinks(configuration, mode, provider, links => links[providerUserId] = jellyfinUserId));
        }
        catch (KeyNotFoundException)
        {
            return BadRequest("No matching provider found");
        }

        return NoContent();
    }

    /// <summary>
    /// Authenticates the user with the given information.
    /// </summary>
    /// <param name="userId">The user id of the user to authenticate.</param>
    /// <param name="isAdmin">Determines whether this user is an administrator.</param>
    /// <param name="enableAuthorization">Determines whether RBAC is used for this user.</param>
    /// <param name="enableAllFolders">Determines whether all folders are enabled.</param>
    /// <param name="enabledFolders">Determines which folders should be enabled for this client.</param>
    /// <param name="enableLiveTv">Determines whether live TV access is allowed for this user.</param>
    /// <param name="enableLiveTvAdmin">Determines whether live TV can be managed by this user.</param>
    /// <param name="authResponse">The client information to authenticate the user with.</param>
    /// <param name="defaultProvider">The default provider of the user to be set after logging in.</param>
    /// <param name="avatarUrl">The new avatar url for the user.</param>
    private async Task<AuthenticationResult> Authenticate(Guid userId, bool isAdmin, bool enableAuthorization, bool enableAllFolders, string[] enabledFolders, bool enableLiveTv, bool enableLiveTvAdmin, AuthResponse authResponse, string defaultProvider, string avatarUrl)
    {
        User user = _userManager.GetUserById(userId);
        if (user is null)
        {
            // Fail closed: the account resolved for this SSO login no longer exists (e.g. it was
            // deleted between resolution and this call), so no session may be minted for it.
            throw new AuthenticationException("SSO authentication aborted: the target user does not exist.");
        }

        if (enableAuthorization)
        {
            user.SetPermission(PermissionKind.IsAdministrator, isAdmin);
            user.SetPermission(PermissionKind.EnableAllFolders, enableAllFolders);
            if (!enableAllFolders)
            {
                user.SetPreference(PreferenceKind.EnabledFolders, enabledFolders);
            }
        }

        if (avatarUrl is not null)
        {
            if (!AvatarUrlValidator.IsAllowedUrl(avatarUrl, out var avatarUri))
            {
                _logger.LogWarning("Refusing to fetch avatar from disallowed URL: {AvatarUrl}", avatarUrl?.ReplaceLineEndings(string.Empty));
            }
            else
            {
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
                        throw new Exception("Content type of avatar URL is not an image, got :  " + (mediaType ?? "(none)"));
                    }

                    const long MaxAvatarBytes = 10 * 1024 * 1024;
                    if (avatarResponse.Content.Headers.ContentLength > MaxAvatarBytes)
                    {
                        throw new Exception("Avatar exceeds the maximum allowed size.");
                    }

                    var extension = mediaType.Split('/').Last();
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
        }

        user.SetPermission(PermissionKind.EnableLiveTvAccess, enableLiveTv);
        user.SetPermission(PermissionKind.EnableLiveTvManagement, enableLiveTvAdmin);

        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        var authRequest = new AuthenticationRequest();
        authRequest.UserId = user.Id;
        authRequest.Username = user.Username;
        authRequest.App = authResponse.AppName;
        authRequest.AppVersion = authResponse.AppVersion;
        authRequest.DeviceId = authResponse.DeviceID;
        authRequest.DeviceName = authResponse.DeviceName;
        _logger.LogInformation("Auth request created...");
        if (!string.IsNullOrEmpty(defaultProvider))
        {
            user.AuthenticationProviderId = defaultProvider;
            await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
            _logger.LogInformation("Set default login provider to " + defaultProvider);
        }

        return await _sessionManager.AuthenticateDirect(authRequest).ConfigureAwait(false);
    }

    private void Invalidate()
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
                    throw new Exception("Avatar exceeds the maximum allowed size.");
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

        if (schemeOverride != "http" && schemeOverride != "https")
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

    private ContentResult ReturnError(int code, string message)
    {
        var errorResult = new ContentResult();
        errorResult.Content = message;
        errorResult.ContentType = MediaTypeNames.Text.Plain;
        errorResult.StatusCode = code;
        return errorResult;
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

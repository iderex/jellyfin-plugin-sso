using System;
using System.Collections.Generic;
using System.IO;
using Duende.IdentityModel.OidcClient.Infrastructure;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth;

/// <summary>
/// The SSO plugin class: bootstrap and page manifests. All configuration access is owned by
/// <see cref="ProviderConfigStore"/> (#318); the public methods below remain the plugin's
/// configuration facade and delegate to it.
/// </summary>
public class SSOPlugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    private readonly Lazy<SecretStore> _secrets;

    /// <summary>
    /// Initializes static members of the <see cref="SSOPlugin"/> class.
    /// </summary>
    static SSOPlugin()
    {
        // Stop the OidcClient trace serializer from JSON-serializing the full options object — the
        // client secret included — into a transient string on every Prepare/Process call, which it does
        // even with Trace logging off (#247). We never consume that trace output, so disabling it in the
        // type initializer (runs once, before any login) keeps the secret out of transient heap strings
        // (defense in depth). The flag is a process-global, so setting it here covers every login.
        LogSerializer.Enabled = false;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SSOPlugin"/> class.
    /// </summary>
    /// <param name="applicationPaths">Internal Jellyfin interface for the ApplicationPath.</param>
    /// <param name="xmlSerializer">Internal Jellyfin interface for the XML information.</param>
    /// <param name="logger">The logger (used to audit insecure-option saves, #140).</param>
    public SSOPlugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer, ILogger<SSOPlugin> logger)
        : base(applicationPaths, xmlSerializer)
    {
        // Handing out `() => Configuration` here is safe: BasePlugin's constructor only records the
        // config path and loads the configuration lazily on first access, so nothing calls back into
        // UpdateConfiguration (and thus ConfigStore) before this assignment completes.
        ConfigStore = new ProviderConfigStore(() => Configuration, PersistBase, logger);

        // Lazy with the default thread-safe mode: the SecretStore (and thus the data-encryption key) is
        // built exactly once, even under concurrent first-use, so two callers can never generate two
        // divergent keys. The key lives in the plugin data folder, separate from the config XML, and is
        // created lazily on the first encrypt (a save) — never at load — so startup does no key I/O.
        _secrets = new Lazy<SecretStore>(() => new SecretStore(Path.Combine(DataFolderPath, "sso-secret.key")));
        Instance = this;
    }

    /// <summary>
    /// Gets the instance of the SSO plugin.
    /// </summary>
    public static SSOPlugin Instance { get; private set; }

    /// <summary>
    /// Gets the name of the SSO plugin.
    /// </summary>
    public override string Name => "SSO-Auth";

    /// <summary>
    /// Gets the GUID of the SSO plugin.
    /// </summary>
    public override Guid Id => Guid.Parse("505ce9d1-d916-42fa-86ca-673ef241d7df");

    /// <summary>
    /// Gets the store that owns every configuration read and write (#318).
    /// </summary>
    internal ProviderConfigStore ConfigStore { get; }

    /// <summary>
    /// Gets the store that encrypts the plugin's at-rest secrets — the OpenID client secret and the SAML
    /// signing key (#158). Its data-encryption key lives in a dedicated file in the plugin data folder,
    /// separate from the config XML, so a leaked config alone cannot decrypt anything. The login flows
    /// reveal a stored secret through this at the point of use.
    /// </summary>
    internal SecretStore Secrets => _secrets.Value;

    /// <summary>
    /// Applies a mutation to the live configuration under a single lock and persists it, so a
    /// read-modify-write cannot race another and lose its update. All configuration writes must go
    /// through this rather than reading <see cref="BasePlugin{T}.Configuration"/>, mutating, and
    /// calling <c>UpdateConfiguration</c> separately.
    /// </summary>
    /// <param name="mutate">The mutation to apply to the live configuration.</param>
    public void MutateConfiguration(Action<PluginConfiguration> mutate) => ConfigStore.Mutate(mutate);

    /// <summary>
    /// Applies a mutation that returns a result (e.g. whether a removal changed anything) under the
    /// same single lock and persists it, so the read-modify-write and the result observation are one
    /// atomic operation.
    /// </summary>
    /// <typeparam name="T">The value the mutation returns.</typeparam>
    /// <param name="mutate">The mutation to apply to the live configuration.</param>
    /// <returns>The value returned by <paramref name="mutate"/>.</returns>
    public T MutateConfiguration<T>(Func<PluginConfiguration, T> mutate) => ConfigStore.Mutate(mutate);

    /// <summary>
    /// Reads a value from the live configuration under the same lock as <see cref="MutateConfiguration(Action{PluginConfiguration})"/>,
    /// so a read cannot tear against a concurrent write of a (non-thread-safe) configuration collection.
    /// </summary>
    /// <typeparam name="T">The value read.</typeparam>
    /// <param name="read">The read to perform against the live configuration.</param>
    /// <returns>The value returned by <paramref name="read"/>.</returns>
    public T ReadConfiguration<T>(Func<PluginConfiguration, T> read) => ConfigStore.Read(read);

    /// <summary>
    /// Persists a replacement configuration through the store's validated save pipeline
    /// (<see cref="ProviderConfigStore.Save"/>): fail-closed validation (#139/#206), server-managed
    /// field preservation (#157/#189), and the insecure-option audit (#140). Jellyfin core's
    /// UpdatePluginConfiguration (the admin config-page save) enters here.
    /// </summary>
    /// <param name="configuration">The configuration to persist.</param>
    public override void UpdateConfiguration(BasePluginConfiguration configuration) => ConfigStore.Save(configuration);

    // The store's only road to disk: persistence stays with the plugin base class, and this named
    // bridge hands base.UpdateConfiguration to the store so a store save cannot re-enter the
    // overridden pipeline above. Every road to disk — the config-page Save and every Mutate (provider
    // Add, login-path canonical-link writes) — funnels through here, so this is the single chokepoint
    // where at-rest secret encryption belongs (#158): the config model is owned by the store, but the
    // on-disk representation is owned by the persistence boundary, and that is where a secret becomes an
    // ssoenc: envelope. ProtectAll is idempotent (an already-encrypted or empty value is left unchanged),
    // so re-persisting is a no-op and a legacy plaintext value is rewritten encrypted on its next save.
    private void PersistBase(BasePluginConfiguration configuration)
    {
        if (configuration is PluginConfiguration incoming)
        {
            ConfigSecretProtection.ProtectAll(incoming, Secrets);
        }

        base.UpdateConfiguration(configuration);
    }

    // Both tables below are the plugin's public URL contract (#370): the first element of each Page()
    // pair is the name a caller (the admin config page, the linking page, SSOViewsController) requests
    // an asset by, matched case-sensitively (SSOViewsController.GetView); the second is the embedded
    // resource path suffix, which must match the source file's actual on-disk name and casing under
    // this project's default (path-derived) embedded-resource naming. The two never have to agree with
    // each other, but changing either one changes what breaks: renaming the registered name breaks
    // every caller of that URL (config.js, linking.html, config page markup); renaming/moving the
    // source file without updating the resource suffix here breaks the embedded-resource lookup at
    // runtime (a 404, since GetManifestResourceStream is also case-sensitive). Config.style.css is
    // deliberately published under two different registered names below — "SSO-Auth.css" (GetPages, the
    // admin config page's own stylesheet load) and "style.css" (GetViews, the public linking page) —
    // the same resource, two unrelated consumers with independently-chosen URL conventions, not a
    // casing inconsistency.

    /// <summary>
    /// Returns the available internal web pages of this plugin.
    /// </summary>
    /// <returns>A list of internal webpages in this application.</returns>
    public IEnumerable<PluginPageInfo> GetPages() =>
        new[]
        {
            Page(Name, "Config.configPage.html"),
            Page(Name + ".js", "Config.config.js"),
            Page(Name + ".css", "Config.style.css"),
            Page(Name + "-linking", "Config.linking.html"),
            Page(Name + "-linking.js", "Config.linking.js"),
        };

    /// <summary>
    /// Returns the available user views for this plugin.
    /// </summary>
    /// <returns>A list of user views for this plugin.</returns>
    public IEnumerable<PluginPageInfo> GetViews() =>
        new[]
        {
            Page("style.css", "Config.style.css"),
            Page("linking", "Config.linking.html"),
            Page("linking.js", "Config.linking.js"),
            Page("ApiClient.js", "Views.ApiClient.js"),
            Page("emby-restyle.css", "Views.emby-restyle.css"),
            Page("jellyfin-apiClient.esm.min.js", "Views.jellyfin-apiClient.esm.min.js"),
        };

    // Every GetPages/GetViews entry is a (registered name, embedded resource) pair under this
    // plugin's namespace; this factory collapses the repeated PluginPageInfo construction to one
    // call per entry.
    private PluginPageInfo Page(string name, string resource) =>
        new() { Name = name, EmbeddedResourcePath = $"{GetType().Namespace}.{resource}" };
}

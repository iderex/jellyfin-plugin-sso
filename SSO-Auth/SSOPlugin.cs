using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Jellyfin.Plugin.SSO_Auth;

/// <summary>
/// The SSO plugin class.
/// </summary>
public class SSOPlugin : BasePlugin<PluginConfiguration>, IPlugin, IHasWebPages
{
    // Serializes every read-modify-write of the plugin configuration so concurrent mutations
    // (notably first-logins each writing a canonical link) cannot lose one another's updates.
    private static readonly object ConfigMutationLock = new object();

    /// <summary>
    /// Initializes a new instance of the <see cref="SSOPlugin"/> class.
    /// </summary>
    /// <param name="applicationPaths">Internal Jellyfin interface for the ApplicationPath.</param>
    /// <param name="xmlSerializer">Internal Jellyfin interface for the XML information.</param>
    public SSOPlugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
        : base(applicationPaths, xmlSerializer)
    {
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
    /// Applies a mutation to the live configuration under a single lock and persists it, so a
    /// read-modify-write cannot race another and lose its update. All configuration writes must go
    /// through this rather than reading <see cref="BasePlugin{T}.Configuration"/>, mutating, and
    /// calling <c>UpdateConfiguration</c> separately.
    /// </summary>
    /// <param name="mutate">The mutation to apply to the live configuration.</param>
    public void MutateConfiguration(Action<PluginConfiguration> mutate)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        lock (ConfigMutationLock)
        {
            var configuration = Configuration;
            mutate(configuration);
            UpdateConfiguration(configuration);
        }
    }

    /// <summary>
    /// Applies a mutation that returns a result (e.g. whether a removal changed anything) under the
    /// same single lock and persists it, so the read-modify-write and the result observation are one
    /// atomic operation.
    /// </summary>
    /// <typeparam name="T">The value the mutation returns.</typeparam>
    /// <param name="mutate">The mutation to apply to the live configuration.</param>
    /// <returns>The value returned by <paramref name="mutate"/>.</returns>
    public T MutateConfiguration<T>(Func<PluginConfiguration, T> mutate)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        lock (ConfigMutationLock)
        {
            var configuration = Configuration;
            var result = mutate(configuration);
            UpdateConfiguration(configuration);
            return result;
        }
    }

    /// <summary>
    /// Persists a replacement configuration, re-injecting server-managed fields from the live
    /// configuration first (#157). The admin settings page saves through this path (Jellyfin core's
    /// UpdatePluginConfiguration) with a snapshot taken at page load, so a canonical link created by a
    /// login since then would be absent from the posted config; re-injecting the live links stops the
    /// save from wiping them. Takes the same lock as <see cref="MutateConfiguration"/> (reentrant, so
    /// calls from there are safe) and skips the copy when the incoming object is the live one.
    /// </summary>
    /// <param name="configuration">The configuration to persist.</param>
    public override void UpdateConfiguration(BasePluginConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        lock (ConfigMutationLock)
        {
            if (configuration is PluginConfiguration incoming && !ReferenceEquals(incoming, Configuration))
            {
                PreserveServerManagedFields(incoming, Configuration);
            }

            base.UpdateConfiguration(configuration);
        }
    }

    /// <summary>
    /// Copies the server-managed fields from <paramref name="live"/> into <paramref name="incoming"/>,
    /// so a save built from a stale client snapshot cannot clear them. Only providers present in
    /// <paramref name="incoming"/> are touched (a deleted provider stays deleted; a newly added one
    /// keeps its own empty map). Two kinds of field are preserved: the per-provider canonical links
    /// (always server-owned, #157), and the OpenID client secret (#189) — the latter only when the
    /// incoming value is blank, since the secret is withheld from JSON responses so a save that did
    /// not set a new one arrives empty and must keep the stored value (a non-blank incoming value is
    /// an intentional rotation and is left as-is).
    /// </summary>
    /// <param name="incoming">The configuration about to be persisted.</param>
    /// <param name="live">The current live configuration to read server-managed values from.</param>
    internal static void PreserveServerManagedFields(PluginConfiguration incoming, PluginConfiguration live)
    {
        if (incoming?.OidConfigs != null && live?.OidConfigs != null)
        {
            foreach (var kvp in live.OidConfigs)
            {
                if (incoming.OidConfigs.TryGetValue(kvp.Key, out var incomingProvider))
                {
                    incomingProvider.CanonicalLinks = kvp.Value.CanonicalLinks;
                    incomingProvider.OidSecret = ResolveUpdatedSecret(incomingProvider, kvp.Value);
                }
            }
        }

        if (incoming?.SamlConfigs != null && live?.SamlConfigs != null)
        {
            foreach (var kvp in live.SamlConfigs)
            {
                if (incoming.SamlConfigs.TryGetValue(kvp.Key, out var incomingProvider))
                {
                    incomingProvider.CanonicalLinks = kvp.Value.CanonicalLinks;
                }
            }
        }
    }

    /// <summary>
    /// Decides which OpenID client secret an updated provider should keep (#189), the single rule
    /// shared by the config-page save and <c>OID/Add</c>. A non-blank incoming secret is an explicit
    /// rotation and wins. A blank one means "keep the stored secret" — but ONLY while the provider
    /// identity (endpoint and client id) is unchanged: if either changed, the stored secret is not
    /// carried over (it stays blank, failing the login closed until an admin supplies one), so a
    /// write-only secret cannot be exfiltrated by repointing the provider at a different token
    /// endpoint. Whitespace-only counts as blank, matching the <c>Trim()</c> at the consumption site.
    /// </summary>
    /// <param name="incoming">The provider config about to be persisted.</param>
    /// <param name="live">The current live provider config.</param>
    /// <returns>The secret to persist for the updated provider.</returns>
    internal static string ResolveUpdatedSecret(OidConfig incoming, OidConfig live)
    {
        if (!string.IsNullOrWhiteSpace(incoming.OidSecret))
        {
            return incoming.OidSecret;
        }

        var identityUnchanged =
            string.Equals(incoming.OidEndpoint, live.OidEndpoint, StringComparison.Ordinal)
            && string.Equals(incoming.OidClientId, live.OidClientId, StringComparison.Ordinal);
        return identityUnchanged ? live.OidSecret : incoming.OidSecret;
    }

    /// <summary>
    /// Reads a value from the live configuration under the same lock as <see cref="MutateConfiguration"/>,
    /// so a read cannot tear against a concurrent write of a (non-thread-safe) configuration collection.
    /// </summary>
    /// <typeparam name="T">The value read.</typeparam>
    /// <param name="read">The read to perform against the live configuration.</param>
    /// <returns>The value returned by <paramref name="read"/>.</returns>
    public T ReadConfiguration<T>(Func<PluginConfiguration, T> read)
    {
        ArgumentNullException.ThrowIfNull(read);
        lock (ConfigMutationLock)
        {
            return read(Configuration);
        }
    }

    /// <summary>
    /// Returns the available internal web pages of this plugin.
    /// </summary>
    /// <returns>A list of internal webpages in this application.</returns>
    public IEnumerable<PluginPageInfo> GetPages()
    {
        return new[]
        {
            new PluginPageInfo
            {
                Name = Name,
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.configPage.html"
            },
            new PluginPageInfo
            {
                Name = Name + ".js",
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.config.js"
            },
            new PluginPageInfo
            {
                Name = Name + ".css",
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.style.css"
            },
            new PluginPageInfo
            {
                Name = Name + "-linking",
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.linking.html"
            },
            new PluginPageInfo
            {
                Name = Name + "-linking.js",
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.linking.js"
            },
        };
    }

    /// <summary>
    /// Returns the available user views for this plugin.
    /// </summary>
    /// <returns>A list of user views for this plugin.</returns>
    public IEnumerable<PluginPageInfo> GetViews()
    {
        return new[]
        {
            new PluginPageInfo
            {
                Name = "style.css",
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.style.css"
            },
            new PluginPageInfo
            {
                Name = "linking",
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.linking.html"
            },
            new PluginPageInfo
            {
                Name = "linking.js",
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.linking.js"
            },
            new PluginPageInfo
            {
                Name = "ApiClient.js",
                EmbeddedResourcePath = $"{GetType().Namespace}.Views.apiClient.js"
            },
            new PluginPageInfo
            {
                Name = "emby-restyle.css",
                EmbeddedResourcePath = $"{GetType().Namespace}.Views.emby-restyle.css"
            },
            new PluginPageInfo
            {
                Name = "jellyfin-apiClient.esm.min.js",
                EmbeddedResourcePath = $"{GetType().Namespace}.Views.jellyfin-apiClient.esm.min.js"
            },
        };
    }
}

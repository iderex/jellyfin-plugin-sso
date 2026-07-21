// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// The portable document produced by the admin config export and consumed by the import (#161): a version
/// marker plus the redacted plugin configuration. It is a JSON-only transport shape — never persisted to
/// the config XML — so it carries no XML-serialization attributes. Serializing it applies the config's
/// existing JSON-boundary redaction unchanged: the provider secrets (<see cref="OidConfig.OidSecret"/>,
/// <see cref="SamlConfig.SamlSigningKeyPfx"/>, <see cref="SamlConfig.SamlRolloverSigningKeyPfx"/>) are
/// withheld by their <see cref="WriteOnlySecretConverter"/> and the server-managed link maps by
/// <c>[JsonIgnore]</c>, so an exported document can contain neither a plaintext secret, an <c>ssoenc:</c>
/// envelope, nor a canonical-link map. The <see cref="FormatVersion"/> lets the import reject a document it
/// does not understand fail-closed rather than partially applying it.
/// </summary>
public class ConfigExportDocument
{
    /// <summary>
    /// Gets or sets the document format version. The import refuses a version it does not recognise (#161),
    /// so a future breaking change to the shape cannot be half-applied to an older instance.
    /// </summary>
    public int FormatVersion { get; set; }

    /// <summary>
    /// Gets or sets the redacted plugin configuration. On export it is a detached snapshot of the live
    /// configuration whose secrets and server-managed link maps are withheld at the JSON boundary; on import
    /// it is the incoming configuration to merge into the target.
    /// </summary>
    public PluginConfiguration? Configuration { get; set; }
}

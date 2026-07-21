// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Diagnostics.CodeAnalysis;

namespace Jellyfin.Plugin.SSO_Auth.Api.Avatar;

/// <summary>
/// Resolves the stored file extension for an avatar HTTP content type, restricted to an allow-list of
/// raster image types. Vector types — notably <c>image/svg+xml</c> — are rejected: an SVG can carry
/// inline script, so a stored SVG avatar could become a stored-XSS vector if the host later serves it
/// executably. The extension is taken from the allow-list, never from the raw content-type subtype (#217).
/// </summary>
internal static class AvatarContentType
{
    /// <summary>
    /// Tries to map an avatar content type to a safe stored file extension.
    /// </summary>
    /// <param name="mediaType">The response media type (case-insensitive), with parameters already stripped.</param>
    /// <param name="extension">
    /// The stored file extension <b>including the leading dot</b> (e.g. <c>.png</c>) when allowed;
    /// otherwise null. The dot is included so the value is a real extension the store appends directly —
    /// a bare form produced dotless filenames like <c>profilepng</c> (#384).
    /// </param>
    /// <returns><c>true</c> when the media type is an allowed raster image; otherwise <c>false</c>.</returns>
    internal static bool TryResolveExtension(string? mediaType, [NotNullWhen(true)] out string? extension)
    {
        extension = (mediaType ?? string.Empty).ToLowerInvariant() switch
        {
            "image/png" => ".png",
            "image/jpeg" => ".jpeg",
            "image/jpg" => ".jpeg",
            "image/gif" => ".gif",
            "image/webp" => ".webp",
            _ => null,
        };

        return extension is not null;
    }
}

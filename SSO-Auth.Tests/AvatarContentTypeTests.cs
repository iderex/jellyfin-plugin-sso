using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="AvatarContentType"/> — the raster-only allow-list that decides which avatar
/// content types are stored and rejects vector types such as <c>image/svg+xml</c> (#217).
/// </summary>
public class AvatarContentTypeTests
{
    [Theory]
    [InlineData("image/png", ".png")]
    [InlineData("image/jpeg", ".jpeg")]
    [InlineData("image/jpg", ".jpeg")]
    [InlineData("image/gif", ".gif")]
    [InlineData("image/webp", ".webp")]
    [InlineData("IMAGE/PNG", ".png")]
    public void AllowedRasterTypes_ResolveWithLeadingDot(string mediaType, string expected)
    {
        // The extension carries the leading dot so the store appends it directly (#384); a bare form
        // produced dotless filenames like profilepng.
        Assert.True(AvatarContentType.TryResolveExtension(mediaType, out var extension));
        Assert.Equal(expected, extension);
        Assert.StartsWith(".", extension);
    }

    [Theory]
    [InlineData("image/svg+xml")]
    [InlineData("image/bmp")]
    [InlineData("image/tiff")]
    [InlineData("text/html")]
    [InlineData("application/octet-stream")]
    [InlineData("")]
    [InlineData(null)]
    public void VectorOrDisallowedTypes_AreRejected(string? mediaType)
    {
        Assert.False(AvatarContentType.TryResolveExtension(mediaType, out var extension));
        Assert.Null(extension);
    }
}

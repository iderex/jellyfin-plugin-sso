using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlRecipientValidator"/> — the pure endpoint-binding check (#156): the
/// signed Recipient (required) and the Response Destination (when present) must match one of this
/// service provider's assertion-consumer URLs.
/// </summary>
public class SamlRecipientValidatorTests
{
    private static readonly string[] AcsUrls =
    {
        "https://jf.example/sso/SAML/post/idp",
        "https://jf.example/sso/SAML/p/idp",
    };

    [Fact]
    public void RecipientMatchingAcs_NoDestination_IsBound()
    {
        Assert.True(SamlRecipientValidator.IsBound("https://jf.example/sso/SAML/post/idp", null, AcsUrls));
    }

    [Fact]
    public void RecipientMatchingLegacyPathForm_IsBound()
    {
        // Either advertised path spelling (post/p) is accepted — the NewPath-flip robustness.
        Assert.True(SamlRecipientValidator.IsBound("https://jf.example/sso/SAML/p/idp", null, AcsUrls));
    }

    [Fact]
    public void RecipientWithSurroundingWhitespace_IsTrimmedAndBound()
    {
        Assert.True(SamlRecipientValidator.IsBound("  https://jf.example/sso/SAML/post/idp  ", null, AcsUrls));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("https://evil.example/sso/SAML/post/idp")]
    public void MissingOrMismatchedRecipient_FailsClosed(string? recipient)
    {
        Assert.False(SamlRecipientValidator.IsBound(recipient!, null, AcsUrls));
    }

    [Fact]
    public void DestinationPresentAndMatching_IsBound()
    {
        Assert.True(SamlRecipientValidator.IsBound(
            "https://jf.example/sso/SAML/post/idp",
            "https://jf.example/sso/SAML/post/idp",
            AcsUrls));
    }

    [Fact]
    public void DestinationPresentButMismatched_IsRejected()
    {
        // A Response-level Destination that is present must still match (defense in depth), even
        // though the Recipient itself is valid.
        Assert.False(SamlRecipientValidator.IsBound(
            "https://jf.example/sso/SAML/post/idp",
            "https://evil.example/sso/SAML/post/idp",
            AcsUrls));
    }
}

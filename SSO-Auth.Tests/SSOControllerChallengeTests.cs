using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the enabled-provider SAML challenge (login, linking, solicited-only, and the
/// rate-limit guard), the Unregister guard, and the admin provider-list endpoints via
/// <see cref="SsoControllerHarness"/>.
/// </summary>
[Collection("SSOController")]
public class SSOControllerChallengeTests
{
    private static SamlConfig EnabledProvider() => new SamlConfig
    {
        Enabled = true,
        SamlEndpoint = "https://idp.example.com/sso",
        SamlClientId = "jellyfin-sp",
    };

    [Fact]
    public void SamlChallenge_EnabledProvider_RedirectsToTheIdentityProvider()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = EnabledProvider());

        var result = Assert.IsType<RedirectResult>(harness.Controller.SamlChallenge("adfs"));

        Assert.StartsWith("https://idp.example.com/sso", result.Url);
        // The redirect carries the deflated+encoded AuthnRequest, so it must be a real SAML redirect.
        Assert.Contains("SAMLRequest=", result.Url);
    }

    [Fact]
    public void SamlChallenge_LoginFlow_SetsTheBrowserBindingCookie()
    {
        // #415: a login challenge sets the browser-binding cookie whose id is recorded against the
        // AuthnRequest, so the session-mint endpoint can require the response to return in the same
        // browser. Secure + HttpOnly + the __Host- prefix mirror #326.
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = EnabledProvider());

        Assert.IsType<RedirectResult>(harness.Controller.SamlChallenge("adfs"));

        var setCookie = harness.Controller.HttpContext.Response.Headers.SetCookie.ToString();
        Assert.Contains(AuthorizeStateBinding.SamlCookieName + "=", setCookie);
        Assert.Contains("secure", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SamlChallenge_LinkingFlow_CarriesTheLinkingRelayState_AndSetsNoBindingCookie()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = EnabledProvider());

        var result = Assert.IsType<RedirectResult>(harness.Controller.SamlChallenge("adfs", isLinking: true));

        // The linking callback is told apart from a login by the RelayState the challenge sets.
        Assert.Contains("SAMLRequest=", result.Url);
        Assert.Contains("RelayState=linking", result.Url);
        // Linking is a separate flow that does not consume the outstanding request, so no binding
        // cookie is minted for it (#415).
        var setCookie = harness.Controller.HttpContext.Response.Headers.SetCookie.ToString();
        Assert.DoesNotContain(AuthorizeStateBinding.SamlCookieName, setCookie);
    }

    [Fact]
    public void SamlChallenge_SigningDisabled_RedirectCarriesNoSignature()
    {
        // Default off (#167): existing deployments are unaffected — the redirect carries the unsigned
        // AuthnRequest exactly as before, with no SigAlg/Signature parameters.
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = EnabledProvider());

        var result = Assert.IsType<RedirectResult>(harness.Controller.SamlChallenge("adfs"));

        Assert.Contains("SAMLRequest=", result.Url);
        Assert.DoesNotContain("SigAlg=", result.Url);
        Assert.DoesNotContain("Signature=", result.Url);
    }

    [Fact]
    public void SamlChallenge_SigningEnabledWithValidKey_RedirectCarriesAVerifiableSignature()
    {
        var (pfx, publicKey) = SamlSigningKeyFactory.CreatePair();
        using (publicKey)
        {
            var harness = new SsoControllerHarness(c =>
            {
                var config = EnabledProvider();
                config.SignAuthnRequests = true;
                config.SamlSigningKeyPfx = pfx;
                c.SamlConfigs["adfs"] = config;
            });

            var result = Assert.IsType<RedirectResult>(harness.Controller.SamlChallenge("adfs"));

            Assert.Contains("SigAlg=", result.Url);
            Assert.Contains("Signature=", result.Url);
            Assert.True(RedirectSignatureVerifies(result.Url, publicKey));
        }
    }

    [Fact]
    public void SamlChallenge_SigningEnabledButKeyMissing_FailsClosedWith500_AndNoRedirect()
    {
        // An operator who turned signing on but has no key must NOT get a silent unsigned request: fail
        // closed with a 500, never a RedirectResult.
        var harness = new SsoControllerHarness(c =>
        {
            var config = EnabledProvider();
            config.SignAuthnRequests = true;
            config.SamlSigningKeyPfx = null;
            c.SamlConfigs["adfs"] = config;
        });

        var result = harness.Controller.SamlChallenge("adfs");

        Assert.IsNotType<RedirectResult>(result);
        Assert.Equal(500, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public void SamlChallenge_SigningEnabledWithGarbageKey_FailsClosedWith500()
    {
        var harness = new SsoControllerHarness(c =>
        {
            var config = EnabledProvider();
            config.SignAuthnRequests = true;
            config.SamlSigningKeyPfx = "QUJD"; // valid base64, not a PKCS#12
            c.SamlConfigs["adfs"] = config;
        });

        var result = harness.Controller.SamlChallenge("adfs");

        Assert.IsNotType<RedirectResult>(result);
        Assert.Equal(500, Assert.IsType<ContentResult>(result).StatusCode);
    }

    private static bool RedirectSignatureVerifies(string url, RSA publicKey)
    {
        var samlRequest = QueryValue(url, "SAMLRequest");
        var sigAlg = QueryValue(url, "SigAlg");
        var signature = Convert.FromBase64String(QueryValue(url, "Signature"));

        var signedQuery = "SAMLRequest=" + Uri.EscapeDataString(samlRequest) + "&SigAlg=" + Uri.EscapeDataString(sigAlg);
        return publicKey.VerifyData(Encoding.UTF8.GetBytes(signedQuery), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static string QueryValue(string url, string name)
    {
        foreach (var pair in url[(url.IndexOf('?') + 1)..].Split('&'))
        {
            var eq = pair.IndexOf('=');
            if (eq > 0 && pair[..eq] == name)
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }

        throw new InvalidOperationException($"Query parameter '{name}' not found in {url}.");
    }

    [Fact]
    public void SamlChallenge_SolicitedOnly_StillRedirects()
    {
        var harness = new SsoControllerHarness(c =>
        {
            var config = EnabledProvider();
            config.ValidateInResponseTo = true; // registers the request id for InResponseTo correlation (#156)
            c.SamlConfigs["adfs"] = config;
        });

        var result = Assert.IsType<RedirectResult>(harness.Controller.SamlChallenge("adfs"));

        Assert.Contains("SAMLRequest=", result.Url);
    }

    [Fact]
    public void SamlChallenge_OverRateLimit_Returns429()
    {
        var harness = new SsoControllerHarness(
            c =>
            {
                c.EnableRateLimit = true;
                c.RateLimitMaxAttempts = 1;
                c.RateLimitWindowSeconds = 60;
            },
            // A dedicated public address so the process-static limiter counter is this test's alone.
            clientIp: IPAddress.Parse("8.8.4.4"));

        // The first call passes the limiter and spends the single-attempt budget; the unknown provider
        // then rejects with the uniform 400, but that is after the budget is spent.
        Assert.Equal(400, Assert.IsType<ContentResult>(harness.Controller.SamlChallenge("does-not-exist")).StatusCode);

        // The second is over budget and is throttled with a 429 before the provider is even looked up.
        var throttled = harness.Controller.SamlChallenge("does-not-exist");
        Assert.Equal(429, Assert.IsType<ContentResult>(throttled).StatusCode);
    }

    [Fact]
    public async Task Unregister_UnknownUser_ReturnsNotFound()
    {
        // The mocked IUserManager returns null for any name, so the guard short-circuits.
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.Unregister("nobody", "Jellyfin");

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public void OidProviders_ReturnsOkSnapshotContainingTheProvider()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = new OidConfig());

        var ok = Assert.IsType<OkObjectResult>(harness.Controller.OidProviders());
        var snapshot = Assert.IsType<SerializableDictionary<string, OidConfig>>(ok.Value);
        Assert.True(snapshot.ContainsKey("keycloak"));
    }

    [Fact]
    public void SamlProviders_ReturnsOkSnapshotContainingTheProvider()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig());

        var ok = Assert.IsType<OkObjectResult>(harness.Controller.SamlProviders());
        var snapshot = Assert.IsType<SerializableDictionary<string, SamlConfig>>(ok.Value);
        Assert.True(snapshot.ContainsKey("adfs"));
    }
}

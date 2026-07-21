// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Secrets;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the provider-add endpoints via <see cref="SsoControllerHarness"/>: a valid
/// config is stored, a malformed base-URL override is rejected fail-closed, a re-save preserves the
/// server-managed canonical links (#157) and the write-only OpenID secret (#189 — kept when the provider
/// identity is unchanged, dropped when the endpoint changes) that the API body never carries, and a NEW
/// provider name containing URI-reserved characters is rejected while an existing one stays updatable (#336).
/// </summary>
[Collection("SSOController")]
public class SSOControllerAddTests
{
    private static readonly Guid User = Guid.Parse("33333333-3333-3333-3333-333333333333");

    [Fact]
    public void OidAdd_ValidConfig_StoresTheProvider()
    {
        var harness = new SsoControllerHarness();

        harness.Controller.OidAdd("keycloak", new OidConfig { OidClientId = "client-1" });

        var stored = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].OidClientId);
        Assert.Equal("client-1", stored);
    }

    [Fact]
    public void OidAdd_MalformedBaseUrlOverride_Throws_AndDoesNotPersist()
    {
        var harness = new SsoControllerHarness();

        Assert.Throws<ArgumentException>(() => harness.Controller.OidAdd("keycloak", new OidConfig { BaseUrlOverride = "not-a-url" }));

        // Fail-closed: the reject runs before the write, so nothing was persisted.
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("keycloak")));
    }

    [Fact]
    public void OidAdd_RequireAcrWithoutAcrValues_Throws_AndDoesNotPersist()
    {
        // #757: the Add API persists through MutateConfiguration and so bypasses the config-page save-time
        // Validate; the acr footgun guard must be mirrored here too, or RequireAcr with no acr_values would
        // persist and refuse every login for the provider (a silent single-provider lockout).
        var harness = new SsoControllerHarness();

        Assert.Throws<ArgumentException>(() => harness.Controller.OidAdd("keycloak", new OidConfig { RequireAcr = true }));

        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("keycloak")));
    }

    [Fact]
    public void OidAdd_RequireAcrWithAcrValues_Persists()
    {
        // The valid combination is accepted and stored.
        var harness = new SsoControllerHarness();

        harness.Controller.OidAdd("keycloak", new OidConfig { RequireAcr = true, AcrValues = "mfa" });

        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("keycloak")));
    }

    [Fact]
    public void OidAdd_NullBody_Throws_AndDoesNotPersist()
    {
        var harness = new SsoControllerHarness();

        Assert.Throws<ArgumentException>(() => harness.Controller.OidAdd("keycloak", null!));

        // Fail-closed: a null [FromBody] is rejected at the door, so no null entry is stored (#350).
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("keycloak")));
    }

    [Fact]
    public void SamlAdd_NullBody_Throws_AndDoesNotPersist()
    {
        var harness = new SsoControllerHarness();

        Assert.Throws<ArgumentException>(() => harness.Controller.SamlAdd("adfs", null!));

        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs.ContainsKey("adfs")));
    }

    [Fact]
    public void OidAdd_ReSaveOfExisting_PreservesCanonicalLinks()
    {
        var harness = new SsoControllerHarness(c =>
            c.OidConfigs["keycloak"] = new OidConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = User } });

        // Re-add the same provider with a fresh config carrying no links, as the [JsonIgnore] API body would.
        harness.Controller.OidAdd("keycloak", new OidConfig());

        var links = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks);
        Assert.Equal(User, links["sub-1"]);
    }

    [Fact]
    public void OidAdd_ReSaveWithBlankSecret_UnchangedIdentity_KeepsStoredSecret()
    {
        // #189 blank-means-keep at the OidAdd door: a re-save carrying a blank secret (as the write-only
        // API body does) but the same provider identity keeps the stored secret. Pins the SECRET half of
        // ServerManagedFields.Preserve at the endpoint — the links half is covered above, but the
        // zero-occurrence conformance rule (#383) no longer guarantees the Preserve CALL routes the
        // secret, so a future links-only substitute must fail here rather than silently wipe #189.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] =
            new OidConfig { OidSecret = "stored-secret", OidEndpoint = "https://idp.example/", OidClientId = "client-1" });

        harness.Controller.OidAdd("keycloak", new OidConfig { OidSecret = string.Empty, OidEndpoint = "https://idp.example/", OidClientId = "client-1" });

        // The persisted secret is now encrypted at rest (#158), so read the stored value and reveal it: the
        // #189 blank-means-keep contract is that the ORIGINAL secret survives the re-save, and reveal
        // round-trips it. The stored form is an envelope, not the plaintext.
        var stored = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].OidSecret);
        Assert.True(SecretEnvelope.IsProtected(stored), "the kept secret must be stored encrypted at rest");
        Assert.Equal("stored-secret", SSOPlugin.Instance.Secrets.Reveal(stored));
    }

    [Fact]
    public void OidAdd_ReSaveWithBlankSecret_ChangedEndpoint_DropsStoredSecret()
    {
        // The #189 exfil guard: a blank secret with a CHANGED endpoint must NOT carry the stored secret
        // over (it stays blank, failing login closed), so a write-only secret cannot be pulled toward a
        // different token endpoint. Also pinned at the endpoint now that the conformance rule is
        // presence-agnostic.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] =
            new OidConfig { OidSecret = "stored-secret", OidEndpoint = "https://idp.example/", OidClientId = "client-1" });

        harness.Controller.OidAdd("keycloak", new OidConfig { OidSecret = string.Empty, OidEndpoint = "https://attacker.example/", OidClientId = "client-1" });

        var stored = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"]);
        // The identity genuinely changed (so the drop is via the ResolveUpdatedSecret identity-change
        // branch, not the unchanged branch), and the stored secret was dropped, not carried to it — this
        // arm guards against an always-keep regression (Test 1 covers the links-only/never-keep case).
        Assert.Equal("https://attacker.example/", stored.OidEndpoint);
        Assert.True(string.IsNullOrEmpty(stored.OidSecret));
    }

    [Fact]
    public void SamlAdd_ValidConfig_StoresTheProvider_ReturnsOk()
    {
        var harness = new SsoControllerHarness();

        Assert.IsType<OkResult>(harness.Controller.SamlAdd("adfs", new SamlConfig { SamlClientId = "client-1" }));

        var stored = SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs"].SamlClientId);
        Assert.Equal("client-1", stored);
    }

    [Fact]
    public void SamlAdd_MalformedBaseUrlOverride_Throws_AndDoesNotPersist()
    {
        var harness = new SsoControllerHarness();

        Assert.Throws<ArgumentException>(() => harness.Controller.SamlAdd("adfs", new SamlConfig { BaseUrlOverride = "not-a-url" }));

        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs.ContainsKey("adfs")));
    }

    [Fact]
    public void SamlAdd_ReSaveOfExisting_PreservesCanonicalLinks()
    {
        var harness = new SsoControllerHarness(c =>
            c.SamlConfigs["adfs"] = new SamlConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-1"] = User } });

        harness.Controller.SamlAdd("adfs", new SamlConfig());

        var links = SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs"].CanonicalLinks);
        Assert.Equal(User, links["nameid-1"]);
    }

    // --- Provider-name validation at registration (#336) ---

    [Fact]
    public void OidAdd_NewProviderWithReservedName_Throws_AndDoesNotPersist()
    {
        var harness = new SsoControllerHarness();

        Assert.Throws<ArgumentException>(() => harness.Controller.OidAdd("my/realm", new OidConfig()));

        // Fail-closed: the guard runs inside the mutation before any write, so nothing was persisted.
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("my/realm")));
    }

    [Fact]
    public void OidAdd_ExistingProviderWithReservedName_StillUpdates()
    {
        // An already-configured reserved-character name is exempt (#336): its callback-URL bytes are
        // registered at the IdP, so the update path must keep working for existing deployments.
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc=prod"] = new OidConfig());

        harness.Controller.OidAdd("kc=prod", new OidConfig { OidClientId = "client-2" });

        var stored = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["kc=prod"].OidClientId);
        Assert.Equal("client-2", stored);
    }

    [Fact]
    public void SamlAdd_NewProviderWithReservedName_Throws_AndDoesNotPersist()
    {
        var harness = new SsoControllerHarness();

        Assert.Throws<ArgumentException>(() => harness.Controller.SamlAdd("prov%1", new SamlConfig()));

        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs.ContainsKey("prov%1")));
    }

    [Fact]
    public void SamlAdd_ExistingProviderWithReservedName_StillUpdates()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs (legacy)"] = new SamlConfig());

        Assert.IsType<OkResult>(harness.Controller.SamlAdd("adfs (legacy)", new SamlConfig { SamlClientId = "client-2" }));

        var stored = SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs (legacy)"].SamlClientId);
        Assert.Equal("client-2", stored);
    }

    [Fact]
    public void OidAdd_CaseVariantOfExistingReservedName_IsTreatedAsNew_AndRejected()
    {
        // The grandfather exemption is keyed on the ordinal, case-sensitive dictionary the login lookup
        // also uses, so a case variant of an existing name is a genuinely different runtime provider,
        // not the exempt one — it must be rejected, not silently accepted as "already configured".
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc=prod"] = new OidConfig());

        Assert.Throws<ArgumentException>(() => harness.Controller.OidAdd("KC=prod", new OidConfig()));

        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("KC=prod")));
    }

    [Fact]
    public void OidAdd_ReAddingADeletedGrandfatheredReservedName_IsRejected()
    {
        // The exemption is by LIVE config, so it is a one-way door: once a grandfathered reserved-name
        // provider is removed, the name is "new" again and cannot be re-added through the API. Pins the
        // documented recovery boundary (README: recover by editing config.xml on disk).
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc=prod"] = new OidConfig());

        harness.Controller.OidDel("kc=prod");
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("kc=prod")));

        Assert.Throws<ArgumentException>(() => harness.Controller.OidAdd("kc=prod", new OidConfig()));
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("kc=prod")));
    }

    [Fact]
    public async Task OidAdd_DisablingAProviderWithLinkedUsers_DoesNotRevokeAnyTokens()
    {
        // #468 documented decision — per-provider disable is intentionally NOT a token-revocation trigger.
        // Jellyfin attributes no live session to the originating SSO provider (RevokeUserTokens is scoped to
        // a user id, not a provider), so revoking on disable would be an unscoped mass-logout of every linked
        // user's password and other-provider sessions too. Disabling only fails FUTURE logins closed (#343);
        // pin that no revoke fires for the linked user when a provider is switched off via a re-add.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = new OidConfig
        {
            Enabled = true,
            OidClientId = "client-1",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = User },
        });

        // The config page's disable path re-adds the provider with Enabled=false; server-managed links are
        // preserved (ServerManagedFields.Preserve), so the user stays linked but the provider is off.
        harness.Controller.OidAdd("keycloak", new OidConfig { Enabled = false, OidClientId = "client-1" });

        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].Enabled));
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
    }
}

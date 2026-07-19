# Release rollback (plugin downgrade) runbook

For an authentication plugin a bad stable release is a **mass-lockout event**:
every OpenID and SAML login can go down at once (this is exactly what 4.1.0.0 →
4.1.1.0 fixed — 4.1.0.0 failed to load on Jellyfin 10.11 and the server disabled
it at startup, taking down every login). Rollback is therefore the last-line
**availability** control, and DORA's 2025/26 research names small batches plus a
practised rollback path as the moderating capabilities for release instability.

This document is the operator's rollback procedure, the per-version
downgrade-safety notes drawn from the actual [CHANGELOG](CHANGELOG.md)
format-change history, a pre-downgrade check, an operator drill, and the
maintainer procedure to pull a bad release from the published manifest.

Rollback is only ever needed for a **stable** channel release. Beta channels
(`X.Y.Z-beta.*`, `manifest-beta`) are opt-in and are not covered here.

---

## 1. How Jellyfin installs and downgrades this plugin

Jellyfin installs plugins from a **manifest** (`manifest.json`) served on the
`manifest-release` branch and published by the release pipeline
([`.github/workflows/publish.yml`](.github/workflows/publish.yml), via the
`Kevinjil/jellyfin-plugin-repo-action`). Each manifest entry lists every
published version with its `version`, `sourceUrl` (the release zip),
`checksum`, and `targetAbi`.

Key facts that make rollback possible:

- **The manifest retains previous versions.** The publish action _appends_ the
  new version to the existing manifest; it does not replace the list. As of this
  writing the published `manifest-release/manifest.json` retains
  `4.2.1`, `4.2.0`, `4.1.1`, and `4.1.0.0` (the manifest was introduced at
  4.1.0.0; releases older than that live only as GitHub release assets, not in
  the manifest). An operator can therefore select an **older version** from the
  Jellyfin catalog and downgrade without leaving the dashboard.
- **Higher version wins for "update", but install is explicit.** Jellyfin's
  catalog offers the highest compatible version as the update. A downgrade is a
  deliberate act: uninstall the current version and install the specific older
  version, or install the older version's zip by hand.
- **`targetAbi` gates visibility.** A version only appears installable on a
  server whose ABI is >= the entry's `targetAbi` (currently `10.11.0.0`). A
  downgrade target must itself satisfy the running server's ABI.

There are two operator rollback mechanisms, in order of preference:

1. **Catalog downgrade** — in the Jellyfin dashboard, uninstall the current SSO
   plugin, then install the prior version from the plugin catalog (the manifest
   still lists it). Restart Jellyfin.
2. **Manual zip install** — download the prior version's
   `sso-authentication_X.Y.Z.0.zip` from its GitHub release (the `sourceUrl` in
   the manifest, or the Releases page), verify its `.sha256`, and drop it into
   the plugin data folder as Jellyfin expects. Use this if the manifest itself
   is the problem, or if the target version predates the manifest.

---

## 2. What actually breaks on downgrade

Two on-disk surfaces determine whether an older build can run on data a newer
build has already written:

### 2a. `PluginConfiguration` (the config XML)

The config is XML-serialized from
[`SSO-Auth/Config/PluginConfiguration.cs`](SSO-Auth/Config/PluginConfiguration.cs)
via Jellyfin's `BasePluginConfiguration`. **There is no schema-version field.**
Compatibility rests on XmlSerializer's tolerance:

- **Adding a field is downgrade-safe.** An older build simply ignores config
  elements it does not know (e.g. the `EnableRateLimit` /
  `RateLimitMaxAttempts` / `RateLimitWindowSeconds` fields added in 4.1.0.0 are
  silently dropped by a pre-4.1.0.0 build; missing fields fall back to their
  constructor defaults).
- **The break is not the XML shape — it is the secret _values_ inside it.** See
  2b. A config written by a newer build parses structurally under an older build;
  the failure is that the older build cannot _decrypt_ the secret strings.

So for this plugin, "config N-1 load compatibility" holds at the serialization
layer across every adjacent version to date. The one real cross-version hazard
is the secret-at-rest format boundary.

### 2b. The secret-at-rest format (the downgrade boundary)

The provider secrets — the OpenID client secret (`OidSecret`) and the SAML
signing keys (`SamlSigningKeyPfx`, `SamlRolloverSigningKeyPfx`) — are, since
**4.1.0.0 (#158)**, stored as an **AES-256-GCM `ssoenc:v1:` envelope** rather
than plaintext (see
[`SSO-Auth/Api/SecretEnvelope.cs`](SSO-Auth/Api/SecretEnvelope.cs) and
[Secrets encrypted at rest and downgrade](providers.md#secrets-encrypted-at-rest-and-downgrade)).

- **Upgrade is transparent / forward-compatible.** A plaintext config is read
  as-is and each secret is re-wrapped as an envelope on the next save. No action
  on the way up.
- **Downgrade across this boundary is breaking.** A build _without_ #158 cannot
  read `ssoenc:` values. After downgrading below 4.1.0.0, the affected
  OpenID/SAML providers behave as if their secret were **unset** — logins fail
  closed. The `ssoenc:v1:` envelope is a versioned, self-describing format, so
  the format can evolve; any future bump of that version prefix is a new
  downgrade boundary of the same kind.
- **The data-encryption key is a separate file.** `sso-secret.key` lives in the
  plugin data folder, separate from the config XML (owner-only `0600` on Linux).
  Older versions ignore it; it can be left in place. Never delete it while any
  `ssoenc:` value exists — without it, every encrypted secret is permanently
  unrecoverable.

**The crossing rule:** downgrading **from >= 4.1.0.0 to < 4.1.0.0** crosses the
secret-format boundary and requires re-entering secrets (or restoring a
pre-upgrade plaintext config backup). Downgrading **within the 4.1.x / 4.2.x
range** (e.g. 4.2.1 → 4.2.0 → 4.1.1 → 4.1.0.0) does **not** cross it — every
build in that range reads `ssoenc:v1:` — so no secret re-entry is needed.

---

## 3. Per-version downgrade-safety notes

Read this as: "if I am downgrading _away from_ version X, what do I have to
account for?" Flags come from the CHANGELOG / `build.yaml` format-change history.

| Downgrading away from          | Crosses a format/compat boundary?                                                                                                                                  | What to do before rolling back                                                                                                                                                                                                               |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **4.2.1.0** → 4.2.0.0          | No. Bug-fix only (null-context authz deny, #626).                                                                                                                  | Nothing beyond a config backup. Secrets stay `ssoenc:v1:`.                                                                                                                                                                                   |
| **4.2.0.0** → 4.1.x            | Behavioural, not on-disk. 4.2.0.0 removed the legacy raw-SAML-assertion `SAML/Auth` path (#528); older builds still accept it.                                     | Nothing on-disk. Any client scripted against the one-time token flow keeps working on the older build too. Config/secrets unchanged.                                                                                                         |
| **4.1.1.0** → 4.1.0.0          | No on-disk change, but **do not**: 4.1.0.0 is the broken build that fails to load on Jellyfin 10.11 (#590).                                                        | Avoid 4.1.0.0 as a rollback target on JF 10.11 — it will disable itself at startup. Roll back to 4.1.1.0 or hold.                                                                                                                            |
| **4.1.0.0** → 4.0.x or earlier | **Yes — breaking on-disk secret format (#158).** Older builds cannot read `ssoenc:` secrets; **also** the OpenID legacy-username link migration (#358) is one-way. | Re-enter every provider secret in plaintext (or restore a pre-4.1.0.0 config backup) **before** installing the older build. Expect linked OpenID accounts keyed on legacy usernames to need admin re-linking. Leave/remove `sso-secret.key`. |
| **4.0.x / 3.5.x and earlier**  | Pre-manifest, pre-encryption. Historic BREAKING markers: 4.0.0.0 (JF 10.11), 3.2.0.0 (hashmap switch).                                                             | Legacy territory; secrets were plaintext. Restore the matching-era config backup; these versions are not in `manifest.json` and must be installed from their GitHub release zip.                                                             |

**One-line rule of thumb:** any downgrade that ends **below 4.1.0.0** requires
secret re-entry or a plaintext config restore. Any downgrade **at or above
4.1.0.0** is config-safe — just avoid landing exactly on 4.1.0.0 on JF 10.11.

---

## 4. Pre-downgrade check (do this before you roll back)

- [ ] **Back up the config.** Copy the plugin's configuration XML
      (`.../plugins/configurations/Jellyfin.Plugin.SSO_Auth.xml` or equivalent)
      to a safe location. This is your restore point regardless of what breaks.
- [ ] **Back up `sso-secret.key`** from the plugin data folder alongside the
      config. (Needed if you re-upgrade later; harmless to an older build.)
- [ ] **Identify the target version and whether it crosses the 4.1.0.0 secret
      boundary** (section 3). If it lands below 4.1.0.0, plan the secret
      re-entry step now — have each provider's client secret / signing key `.pfx`
      to hand.
- [ ] **Confirm the target version is manifest-listed and ABI-compatible.**
      Check it appears in `manifest-release/manifest.json` with a `targetAbi`
      your server satisfies (`10.11.0.0`). If not, plan a manual zip install
      from the GitHub release and verify the `.sha256`.
- [ ] **Do NOT choose 4.1.0.0 as a rollback target on Jellyfin 10.11** (#590 —
      it disables itself at startup).
- [ ] **Note whether a config export exists.** A `ConfigExport` document is
      **redacted** — it carries no secret and no `ssoenc:` envelope
      ([providers.md](providers.md#the-export-is-redacted--secrets-never-leave-the-server)),
      so it is **not** a secret backup. It restores structure only; secrets
      still need re-entry. The raw config XML plus `sso-secret.key` is the real
      backup pair.

---

## 5. Operator drill (rollback in practice)

A short, followable sequence. Practise it on a staging instance so it is muscle
memory before a real incident.

1. **Snapshot.** Stop Jellyfin (or at least stop new logins). Copy the config
   XML and `sso-secret.key` out (section 4).
2. **Decide the target.** Pick the last-known-good version. Determine from
   section 3 whether it crosses the 4.1.0.0 secret boundary.
3. **If crossing below 4.1.0.0:** while still on the newer build, either export
   nothing useful for secrets — instead **restore the pre-upgrade plaintext
   config backup** after the downgrade, or be ready to re-enter each secret on
   the older build's settings page.
4. **Uninstall** the current SSO plugin in the dashboard.
5. **Install the target version** — catalog (older version still listed) or the
   verified GitHub zip.
6. **Restore config if needed** (plaintext backup for a below-4.1.0.0 target).
7. **Restart Jellyfin.**
8. **Verify the plugin loaded** (dashboard shows it active, no startup-disabled
   state — the 4.1.0.0 failure mode manifested as the server disabling the
   plugin at startup).
9. **Smoke-test one OpenID and one SAML login** end to end (challenge →
   callback → session minted). A "secret unset" symptom here means you crossed
   the secret boundary and still owe a re-entry.
10. **Re-enable logins / restore traffic.** Record what happened and why, and
    open/annotate the issue for the bad release.

---

## 6. Maintainer: pull a bad release from the manifest

If a published stable is bad, the fastest containment is to stop _new_
installs/updates from picking it up, then ship a fix-forward.

- **Preferred — fix forward.** Publish a higher patch version (as 4.1.1.0
  superseded the broken 4.1.0.0). Because higher-version-wins drives the
  catalog's "update", a good higher version pulls the fleet forward without any
  manifest surgery. This is the primary path.
- **Contain by de-listing the bad version.** To stop the bad version being
  _offered_ for fresh installs, remove **that version's entry** from the
  `versions` array in `manifest-release/manifest.json` (a commit on the
  `manifest-release` branch). The manifest is the install source of truth;
  de-listing removes it from every server's catalog. Leave the other entries
  intact so downgrade targets remain available. The GitHub **release itself
  stays** — do not delete it: a deleted immutable release permanently burns its
  tag (`publish.yml` header), and the zip is still the `sourceUrl` for anyone
  doing a manual install.
- **Never delete the release or reuse the tag.** Tags are immutable and
  single-use; a fix ships as a new version + new `-stable` tag, never a re-cut
  of the old one.
- **Announce.** Note the bad version and the fixed version in `CHANGELOG.md` and
  the release notes so operators who already installed it know to move.

---

## 7. E2E downgrade smoke check (wire into `/release-prep`)

Before publishing a stable, confirm the rollback path still works. This mirrors
the manual-check discipline in
[RELEASE-QA-CHECKLIST.md](RELEASE-QA-CHECKLIST.md) (packaging/install/upgrade is
already a manual item there — this is its downgrade twin):

- [ ] **Manifest retains prior versions.** After the dry-run/publish, confirm
      the new `manifest.json` still lists the previous stable version(s), not
      only the new one.
- [ ] **Downgrade smoke.** On a staging server running the release candidate
      with a saved config (secrets encrypted as `ssoenc:v1:`), uninstall it and
      install the previous stable from the catalog. Confirm: the older build
      **loads** (not startup-disabled), the config parses, and a login still
      succeeds **without** re-entering secrets — proving no unintended secret- or
      config-format boundary was crossed within the supported range.
- [ ] **Boundary note reviewed.** If this release changes the secret envelope
      version, the `PluginConfiguration` shape in a non-additive way, or any
      other on-disk format, section 3 of this document and `CHANGELOG.md` are
      updated with the new downgrade flag before publishing.

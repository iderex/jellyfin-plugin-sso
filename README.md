<!-- markdownlint-disable MD041 -->

> [!NOTE]
>
> **Status: Beta** — the third rung of the maturity ladder (**In-Development → Alpha → Beta → Release Candidate → Full Release**; see the [Roadmap](https://github.com/iderex/jellyfin-plugin-sso/wiki/Roadmap)). Installable by adding this plugin's own repository to Jellyfin (see [Installing](#installing)).

<h1 align="center">Jellyfin SSO Plugin</h1>

<p align="center">
<img alt="Jellyfin SSO Plugin" src="https://raw.githubusercontent.com/iderex/jellyfin-plugin-sso/main/img/banner.png" width="820"/>
<br/>
<br/>
<a href="https://github.com/iderex/jellyfin-plugin-sso/blob/main/LICENSE.txt">
<img alt="GPL 3.0 License" src="https://img.shields.io/github/license/iderex/jellyfin-plugin-sso.svg"/>
</a>
<a href="https://github.com/iderex/jellyfin-plugin-sso/releases">
<img alt="Latest release" src="https://img.shields.io/github/v/release/iderex/jellyfin-plugin-sso?display_name=tag&label=release"/>
</a>
<a href="https://github.com/iderex/jellyfin-plugin-sso/actions/workflows/dotnet.yml">
<img alt="Build Status" src="https://github.com/iderex/jellyfin-plugin-sso/actions/workflows/dotnet.yml/badge.svg"/>
</a>
<a href="https://github.com/iderex/jellyfin-plugin-sso/wiki">
<img alt="Documentation" src="https://img.shields.io/badge/docs-wiki-blue"/>
</a>
<a href="https://www.bestpractices.dev/projects/13660">
<img alt="OpenSSF Best Practices" src="https://www.bestpractices.dev/projects/13660/badge"/>
</a>
<a href="https://securityscorecards.dev/viewer/?uri=github.com/iderex/jellyfin-plugin-sso">
<img alt="OpenSSF Scorecard" src="https://api.securityscorecards.dev/projects/github.com/iderex/jellyfin-plugin-sso/badge"/>
</a>
</p>

<p align="center">
Sign in to Jellyfin with your existing identity provider — Keycloak, Authelia, authentik, Entra ID, Google, and more — over <b>OpenID&nbsp;Connect</b> or <b>SAML&nbsp;2.0</b>, instead of a separate Jellyfin password.
</p>

> ### 🔁 Revival
>
> This is a revival of [**9p4/jellyfin-plugin-sso**](https://github.com/9p4/jellyfin-plugin-sso), which its original author has since archived. It continues from the last upstream release (**4.0.0.x**, Jellyfin 10.11 / .NET 9) and is taken forward **security-first**. Its hardened sibling project, **`jellyfin-plugin-sso-V2`** (private), is the reference this repository draws on — ported across deliberately, one reviewed change at a time. Huge thanks to the original author and contributors for the foundation.
>
> **Status:** **Beta** — the third stage of the maturity ladder. See the [Roadmap](https://github.com/iderex/jellyfin-plugin-sso/wiki/Roadmap) for what each stage gates, and [Installing](#installing) — a packaged release is now installable by adding this plugin's own repository to Jellyfin, with build-from-source as the alternative.
>
> ### How this project is developed
>
> This is a **security-sensitive login path**, so every change — even a one-liner — runs the same gated flow: a GitHub **issue** first, then a short-lived work branch, an implementation with **tests** (a negative test for every fail-closed branch), an **adversarial security review** for anything touching the login path or crypto, and a pull request that must pass **CI** (build with warnings-as-errors, the full test suite, format and conformance checks) and **CodeQL** — before it merges. We review and quality-gate our own work; no external review service is a merge gate. Security work always outranks feature work, and the code stays minimal and self-documenting.
>
> If you contribute, please work the same way: understand and own every line you propose, and be ready to explain what it does and why. 🙂
>
> ### 🤝 AI-assisted, human-owned
>
> Development here is **AI-assisted**. Claude (Anthropic) helps with individual **process steps** — generating and analysing code, running the adversarial security reviews, and translating documentation and comments into English. It never hands over finished, unreviewed work: each step is only a proposal. **A human maintainer reviews, understands, edits where needed, and signs off on every one** — the AI proposes, a person decides, and **a human stays responsible for every line that ships, at all times.** The review discipline is modelled, as far as is practical for a volunteer project, on the change-control expected of TÜV/BSI-certified software in a critical sector such as healthcare — with **no claim to actual certification**. In short: nothing lands because a tool suggested it; it lands because a person verified it.

## Features

- **OpenID Connect and SAML 2.0** — either or both, multiple providers side by side. See the [Provider Setup](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup).
- **Role-based access control** — map identity-provider groups/roles to login, administrator, library folders, and Live TV.
- **Hardened, fail-closed login path** — identities bound to the stable `sub` / `NameID`, fail-closed SAML and `id_token` validation, and SSRF-guarded avatar fetches. Details on the [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model) page.
- **Optional SSO-only login** — disable password login for every account except a designated break-glass admin, behind a fail-closed last-admin guard so no configuration can strand a server without a working admin login. Runbook on the [Provider Setup](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup#sso-only-login-disable-password-login) page.
- **Avatar sync, Quick Connect, and self-service account linking**.
- **Tested** — a growing xUnit suite over the security-critical paths, with CI (build, format, CodeQL) on every change.

> The feature set from the sibling project is being ported here one reviewed change at a time; this list reflects what is implemented today.

## Supported providers

Any OIDC-conformant or SAML 2.0 identity provider should work. These have verified, step-by-step guides on the [Provider Setup](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup) wiki page:

| Provider                                                                                                                                                                                    | OIDC | SAML | Role mapping (RBAC) |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--: | :--: | :-----------------: |
| [Authelia](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup#authelia)                                                                                                      |  ✔   |  —   |          ✔          |
| [authentik](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup#authentik)                                                                                                    |  ✔   |  —   |          ✔          |
| Keycloak ([OIDC](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup#keycloak-oidc), [SAML](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup#keycloak-saml)) |  ✔   |  ✔   |          ✔          |
| [Pocket ID](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup#pocket-id)                                                                                                    |  ✔   |  —   |          ✔          |
| [Kanidm](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup#kanidm)                                                                                                          |  ✔   |  —   |          ✔          |
| Google                                                                                                                                                                                      |  ✔   |  —   |          —          |

"—" under SAML means no verified guide yet, not that it cannot work. Google works without role mapping and with caveats (numeric usernames; endpoint validation must be relaxed) — see the wiki. A guide for a provider you use is a welcome contribution.

## How it compares

Honest positioning against the alternatives — pick what fits your setup:

|                                  | This plugin                                                                                                              | Jellyfin built-in auth | Official [LDAP plugin](https://github.com/jellyfin/jellyfin-plugin-ldapauth) | Archived [9p4 plugin](https://github.com/9p4/jellyfin-plugin-sso)                               |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ---------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Sign-in model                    | Delegated to your IdP (OIDC / SAML)                                                                                      | Local passwords        | Directory bind (LDAP/AD)                                                     | Delegated to your IdP (OIDC / SAML)                                                             |
| Passwords touch Jellyfin         | No (optional SSO-only mode)                                                                                              | Yes                    | Yes (bind credentials)                                                       | No                                                                                              |
| Role / permission mapping        | ✔ from IdP claims (admin, folders, Live TV)                                                                              | Manual per user        | ✔ from LDAP attributes                                                       | ✔ from IdP claims                                                                               |
| Account linking (existing users) | ✔ self-service                                                                                                           | n/a                    | ✔ (by username)                                                              | ✔                                                                                               |
| Maintenance status               | Active (Beta)                                                                                                            | Active (core)          | Active (official)                                                            | Archived, unmaintained                                                                          |
| Security process                 | Adversarial review + CI gates per change ([Review Gate](https://github.com/iderex/jellyfin-plugin-sso/wiki/Review-Gate)) | Jellyfin core process  | Jellyfin org process                                                         | —                                                                                               |
| Native clients                   | Via Quick Connect                                                                                                        | ✔ everywhere           | ✔ everywhere                                                                 | Via Quick Connect                                                                               |
| Best when                        | You run an IdP (or want one) and want passwords out of Jellyfin                                                          | Small setups, no IdP   | You have AD/LDAP but no web IdP                                              | (migrate here — [guide](https://github.com/iderex/jellyfin-plugin-sso/wiki/Migrating-from-9p4)) |

The LDAP plugin and this one solve different problems and can even coexist; if you already run Authelia/authentik/Keycloak, this plugin is the direct path. Coming from the archived 9p4 plugin, migration is an in-place upgrade.

Jellyfin upstream is building [native OIDC](https://github.com/jellyfin/jellyfin/pull/17271) (13.0 at the earliest). This plugin **complements** it rather than competing: it remains the option for **SAML 2.0, folder/Live-TV role mapping, account linking, avatar sync and SSO-only mode** — and for every current server release. Full stance: [Native OIDC Coexistence](https://github.com/iderex/jellyfin-plugin-sso/wiki/Native-OIDC-Coexistence).

## Installing

> **This is an independent plugin repository.** Jellyfin's built-in catalog only lists plugins that live in the [`jellyfin`](https://github.com/jellyfin) GitHub org, and there is currently no official SSO plugin there (the LDAP plugin is the only official auth plugin). You install this plugin by adding **its** repository (below) under **Plugins → Repositories**; it then appears in your in-app catalog. The project is independent for now.

**Add this plugin's repository, then install from the in-app catalog (recommended for testing):**

1. In Jellyfin, go to **Dashboard → Plugins → Repositories** and add the repository URL for the channel you want. **One URL serves both Jellyfin generations** — your server installs the matching build automatically. Add **one** of these:

   | Channel    | Repository URL                                                                                |
   | ---------- | --------------------------------------------------------------------------------------------- |
   | **stable** | `https://raw.githubusercontent.com/iderex/jellyfin-plugin-sso/manifest-release/manifest.json` |
   | **beta**   | `https://raw.githubusercontent.com/iderex/jellyfin-plugin-sso/manifest-beta/manifest.json`    |
   - **stable** ships tagged releases only. **beta** publishes on every merge, so betas move fast and may break — use them for testing, not production.
   - Each manifest lists builds for **both Jellyfin 10.11** (.NET 9) and **Jellyfin 12.0** (.NET 10). Jellyfin filters by the plugin's target ABI, so your server is only ever offered the build that runs on it — you don't pick the generation, it does. Jellyfin 12.0 support is currently **beta only** (the stable 12.0 build lands at a 12.0 stable release).

2. Go to **Dashboard → Plugins → Catalog**, find **SSO Authentication**, and install it.
3. **Restart Jellyfin** to load the plugin.

The plugin GUID is unchanged from the original `9p4` plugin, so a new version installs over an existing one in place and keeps your existing configuration. To switch channels, replace the repository URL and let the catalog offer the other channel's build.

**Build from source (alternative):**

```
dotnet publish -c Release
```

Copy the **full publish output** (`SSO-Auth.dll` and every dependency DLL beside it — the OpenID client, the embedded library, and the other referenced assemblies) into your Jellyfin plugins directory under `config/plugins/sso/`, then restart Jellyfin. Copying only a subset can leave Jellyfin unable to load the plugin. [JPRM](https://github.com/oddstr13/jellyfin-plugin-repository-manager) packages the correct set for you if you prefer.

**Client support:** SSO sign-in runs in the Jellyfin **Web UI** and in clients that support **Quick Connect** (the mobile and TV apps drive the login through Quick Connect). A native client that does not support Quick Connect cannot complete the browser redirect flow — use the Web UI or a Quick Connect client there.

**Coming from the old plugin repository?** This project is the maintained continuation of the archived `9p4/jellyfin-plugin-sso`. If your Jellyfin still points at the old `9p4` manifest — or at any other now-dead SSO manifest URL, such as a former `jellyfin-plugin-sso-V2` one — it will not receive updates from here. Packaged releases have resumed: replace the stale plugin-repository URL with the 10.11 stable manifest (`https://raw.githubusercontent.com/iderex/jellyfin-plugin-sso/manifest-release/manifest.json`) under **Dashboard → Plugins → Repositories**, then install **SSO Authentication** from the catalog. The plugin GUID is unchanged, so it updates in place and keeps your existing configuration.

## Configuration

Configure your providers on the plugin's settings page (**Dashboard → Plugins → SSO-Auth**) and via the admin API. The [Provider Setup](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup) walks through setup for common identity providers.

Provider names become part of the callback URLs you register with your identity provider — OpenID Connect: `.../sso/OID/redirect/PROVIDER_NAME`; SAML: `.../sso/SAML/post/PROVIDER_NAME` — so a newly added name on **either protocol** must not contain control characters (such as a tab or newline), `%`, a backslash, or URI-reserved characters (`: / ? # [ ] @ ! $ & ' ( ) * + , ; =`) — registration rejects such names. Names that are already configured keep working unchanged; note that this exemption is by live configuration, so once you **delete** a provider whose name uses one of these characters you cannot re-add it through the UI or API (nor restore it from a full-config backup) — recover by editing `config.xml` on disk.

> **Scripting the admin API?** The provider-management endpoints use Jellyfin's `RequiresElevation` policy — pass your admin API key in the header (`-H 'Authorization: MediaBrowser Token="YOUR_KEY"'`) rather than as a `?api_key=` query parameter, which would leak the secret into proxy logs, the process list, and shell history.

## Documentation

Broader documentation lives in the **[Wiki](https://github.com/iderex/jellyfin-plugin-sso/wiki)**:

- [Installation](https://github.com/iderex/jellyfin-plugin-sso/wiki/Installation) · [Login Flow](https://github.com/iderex/jellyfin-plugin-sso/wiki/Login-Flow) · [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model) · [Troubleshooting](https://github.com/iderex/jellyfin-plugin-sso/wiki/Troubleshooting)
- Per-identity-provider setup: [Provider Setup](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup)
- In-tree contributor map of the login flow and code layout: [Architecture Internals](https://github.com/iderex/jellyfin-plugin-sso/wiki/Architecture-Internals)
- Project policies: [Governance](GOVERNANCE.md) · [Privacy & data handling](docs/PRIVACY.md) · [Support & security updates](SECURITY.md#supported-versions--security-updates) · [Remediation & secrets policy](docs/SECURITY-REMEDIATION-POLICY.md)
- Honest maturity self-assessment (Silver/Gold + OSPS, incl. what a solo project structurally cannot meet): [Maturity Map](https://github.com/iderex/jellyfin-plugin-sso/wiki/Maturity-Map)

## Security

This plugin is built to **fail closed by default**: a missing signature, a weak SHA-1 signature, an under-strength signing key (RSA below 2048 bits, or an EC key off the approved NIST P-256/384/521 curves), an out-of-bounds time window, a wrong audience, a replayed assertion, or an unrecognized identity is rejected rather than waved through. A few documented per-provider options (e.g. `DoNotValidateAudience`, `DoNotValidateIssuerName`) can deliberately relax specific checks for providers that need it — the [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model) page notes which. Two operator-facing controls:

- **Write-only client secret** — the OpenID secret is stored but never returned in a config response; on the settings page, leave it blank to keep the current value or type a new one to replace it.
- **Secrets encrypted at rest** — the OpenID client secret and the SAML request-signing key are stored in the config XML as AES-256-GCM `ssoenc:v1:` envelopes, encrypted under a key kept in a separate file (`sso-secret.key`) in the plugin data folder, so a leaked config alone cannot reveal them. Existing plaintext values keep working and are re-encrypted on the next save (transparent migration). This changes the on-disk format — see the [downgrade / rollback note](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup#secrets-encrypted-at-rest-and-downgrade) before rolling back.
- **Optional rate limiting** on the anonymous SSO endpoints (opt-in, off by default) to blunt brute force. Behind a reverse proxy, configure Jellyfin's _Known proxies_ setting so it targets the real client.

Details and tuning are on the [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model) wiki page; security-relevant behavior is covered by the test suite.

Found a vulnerability? Please report it **privately** via GitHub's ["Report a vulnerability"](https://github.com/iderex/jellyfin-plugin-sso/security/advisories/new) — not the public issue tracker. See [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. The plugin targets **.NET 9** and **Jellyfin 10.11**. Build with `dotnet build` / `dotnet publish` and run the tests with `dotnet test`. CI builds and tests every change, and the login path goes through an adversarial review. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## Credits

Built on the [Jellyfin LDAP plugin](https://github.com/jellyfin/jellyfin-plugin-ldapauth), [AspNetSaml](https://github.com/jitbit/AspNetSaml/) (SAML), and the [Duende IdentityModel OIDC Client](https://github.com/DuendeSoftware/foss) (OpenID Connect) — and on the original [9p4/jellyfin-plugin-sso](https://github.com/9p4/jellyfin-plugin-sso) and its contributors.

## License

Licensed under the [GNU GPL v3.0](https://github.com/iderex/jellyfin-plugin-sso/blob/main/LICENSE.txt).

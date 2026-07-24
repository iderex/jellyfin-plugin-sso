<!-- markdownlint-disable MD041 -->

> [!NOTE]
>
> **Status: Beta** — the third rung of the maturity ladder (In-Development → Alpha → Beta → Release Candidate → Full Release). Install it by adding this plugin's own repository to Jellyfin — see [Installing](#installing).

<h1 align="center">Community SSO for Jellyfin</h1>

<p align="center">
<img alt="Community SSO for Jellyfin" src="https://raw.githubusercontent.com/iderex/jellyfin-plugin-sso/main/img/banner.png" width="820"/>
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
> This is a security-first revival of [**9p4/jellyfin-plugin-sso**](https://github.com/9p4/jellyfin-plugin-sso), which its original author has since archived. It continues from the last upstream release (**4.0.0.x**, Jellyfin 10.11 / .NET 9). Huge thanks to the original author and contributors for the foundation.
>
> ### 🤝 AI-assisted, human-owned
>
> Development here is **AI-assisted**. Claude (Anthropic) helps with individual **process steps** — generating and analysing code, running the adversarial security reviews, and translating documentation and comments into English. It never hands over finished, unreviewed work: each step is only a proposal. **A human maintainer reviews, understands, edits where needed, and signs off on every one** — the AI proposes, a person decides, and **a human stays responsible for every line that ships, at all times.** The review discipline is modelled, as far as is practical for a volunteer project, on the change-control expected of TÜV/BSI-certified software in a critical sector such as healthcare — with **no claim to actual certification**. In short: nothing lands because a tool suggested it; it lands because a person verified it.

## Features

- **OpenID Connect and SAML 2.0** — either or both, multiple providers side by side.
- **Role-based access control** — map identity-provider groups/roles to login, administrator, library folders, Live TV, generic permissions, and a per-group parental-rating ceiling.
- **Hardened, fail-closed login path** — identities bound to the stable `sub` / `NameID`, fail-closed SAML and `id_token` validation, and SSRF-guarded avatar fetches.
- **Optional SSO-only login** — disable password login for every account except a designated break-glass admin, behind a fail-closed last-admin guard.
- **Avatar sync, Quick Connect, and self-service account linking.**
- **Tested** — a growing xUnit suite over the security-critical paths, with CI (build, format, CodeQL) on every change.

How this plugin compares to Jellyfin's built-in auth, the official LDAP plugin, and the archived 9p4 plugin: see the [Comparison](https://github.com/iderex/jellyfin-plugin-sso/wiki/Comparison) wiki page.

## Supported providers

Any OIDC-conformant or SAML 2.0 identity provider should work. Keycloak, Authelia, authentik, Dex, Pocket ID, Kanidm, Zitadel, and Google have verified, step-by-step guides — with the per-provider caveats — on the [Provider Setup](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup) wiki page.

The self-hostable providers run in an automated end-to-end login test in CI ([`e2e-login.yml`](.github/workflows/e2e-login.yml)); cloud providers (Google, Entra ID) can't run in ephemeral CI and are verified manually. A verified guide (or a test) for a provider you use is a welcome contribution.

## Installing

> **This is an independent plugin repository** — it is not in Jellyfin's built-in catalog. You install it by adding **its** repository under **Plugins → Repositories**.

1. In Jellyfin, go to **Dashboard → Plugins → Repositories** and add this repository URL (one URL serves both Jellyfin 10.11 and 12.0 — your server installs the matching build automatically):

   ```
   https://raw.githubusercontent.com/iderex/jellyfin-plugin-sso/manifest-beta/manifest.json
   ```

2. Go to **Dashboard → Plugins → Catalog**, find **Community SSO for Jellyfin**, and install it.
3. **Restart Jellyfin.**

This project is **beta software — the beta channel is the only release channel** for now. The plugin GUID is unchanged from the original `9p4` plugin, so it installs over an existing one in place and keeps your configuration. Build-from-source, the release channels, client (Quick Connect) support, and migrating from the old `9p4` manifest are covered on the [Installation](https://github.com/iderex/jellyfin-plugin-sso/wiki/Installation) wiki page.

## Configuration

Configure your providers on the plugin's settings page (**Dashboard → Plugins → SSO-Auth**) and via the admin API. The [Provider Setup](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup) walkthrough and the [Hardening & Options Reference](https://github.com/iderex/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference) cover every option, the provider-name rules, and the admin-API details.

## Documentation

Full documentation lives in the **[Wiki](https://github.com/iderex/jellyfin-plugin-sso/wiki)**:

- [Installation](https://github.com/iderex/jellyfin-plugin-sso/wiki/Installation) · [Provider Setup](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup) · [Login Flow](https://github.com/iderex/jellyfin-plugin-sso/wiki/Login-Flow) · [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model) · [Troubleshooting](https://github.com/iderex/jellyfin-plugin-sso/wiki/Troubleshooting)
- Project policies: [Governance](GOVERNANCE.md) · [Support & security updates](SECURITY.md#supported-versions--security-updates) · [Remediation & secrets policy](docs/SECURITY-REMEDIATION-POLICY.md)

## Security

This plugin is built to **fail closed by default**: a missing signature, a weak signature or under-strength key, an out-of-bounds time window, a wrong audience, a replayed assertion, or an unrecognized identity is rejected rather than waved through. Secrets are stored write-only and AES-256-GCM-encrypted at rest. The controls and their tuning — encryption at rest, optional rate limiting, new-user approval, step-up/MFA passthrough — are on the [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model) wiki page, and security-relevant behavior is covered by the test suite.

Found a vulnerability? Please report it **privately** via GitHub's ["Report a vulnerability"](https://github.com/iderex/jellyfin-plugin-sso/security/advisories/new) — not the public issue tracker. See [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. The plugin targets **.NET 9 / Jellyfin 10.11** and **.NET 10 / Jellyfin 12**. Build with `dotnet build` / `dotnet publish` and run the tests with `dotnet test` (the runner needs the .NET 10 SDK). CI builds and tests every change, and the login path goes through an adversarial review. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## Credits

Built on the [Jellyfin LDAP plugin](https://github.com/jellyfin/jellyfin-plugin-ldapauth), [AspNetSaml](https://github.com/jitbit/AspNetSaml/) (SAML), and the [Duende IdentityModel OIDC Client](https://github.com/DuendeSoftware/foss) (OpenID Connect) — and on the original [9p4/jellyfin-plugin-sso](https://github.com/9p4/jellyfin-plugin-sso) and its contributors.

## License

Licensed under the [GNU GPL v3.0](https://github.com/iderex/jellyfin-plugin-sso/blob/main/LICENSE.txt).

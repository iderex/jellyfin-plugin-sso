<!-- markdownlint-disable MD041 -->

> [!WARNING]
>
> ## ⛔ In-Development — do NOT install this on a production system
>
> This plugin is at the **In-Development** stage — the first rung of its maturity ladder (**In-Development → Alpha → Beta → Release Candidate → Full Release**; see the [Roadmap](https://github.com/iderex/jellyfin-plugin-sso/wiki/Roadmap)). It exists **exclusively for developers to test** — nothing else. Under **no circumstances** should it be installed on a production system or put in front of a real Jellyfin instance with real user accounts: it is a login path under active reconstruction, and you must expect **breaking changes, incomplete features, and security gaps that are still being closed**. Wait for a **Full Release** before using it anywhere that matters.

<h1 align="center">Jellyfin SSO Plugin</h1>

<p align="center">
<img alt="Logo" src="https://raw.githubusercontent.com/iderex/jellyfin-plugin-sso/main/img/logo.png"/>
<br/>
<br/>
<a href="https://github.com/iderex/jellyfin-plugin-sso/blob/main/LICENSE.txt">
<img alt="GPL 3.0 License" src="https://img.shields.io/github/license/iderex/jellyfin-plugin-sso.svg"/>
</a>
<a href="https://github.com/iderex/jellyfin-plugin-sso/actions/workflows/dotnet.yml">
<img alt="Build Status" src="https://github.com/iderex/jellyfin-plugin-sso/actions/workflows/dotnet.yml/badge.svg"/>
</a>
<a href="https://github.com/iderex/jellyfin-plugin-sso/wiki">
<img alt="Documentation" src="https://img.shields.io/badge/docs-wiki-blue"/>
</a>
</p>

<p align="center">
Sign in to Jellyfin with your existing identity provider — Keycloak, Authelia, authentik, Entra ID, Google, and more — over <b>OpenID&nbsp;Connect</b> or <b>SAML&nbsp;2.0</b>, instead of a separate Jellyfin password.
</p>

> ### ⚡ Actively maintained revival
>
> This is a revival of [**9p4/jellyfin-plugin-sso**](https://github.com/9p4/jellyfin-plugin-sso), which its original author has since archived. It continues from the last upstream release (**4.0.0.x**, Jellyfin 10.11 / .NET 9) and is being taken forward **security-first**: an automated test suite has been added and the login path is being hardened step by step. Huge thanks to the original author and contributors for the foundation.
>
> Its hardened sibling project, **`jellyfin-plugin-sso-V2`** (private), is the reference this repository draws on — a good deal still remains to be ported across from there, deliberately, one reviewed change at a time.
>
> **Status:** **In-Development** — the first stage of the maturity ladder. See the [Roadmap](https://github.com/iderex/jellyfin-plugin-sso/wiki/Roadmap) for what each stage gates, and [Installing](#installing) — for now the reliable path is building from source; a packaged release will follow as the security-hardening pass advances the maturity stages.

> ### 🤖 A note on AI and on contributions
>
> I am a non-native English speaker, so **[Claude](https://www.anthropic.com/claude)** (Anthropic) assists me in two ways: it **translates documentation and comments into English** — the README, the wiki, the in-repo guides, and code comments — and it **helps generate and analyse code** during development.
>
> - **A human owns and reviews everything.** Claude never produces finished code, a complete pull request, or any other artifact that lands unexamined. Every AI-assisted change — translated text or code — is reviewed, understood, edited, and evaluated by me before it merges; I hold responsibility for it. The AI proposes; the human decides.
> - **The AI is not in the product.** It plays **no role at runtime**, in authentication, or in processing your users' data.
>
> The review discipline around this is modelled — as far as is practical for a volunteer project — on the change-control expected of **TÜV/BSI-certified software in critical sectors such as healthcare**: every change is issue-driven, adversarially reviewed on the login path, and documented before it merges. It is an approximation of that practice, not a certification.
>
> Provided in the spirit of transparent AI use, in line with the EU AI Act's transparency principles (Art. 50).
>
> **On code, please don't "vibe-code" it.** This is a security-sensitive login path. Contributions are expected from people who understand what they are changing — a pull request that is unreviewed AI output, submitted without the domain knowledge to judge it, will be turned away. Use whatever tools help you, but own and understand every line you propose. 🙂

## Features

- **OpenID Connect and SAML 2.0** — either or both, multiple providers side by side. See the [Provider Guides](providers.md).
- **Role-based access control** — map identity-provider groups/roles to login, administrator, library folders, and Live TV.
- **Hardened, fail-closed login path** — identities bound to the stable `sub` / `NameID`, fail-closed SAML and `id_token` validation, and SSRF-guarded avatar fetches. Details on the [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model) page.
- **Avatar sync, Quick Connect, and self-service account linking**.
- **Tested** — a growing xUnit suite over the security-critical paths, with CI (build, format, CodeQL) on every change.

> The feature set from the sibling project is being ported here one reviewed change at a time; this list reflects what is implemented today.

## Installing

**Build from source (current recommended path):**

```
dotnet publish -c Release
```

Copy the **full publish output** (`SSO-Auth.dll` and every dependency DLL beside it — the OpenID client, the embedded library, and the other referenced assemblies) into your Jellyfin plugins directory under `config/plugins/sso/`, then restart Jellyfin. Copying only a subset can leave Jellyfin unable to load the plugin. [JPRM](https://github.com/oddstr13/jellyfin-plugin-repository-manager) packages the correct set for you if you prefer.

A packaged release installable from a plugin repository will be published once the hardening pass reaches its first release milestone.

**Client support:** SSO sign-in runs in the Jellyfin **Web UI** and in clients that support **Quick Connect** (the mobile and TV apps drive the login through Quick Connect). A native client that does not support Quick Connect cannot complete the browser redirect flow — use the Web UI or a Quick Connect client there.

**Coming from the old plugin repository?** This project is the maintained continuation of the archived `9p4/jellyfin-plugin-sso`. If your Jellyfin still points at the old `9p4` manifest, it will not receive updates from here. Once packaged releases resume, switch the plugin-repository URL to this repository's manifest; until then, build from source as above. The plugin GUID is unchanged, so an in-place update keeps your existing configuration.

## Configuration

Configure your providers on the plugin's settings page (**Dashboard → Plugins → SSO-Auth**) and via the admin API. The [Provider Guides](providers.md) walk through setup for common identity providers.

> **Scripting the admin API?** The provider-management endpoints use Jellyfin's `RequiresElevation` policy — pass your admin API key in the header (`-H 'Authorization: MediaBrowser Token="YOUR_KEY"'`) rather than as a `?api_key=` query parameter, which would leak the secret into proxy logs, the process list, and shell history.

## Documentation

Broader documentation lives in the **[Wiki](https://github.com/iderex/jellyfin-plugin-sso/wiki)**:

- [Installation](https://github.com/iderex/jellyfin-plugin-sso/wiki/Installation) · [Login Flow](https://github.com/iderex/jellyfin-plugin-sso/wiki/Login-Flow) · [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model) · [Troubleshooting](https://github.com/iderex/jellyfin-plugin-sso/wiki/Troubleshooting)
- Per-identity-provider setup: [Provider Guides](providers.md)

## Security

This plugin is built to **fail closed by default**: a missing signature, a weak SHA-1 signature, an out-of-bounds time window, a wrong audience, a replayed assertion, or an unrecognized identity is rejected rather than waved through. A few documented per-provider options (e.g. `DoNotValidateAudience`, `DoNotValidateIssuerName`) can deliberately relax specific checks for providers that need it — the [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model) page notes which. Two operator-facing controls:

- **Write-only client secret** — the OpenID secret is stored but never returned in a config response; on the settings page, leave it blank to keep the current value or type a new one to replace it.
- **Optional rate limiting** on the anonymous SSO endpoints (opt-in, off by default) to blunt brute force. Behind a reverse proxy, configure Jellyfin's _Known proxies_ setting so it targets the real client.

Details and tuning are on the [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model) wiki page; security-relevant behavior is covered by the test suite.

Found a vulnerability? Please report it **privately** via GitHub's ["Report a vulnerability"](https://github.com/iderex/jellyfin-plugin-sso/security/advisories/new) — not the public issue tracker. See [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. The plugin targets **.NET 9** and **Jellyfin 10.11**. Build with `dotnet build` / `dotnet publish` and run the tests with `dotnet test`. CI builds and tests every change, and the login path additionally goes through a security review before merge. Please read the note on AI and contributions above.

## Credits

Built on the [Jellyfin LDAP plugin](https://github.com/jellyfin/jellyfin-plugin-ldapauth), [AspNetSaml](https://github.com/jitbit/AspNetSaml/) (SAML), and the [Duende IdentityModel OIDC Client](https://github.com/DuendeSoftware/foss) (OpenID Connect) — and on the original [9p4/jellyfin-plugin-sso](https://github.com/9p4/jellyfin-plugin-sso) and its contributors.

## License

Licensed under the [GNU GPL v3.0](https://github.com/iderex/jellyfin-plugin-sso/blob/main/LICENSE.txt).

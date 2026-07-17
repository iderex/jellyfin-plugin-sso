<!-- markdownlint-disable MD041 -->

> [!WARNING]
>
> ## 🟠 In development — do NOT install this on a production system
>
> This plugin is at the **In-Development** stage — the first rung of its maturity ladder (**In-Development → Alpha → Beta → Release Candidate → Full Release**; see the [Roadmap](https://github.com/iderex/jellyfin-plugin-sso/wiki/Roadmap)). It exists **exclusively for developers to test** — nothing else. Under **no circumstances** should it be installed on a production system or put in front of a real Jellyfin instance with real user accounts: it is a login path still under reconstruction, and you must expect **breaking changes, incomplete features, and security gaps that are still open**. Wait for a **Full Release** before using it anywhere that matters.

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

> ### 🔁 Revival
>
> This is a revival of [**9p4/jellyfin-plugin-sso**](https://github.com/9p4/jellyfin-plugin-sso), which its original author has since archived. It continues from the last upstream release (**4.0.0.x**, Jellyfin 10.11 / .NET 9) and is taken forward **security-first**. Its hardened sibling project, **`jellyfin-plugin-sso-V2`** (private), is the reference this repository draws on — ported across deliberately, one reviewed change at a time. Huge thanks to the original author and contributors for the foundation.
>
> **Status:** **In-Development** — the first stage of the maturity ladder. See the [Roadmap](https://github.com/iderex/jellyfin-plugin-sso/wiki/Roadmap) for what each stage gates, and [Installing](#installing) — for now the only path is building from source; a packaged release follows once the security-hardening pass has advanced the maturity stages.
>
> ### How this project is developed
>
> This is a **security-sensitive login path**, so every change — even a one-liner — runs the same gated flow: a GitHub **issue** first, then a short-lived work branch, an implementation with **tests** (a negative test for every fail-closed branch), an **adversarial security review** for anything touching the login path or crypto, and a pull request that must pass **CI** (build with warnings-as-errors, the full test suite, format and conformance checks) and **CodeQL** — before it merges. We review and quality-gate our own work; no external review service is a merge gate. Security work always outranks feature work, and the code stays minimal and self-documenting.
>
> If you contribute, please work the same way: understand and own every line you propose, and be ready to explain what it does and why. 🙂

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

Provider names become part of the callback URLs you register with your identity provider — OpenID Connect: `.../sso/OID/redirect/PROVIDER_NAME`; SAML: `.../sso/SAML/post/PROVIDER_NAME` — so a newly added name on **either protocol** must not contain control characters (such as a tab or newline), `%`, a backslash, or URI-reserved characters (`: / ? # [ ] @ ! $ & ' ( ) * + , ; =`) — registration rejects such names. Names that are already configured keep working unchanged; note that this exemption is by live configuration, so once you **delete** a provider whose name uses one of these characters you cannot re-add it through the UI or API (nor restore it from a full-config backup) — recover by editing `config.xml` on disk.

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

Issues and pull requests are welcome. The plugin targets **.NET 9** and **Jellyfin 10.11**. Build with `dotnet build` / `dotnet publish` and run the tests with `dotnet test`. CI builds and tests every change, and the login path goes through an adversarial review. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## Credits

Built on the [Jellyfin LDAP plugin](https://github.com/jellyfin/jellyfin-plugin-ldapauth), [AspNetSaml](https://github.com/jitbit/AspNetSaml/) (SAML), and the [Duende IdentityModel OIDC Client](https://github.com/DuendeSoftware/foss) (OpenID Connect) — and on the original [9p4/jellyfin-plugin-sso](https://github.com/9p4/jellyfin-plugin-sso) and its contributors.

## License

Licensed under the [GNU GPL v3.0](https://github.com/iderex/jellyfin-plugin-sso/blob/main/LICENSE.txt).

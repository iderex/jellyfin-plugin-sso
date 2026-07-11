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
</p>

<p align="center">
Sign in to Jellyfin with your existing identity provider — Keycloak, Authelia, authentik, Entra ID, Google, and more — over <b>OpenID&nbsp;Connect</b> or <b>SAML&nbsp;2.0</b>, instead of a separate Jellyfin password.
</p>

> ### ⚡ Actively maintained revival
>
> This is a revival of [**9p4/jellyfin-plugin-sso**](https://github.com/9p4/jellyfin-plugin-sso), which its original author archived. It continues from the last upstream release (**4.0.0.x**, Jellyfin 10.11 / .NET 9) and is being taken forward **security-first**: an automated test suite has been added and the login path is being hardened step by step. Huge thanks to the original author and contributors for the foundation.
>
> **Status:** early and under active development. See [Installing](#installing) — for now the reliable path is building from source; a packaged release will follow once the security-hardening pass reaches its first milestone.

> ### 🤖 A note on AI and on contributions
>
> Development is assisted by **[Claude](https://www.anthropic.com/claude)** (Anthropic) — the maintainer is a non-native English speaker and uses it for documentation, English clarity, and development. Two things matter:
>
> - **A human stays responsible.** Every change — code and prose — is reviewed and owned by the maintainer before it lands; he holds responsibility for it. Nothing merges without a green build, tests, and (for the login path) a security review.
> - **The AI is not in the product.** AI tooling is used **during development only**. It is **not** part of the plugin at runtime and plays **no role in authentication or in processing your users' data**.
>
> Provided in the spirit of transparent AI use, in line with the EU AI Act's transparency principles (Art. 50).
>
> **On code, please don't "vibe-code" it.** This is a security-sensitive login path. Contributions are expected from people who understand what they are changing — a pull request that is unreviewed AI output, submitted without the domain knowledge to judge it, will be turned away. Use whatever tools help you, but own and understand every line you propose. 🙂

## Features

- **OpenID Connect and SAML 2.0** — use either or both, with multiple providers side by side. See the [Provider Guides](providers.md) for per-IdP setup.
- **Role-based access control** — map identity-provider groups/roles to Jellyfin access: login, administrator, library folders, and Live TV.
- **Hardened, fail-closed login path** — SSO identities bind to the stable `sub` / `NameID`, so a matching username cannot take over an existing account; a first login that collides with an unlinked account is refused unless explicitly allowed. SAML responses are validated fail-closed: single-reference signature (XML-signature-wrapping aware), enforced time bounds, `AudienceRestriction`, and one-time-use replay protection. Server-side avatar fetches are SSRF-guarded, and the OpenID login-state store is safe under concurrent logins.
- **Tested** — a growing xUnit test suite covers the security-critical validation paths, and every change runs through CI (build, format, CodeQL) before merge.
- **Avatar sync, Quick Connect support, and self-service account linking** at `/SSOViews/linking`.

> More of the feature set from the sibling project is being ported here deliberately, one reviewed change at a time; this list reflects what is actually implemented today.

## Installing

**Build from source (current recommended path):**

```
dotnet publish -c Release
```

Copy `SSO-Auth.dll`, `Duende.IdentityModel.OidcClient.dll`, and `Duende.IdentityModel.dll` from the build output into your Jellyfin plugins directory under `config/plugins/sso/`, then restart Jellyfin. [JPRM](https://github.com/oddstr13/jellyfin-plugin-repository-manager) can produce a packaged plugin if you prefer.

A packaged release installable from a plugin repository will be published once the hardening pass reaches its first release milestone.

## Configuration

Configure your providers on the plugin's settings page (**Dashboard → Plugins → SSO-Auth**) and via the admin API. The [Provider Guides](providers.md) walk through setup for common identity providers.

> **Scripting the admin API?** The provider-management endpoints use Jellyfin's `RequiresElevation` policy — pass your admin API key in the header (`-H 'Authorization: MediaBrowser Token="YOUR_KEY"'`) rather than as a `?api_key=` query parameter, which would leak the secret into proxy logs, the process list, and shell history.

## Security

SSO is a sensitive part of your stack, and this plugin is being built to **fail closed**: a missing signature, an out-of-bounds time window, a wrong audience, a replayed assertion, or an unrecognized identity is rejected rather than waved through. Security-relevant behavior is covered by the automated test suite.

Found a vulnerability? Please report it **privately** via GitHub's ["Report a vulnerability"](https://github.com/iderex/jellyfin-plugin-sso/security/advisories/new) — not the public issue tracker. See [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. The plugin targets **.NET 9** and **Jellyfin 10.11**. Build with `dotnet build` / `dotnet publish` and run the tests with `dotnet test`. CI builds and tests every change, and the login path additionally goes through a security review before merge. Please read the note on AI and contributions above.

## Credits

Built on the [Jellyfin LDAP plugin](https://github.com/jellyfin/jellyfin-plugin-ldapauth), [AspNetSaml](https://github.com/jitbit/AspNetSaml/) (SAML), and the [Duende IdentityModel OIDC Client](https://github.com/DuendeSoftware/foss) (OpenID Connect) — and on the original [9p4/jellyfin-plugin-sso](https://github.com/9p4/jellyfin-plugin-sso) and its contributors.

## License

Licensed under the [GNU GPL v3.0](https://github.com/iderex/jellyfin-plugin-sso/blob/main/LICENSE.txt).

<!-- markdownlint-disable MD041 -->

> [!WARNING]
>
> ## ⛔ Pre-alpha software — do NOT install this on a production system
>
> This plugin is in **pre-alpha**. It exists **exclusively for developers to test** — nothing else. Under **no circumstances** should it be installed on a production system or put in front of a real Jellyfin instance with real user accounts: it is a login path under active reconstruction, and you must expect **breaking changes, incomplete features, and security gaps that are still being closed**. Wait for a stable release before using it anywhere that matters.

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
> **Status:** early and under active development. See [Installing](#installing) — for now the reliable path is building from source; a packaged release will follow once the security-hardening pass reaches its first milestone.

> ### 🤖 A note on AI and on contributions
>
> The maintainer is a non-native English speaker, so **[Claude](https://www.anthropic.com/claude)** (Anthropic) is used to **translate documentation and comments into English** — the README, the wiki, the in-repo guides, and code comments.
>
> - **A human reviews it.** Every AI-translated text is reviewed and edited by the maintainer before it lands; he holds responsibility for it.
> - **The AI is not in the product.** It plays **no role at runtime**, in authentication, or in processing your users' data.
>
> Provided in the spirit of transparent AI use, in line with the EU AI Act's transparency principles (Art. 50).
>
> **On code, please don't "vibe-code" it.** This is a security-sensitive login path. Contributions are expected from people who understand what they are changing — a pull request that is unreviewed AI output, submitted without the domain knowledge to judge it, will be turned away. Use whatever tools help you, but own and understand every line you propose. 🙂

## Features

- **OpenID Connect and SAML 2.0** — use either or both, with multiple providers side by side. See the [Provider Guides](providers.md) for per-IdP setup.
- **Role-based access control** — map identity-provider groups/roles to Jellyfin access: login, administrator, library folders, and Live TV.
- **Hardened, fail-closed login path** — SSO identities bind to the stable `sub` / `NameID`, so a matching username cannot take over an existing account; a first login that collides with an unlinked account is refused unless explicitly allowed. SAML responses are validated fail-closed: single-reference signature (XML-signature-wrapping aware), DTDs rejected outright (no XXE, no entity-expansion DoS), enforced time bounds, `AudienceRestriction`, and one-time-use replay protection. The OpenID login state is bound to its provider and single-use, closing cross-provider state replay, and the returned `id_token` is validated fail-closed — signature against the provider's published JWKS (asymmetric RS/PS/ES algorithms only), issuer, audience, and expiry (see the [id_token requirements](providers.md#openid-connect-id_token-requirements)). Server-side avatar fetches are SSRF-guarded.
- **Tested** — a growing xUnit test suite covers the security-critical validation paths, and every change runs through CI (build, format, CodeQL) before merge.
- **Avatar sync, Quick Connect support, and self-service account linking** at `/SSOViews/linking`.

> More of the feature set from the sibling project is being ported here deliberately, one reviewed change at a time; this list reflects what is actually implemented today.

## Installing

**Build from source (current recommended path):**

```
dotnet publish -c Release
```

Copy the **full publish output** (`SSO-Auth.dll` and every dependency DLL beside it — the OpenID client, the embedded library, and the other referenced assemblies) into your Jellyfin plugins directory under `config/plugins/sso/`, then restart Jellyfin. Copying only a subset can leave Jellyfin unable to load the plugin. [JPRM](https://github.com/oddstr13/jellyfin-plugin-repository-manager) packages the correct set for you if you prefer.

A packaged release installable from a plugin repository will be published once the hardening pass reaches its first release milestone.

## Configuration

Configure your providers on the plugin's settings page (**Dashboard → Plugins → SSO-Auth**) and via the admin API. The [Provider Guides](providers.md) walk through setup for common identity providers.

> **Scripting the admin API?** The provider-management endpoints use Jellyfin's `RequiresElevation` policy — pass your admin API key in the header (`-H 'Authorization: MediaBrowser Token="YOUR_KEY"'`) rather than as a `?api_key=` query parameter, which would leak the secret into proxy logs, the process list, and shell history.

## Documentation

Broader documentation lives in the **[Wiki](https://github.com/iderex/jellyfin-plugin-sso/wiki)**:

- [Installation](https://github.com/iderex/jellyfin-plugin-sso/wiki/Installation) · [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model) · [Troubleshooting](https://github.com/iderex/jellyfin-plugin-sso/wiki/Troubleshooting)
- Per-identity-provider setup: [Provider Guides](providers.md)

## Security

SSO is a sensitive part of your stack, and this plugin is being built to **fail closed**: a missing signature, a weak SHA-1 signature, an out-of-bounds time window, a wrong audience, a replayed assertion, or an unrecognized identity is rejected rather than waved through. Security-relevant behavior is covered by the automated test suite.

The anonymous SSO endpoints can additionally be **rate-limited per client address** (opt-in, off by default): set `EnableRateLimit` in the plugin's XML configuration, with `RateLimitMaxAttempts` (default 30) per `RateLimitWindowSeconds` (default 60) per endpoint stage, and throttled requests answered with `429 Retry-After`. The limiter keys on the connection's remote address only — **if Jellyfin runs behind a reverse proxy, configure Jellyfin's own _Known proxies_ networking setting** so the server resolves the real client from the forwarded headers; the plugin deliberately never parses `X-Forwarded-For` itself (a client-spoofable header must not steer throttling). Non-public source addresses (loopback, private ranges, CGNAT) are never throttled, so an unconfigured proxy can never pool the whole userbase into one throttled bucket. IPv6 clients are keyed on their /64. The limiter is best-effort and in-process: counters are per Jellyfin instance and reset on restart — it blunts sustained brute force at the public edge, it is not a hard quota.

Found a vulnerability? Please report it **privately** via GitHub's ["Report a vulnerability"](https://github.com/iderex/jellyfin-plugin-sso/security/advisories/new) — not the public issue tracker. See [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. The plugin targets **.NET 9** and **Jellyfin 10.11**. Build with `dotnet build` / `dotnet publish` and run the tests with `dotnet test`. CI builds and tests every change, and the login path additionally goes through a security review before merge. Please read the note on AI and contributions above.

## Credits

Built on the [Jellyfin LDAP plugin](https://github.com/jellyfin/jellyfin-plugin-ldapauth), [AspNetSaml](https://github.com/jitbit/AspNetSaml/) (SAML), and the [Duende IdentityModel OIDC Client](https://github.com/DuendeSoftware/foss) (OpenID Connect) — and on the original [9p4/jellyfin-plugin-sso](https://github.com/9p4/jellyfin-plugin-sso) and its contributors.

## License

Licensed under the [GNU GPL v3.0](https://github.com/iderex/jellyfin-plugin-sso/blob/main/LICENSE.txt).

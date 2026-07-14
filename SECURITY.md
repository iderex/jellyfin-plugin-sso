# Security policy

This plugin is a login path for a Jellyfin server. Security reports are taken
seriously and handled with priority over all other work.

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub's
[private vulnerability reporting](https://github.com/iderex/jellyfin-plugin-sso/security/advisories/new)
("Report a vulnerability" on the Security tab of this repository).

Please do **not** open a public issue for an exploitable vulnerability. A public
issue is created once a fix has been released.

If you used LLMs/AI tooling to find the issue, please verify it manually before
reporting.

## What to expect

- An initial response within a few days.
- Security fixes are released as soon as they are ready — they are never
  batched or delayed behind feature work.
- Coordinated disclosure: please allow a fix to be released before public
  disclosure.

## Supported versions

The latest released version is the only supported version.

## Repository security controls

- **Secret scanning** and **push protection** are enabled, so a leaked credential — an identity-provider client secret, a CI token — is blocked before it can be pushed.
- **Dependabot** opens dependency-update pull requests; a dependency-review check blocks a pull request that introduces or upgrades to a known-vulnerable dependency; and the build fails on any known-vulnerable dependency, transitive ones included.
- Pull requests to `main` run CodeQL, a Trojan-Source/Unicode check, and a build with warnings treated as errors; a GitHub Actions workflow audit (zizmor) and repository-specific security-invariant checks (Opengrep) run on every pull request. A scheduled OpenSSF Scorecard scan audits the repository's supply-chain posture and publishes its results to code scanning. Changes to the login path additionally go through an adversarial security review before they merge.

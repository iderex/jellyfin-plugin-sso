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

## Verifying a release download

Every stable release asset ships with an `.md5` and a `.sha256` sidecar per
plugin `.zip`; the `.md5` is the checksum the Jellyfin manifest uses to validate
the download, and it is unchanged.

In addition, each stable release zip carries a **signed SLSA build-provenance
attestation** (SLSA v1.1, Build L3 — the package build runs in a reusable GitHub
Actions workflow, which is what raises the provenance from L2 to L3). After
downloading a release zip you can verify it was produced by this repository's
release pipeline and has not been tampered with:

```sh
gh attestation verify <plugin>.zip --repo iderex/jellyfin-plugin-sso
```

The provenance attestation complements the checksum sidecars — it does not
replace the manifest MD5.

## Repository security controls

- **Secret scanning** and **push protection** are enabled, so a leaked credential — an identity-provider client secret, a CI token — is blocked before it can be pushed.
- **Dependabot** opens dependency-update pull requests; a dependency-review check blocks a pull request that introduces or upgrades to a known-vulnerable dependency; and the build fails on any known-vulnerable dependency, transitive ones included.
- Pull requests to `main` run CodeQL, a Trojan-Source/Unicode check, and a build with warnings treated as errors; a GitHub Actions workflow audit (zizmor) and repository-specific security-invariant checks (Opengrep) run on every pull request. A scheduled OpenSSF Scorecard scan audits the repository's supply-chain posture and publishes its results to code scanning. Changes to the login path additionally go through an adversarial security review before they merge.

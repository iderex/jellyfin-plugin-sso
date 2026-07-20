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

## Supported versions & security updates

**Support model (best-effort, volunteer):** this is a volunteer-maintained
open-source project. The commitments below describe intent, applied
consistently — they are not a contractual SLA.

- **One active version line: 4.x.** Security fixes land in a **new latest
  release** of that line; older releases are not patched in place. "Supported"
  means: update to the latest release.
- Each release is packaged for the server generations the manifests cover
  (currently Jellyfin **10.11/11.x** on .NET 9 as the stable line, Jellyfin
  **12.0** as beta until 12.0 itself is stable — see the README's install
  matrix). A security fix ships for **all ABI builds of the latest release**
  at the same time.
- **When a future major line replaces 4.x** (the planned JF12-native 5.0 line —
  [#743](https://github.com/iderex/jellyfin-plugin-sso/issues/743)), the intent
  is to keep shipping **security fixes for the previous line for at least six
  months** after the new line's first stable release.
- **End of support is announced**, not silent: in `CHANGELOG.md` and the
  release notes of the release that starts the clock, with at least three
  months' notice before the final security update of a line.

Release integrity, channels and the soak/promotion model are described in the
[Release Policy](https://github.com/iderex/jellyfin-plugin-sso/wiki/Release-Policy)
wiki page.

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

For how these controls together cover what an automated PR reviewer would catch — and the one accepted residual — see [Review Gate](https://github.com/iderex/jellyfin-plugin-sso/wiki/Review-Gate). For how they map onto the OpenSSF Best Practices passing-level criteria, see [OpenSSF Best Practices](https://github.com/iderex/jellyfin-plugin-sso/wiki/OpenSSF-Best-Practices).

## EU Cyber Resilience Act (CRA) position

- **This is a non-commercial FLOSS project.** It is developed and published
  without monetization of any kind, which places it outside the CRA's
  manufacturer obligations; the project also matches the spirit of the CRA's
  **open-source software steward** role (Art. 24), whose obligations it meets
  voluntarily: this document **is** the project's coordinated
  vulnerability-handling and cybersecurity policy (reporting channel, response
  expectations, supported versions above), and actively-exploited
  vulnerabilities would be handled through the private-advisory process
  described here.
- **No conformity claim.** The project does **not** claim CRA conformity or CE
  marking, and nothing here should be read as such — the statements above
  describe only which obligations are voluntarily met.
- **Commercial redistributors carry their own obligations.** Anyone who
  integrates or redistributes this plugin **commercially** becomes responsible
  for the CRA manufacturer obligations for their product; this project's
  artifacts help (release provenance and checksums above, a dependency SBOM is
  planned — [#763](https://github.com/iderex/jellyfin-plugin-sso/issues/763)
  tracks OpenVEX), but do not transfer that responsibility.
- Data-handling transparency for operators lives in
  [docs/PRIVACY.md](docs/PRIVACY.md).

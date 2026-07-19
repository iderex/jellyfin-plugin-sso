# OpenSSF Best Practices — passing-level readiness

This document maps every criterion of the **OpenSSF Best Practices badge**
(passing level) to the concrete evidence in this repository, so the self-assessment
at [bestpractices.dev](https://www.bestpractices.dev) can be filled in honestly and
quickly. It also flags the few criteria that are `Met (N/A)` or `Partial`, with the
reason and, where relevant, how to close the gap.

**Status: ready to register.** No passing-level `MUST` is unmet. Two `SUGGESTED`
criteria are `Partial`, and three criteria are answered `N/A` with justification —
none of which block the badge. What remains is a maintainer web action, described
in [What the maintainer must do](#what-the-maintainer-must-do).

This is a **criteria-to-evidence mapping and readiness statement**, not a claim that
the badge has been awarded. The badge is awarded only after the maintainer registers
the project and completes the self-certification; this repository does not display a
real badge ID until then.

## Summary

Passing level has **67 criteria** across six categories. Assessment against this
repository:

| Category       | Criteria | Met | Met (N/A) | Partial | Unmet |
| -------------- | -------: | --: | --------: | ------: | ----: |
| Basics         |       13 |  13 |         0 |       0 |     0 |
| Change Control |        9 |   8 |         0 |       1 |     0 |
| Reporting      |        8 |   8 |         0 |       0 |     0 |
| Quality        |       13 |  12 |         0 |       1 |     0 |
| Security       |       16 |  14 |         2 |       0 |     0 |
| Analysis       |        8 |   7 |         1 |       0 |     0 |
| **Total**      |   **67** |  62 |         3 |       2 |     0 |

- **Met** — a `MUST`/`SHOULD`/`SUGGESTED` criterion satisfied by a concrete control
  in this repo, with the evidence linked below.
- **Met (N/A)** — genuinely not applicable to this project; the questionnaire answer
  is `N/A` with the justification given here.
- **Partial** — a `SUGGESTED` (never a `MUST`) criterion only partly satisfied; noted
  honestly. Neither blocks the badge.
- **Unmet** — none.

Legend in the tables below: **M** = MUST, **S** = SHOULD, **·** = SUGGESTED.

## Basics

| ID                        | Lvl | Status | Evidence                                                                                                                                                                                         |
| ------------------------- | :-: | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| description_good          |  M  | Met    | [README.md](README.md) opening paragraph — one-line description of what the plugin does (SSO for Jellyfin over OIDC / SAML).                                                                     |
| interact                  |  M  | Met    | [README.md](README.md) (Installing, Configuration, Contributing) and [CONTRIBUTING.md](CONTRIBUTING.md) explain how to obtain and how to give feedback; GitHub Issues is the feedback channel.   |
| contribution              |  M  | Met    | [CONTRIBUTING.md](CONTRIBUTING.md) — full contribution process (issue → branch → tests → PR).                                                                                                    |
| contribution_requirements |  S  | Met    | [CONTRIBUTING.md](CONTRIBUTING.md) (build/test/format commands, branch naming, own-every-line rule) + [.github/pull_request_template.md](.github/pull_request_template.md) checklist.            |
| floss_license             |  M  | Met    | GNU GPL v3.0 — [LICENSE.txt](LICENSE.txt).                                                                                                                                                       |
| floss_license_osi         |  ·  | Met    | GPL-3.0 is [OSI-approved](https://opensource.org/license/gpl-3-0) and FSF-approved.                                                                                                              |
| license_location          |  M  | Met    | [LICENSE.txt](LICENSE.txt) at the repository root (standard location; GitHub detects it).                                                                                                        |
| documentation_basics      |  M  | Met    | [README.md](README.md), the [Wiki](https://github.com/iderex/jellyfin-plugin-sso/wiki), and [providers.md](providers.md).                                                                        |
| documentation_interface   |  M  | Met    | [providers.md](providers.md) (per-provider setup), the admin-API usage note in [README.md](README.md), and the [Login Flow](https://github.com/iderex/jellyfin-plugin-sso/wiki/Login-Flow) page. |
| sites_https               |  M  | Met    | Project site and manifests are served by GitHub / `raw.githubusercontent.com` over HTTPS/TLS only.                                                                                               |
| discussion                |  M  | Met    | [GitHub Issues](https://github.com/iderex/jellyfin-plugin-sso/issues) — searchable, publicly archived discussion of changes and bugs.                                                            |
| english                   |  S  | Met    | All repository artifacts are in English (see [CONTRIBUTING.md](CONTRIBUTING.md) styleguide).                                                                                                     |
| maintained                |  M  | Met    | Active: regular commits, a released `4.2.x` line, an issue-driven flow, and a security-report SLA. Self-attested at registration.                                                                |

## Change control

| ID                  | Lvl | Status  | Evidence                                                                                                                                                                                                                                                                                                                                |
| ------------------- | :-: | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| repo_public         |  M  | Met     | Public Git repository on GitHub.                                                                                                                                                                                                                                                                                                        |
| repo_track          |  M  | Met     | Git records what/who/when for every change.                                                                                                                                                                                                                                                                                             |
| repo_interim        |  M  | Met     | PR-only `main` with interim commits per PR; branches reviewed before release. [CONTRIBUTING.md](CONTRIBUTING.md), [REVIEW-GATE.md](REVIEW-GATE.md).                                                                                                                                                                                     |
| repo_distributed    |  ·  | Met     | Git (distributed VCS).                                                                                                                                                                                                                                                                                                                  |
| version_unique      |  M  | Met     | Four-part `X.Y.Z.W` version scheme, unique per release — [CHANGELOG.md](CHANGELOG.md), `build.yaml`.                                                                                                                                                                                                                                    |
| version_semver      |  ·  | Partial | Uses a documented four-part `X.Y.Z.W` scheme (breaking / feature / bug-fix / security), the Jellyfin-plugin convention — not strict SemVer or CalVer. Monotonic and meaningful, but this SUGGESTED criterion may be answered `Met` with the justification in [CHANGELOG.md](CHANGELOG.md), or left unmet. See the note below the table. |
| version_tags        |  ·  | Met     | Releases are tagged (`X.Y.Z-stable`) — see the tag trigger in [.github/workflows/publish.yml](.github/workflows/publish.yml).                                                                                                                                                                                                           |
| release_notes       |  M  | Met     | [CHANGELOG.md](CHANGELOG.md) (human-readable per-release summary) plus auto-generated GitHub release notes (`generate_release_notes: true` in [publish.yml](.github/workflows/publish.yml)).                                                                                                                                            |
| release_notes_vulns |  M  | Met     | The `W` (fourth) digit denotes a security release; [CHANGELOG.md](CHANGELOG.md) documents security fixes with their issue numbers (e.g. the #626 authorization fix in 4.2.1.0).                                                                                                                                                         |

> **version_semver note.** The Jellyfin plugin ABI requires a four-part numeric
> version, so a strict three-part SemVer string is not usable as the shipped version.
> The scheme is documented and monotonic, so at registration this SUGGESTED item can
> reasonably be answered `Met` with that justification. It is recorded here as
> `Partial` only to be precise that it is not literally SemVer/CalVer.

## Reporting

| ID                            | Lvl | Status | Evidence                                                                                                                                                |
| ----------------------------- | :-: | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| report_process                |  M  | Met    | [CONTRIBUTING.md](CONTRIBUTING.md) (Reporting Bugs) + [issue templates](.github/ISSUE_TEMPLATE/).                                                       |
| report_tracker                |  S  | Met    | [GitHub Issues](https://github.com/iderex/jellyfin-plugin-sso/issues).                                                                                  |
| report_responses              |  M  | Met    | Issue-driven flow; the maintainer triages and responds. Self-attested from the issue history at registration.                                           |
| enhancement_responses         |  S  | Met    | Enhancement requests are tracked and triaged as issues with `priority:` labels.                                                                         |
| report_archive                |  M  | Met    | GitHub Issues is a public, permanent, searchable archive of reports and responses.                                                                      |
| vulnerability_report_process  |  M  | Met    | [SECURITY.md](SECURITY.md) publishes the reporting process; linked from [README.md](README.md).                                                         |
| vulnerability_report_private  |  M  | Met    | Private reporting via GitHub [security advisories](https://github.com/iderex/jellyfin-plugin-sso/security/advisories/new) — [SECURITY.md](SECURITY.md). |
| vulnerability_report_response |  M  | Met    | [SECURITY.md](SECURITY.md): "An initial response within a few days" — within the required ≤ 14 days.                                                    |

## Quality

| ID                          | Lvl | Status  | Evidence                                                                                                                                                                                                                                                                                 |
| --------------------------- | :-: | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| build                       |  M  | Met     | `dotnet build` / `dotnet publish` — [CONTRIBUTING.md](CONTRIBUTING.md), [.github/workflows/build.yml](.github/workflows/build.yml).                                                                                                                                                      |
| build_common_tools          |  ·  | Met     | .NET SDK + MSBuild (common, standard tooling).                                                                                                                                                                                                                                           |
| build_floss_tools           |  S  | Met     | The .NET SDK is FLOSS (MIT); the build needs no proprietary tool.                                                                                                                                                                                                                        |
| test                        |  M  | Met     | xUnit suite `SSO-Auth.Tests` (FLOSS) + `PropertyTests` (FsCheck).                                                                                                                                                                                                                        |
| test_invocation             |  S  | Met     | `dotnet test` — the standard invocation for .NET.                                                                                                                                                                                                                                        |
| test_most                   |  ·  | Partial | A "growing xUnit suite over the security-critical paths" plus property tests and weekly Stryker mutation testing scoped to the SAML/OIDC core — strong on the critical surface, but branch coverage across the whole codebase is not asserted. Honest `Partial` for this SUGGESTED item. |
| test_continuous_integration |  ·  | Met     | CI builds and tests every PR — [.github/workflows/dotnet.yml](.github/workflows/dotnet.yml).                                                                                                                                                                                             |
| test_policy                 |  M  | Met     | Policy: a negative test for every fail-closed branch — [CONTRIBUTING.md](CONTRIBUTING.md), [REVIEW-GATE.md](REVIEW-GATE.md) (Correctness).                                                                                                                                               |
| tests_are_added             |  M  | Met     | Recent evidence: e.g. the 4.2.1.0 (#626) fix corrected a test to assert the explicit deny — [CHANGELOG.md](CHANGELOG.md); PRs add tests with changes.                                                                                                                                    |
| tests_documented_added      |  ·  | Met     | The test expectation is documented in [CONTRIBUTING.md](CONTRIBUTING.md) and the [PR template](.github/pull_request_template.md).                                                                                                                                                        |
| warnings                    |  M  | Met     | `TreatWarningsAsErrors` (`Directory.Build.props`) + Roslyn analyzers (Roslynator, Meziantou, StyleCop), severities pinned in `.editorconfig` — [REVIEW-GATE.md](REVIEW-GATE.md).                                                                                                         |
| warnings_fixed              |  M  | Met     | `dotnet build --warnaserror` in CI makes any warning a build failure — [CONTRIBUTING.md](CONTRIBUTING.md).                                                                                                                                                                               |
| warnings_strict             |  ·  | Met     | `AnalysisMode Recommended`, `AnalysisModeSecurity=All`, Security-category rules at `error` — [REVIEW-GATE.md](REVIEW-GATE.md).                                                                                                                                                           |

## Security

| ID                             | Lvl | Status    | Evidence                                                                                                                                                                                                                                                              |
| ------------------------------ | :-: | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| know_secure_design             |  M  | Met       | Security-first design and threat model — [THREAT-MODEL.md](THREAT-MODEL.md), [SSO-ONLY-LOGIN-DESIGN.md](SSO-ONLY-LOGIN-DESIGN.md); fail-closed principle throughout. Self-attested.                                                                                   |
| know_common_errors             |  M  | Met       | STRIDE threat model and adversarial-review lenses citing ASVS — [THREAT-MODEL.md](THREAT-MODEL.md), [REVIEW-GATE.md](REVIEW-GATE.md). Self-attested.                                                                                                                  |
| crypto_published               |  M  | Met       | Standard published protocols/algorithms only: OpenID Connect, SAML 2.0, AES-256-GCM for secret-at-rest — [README.md](README.md) (Security).                                                                                                                           |
| crypto_call                    |  S  | Met       | Crypto is delegated to platform/library code (.NET crypto, Duende IdentityModel OIDC client, AspNetSaml) rather than re-implemented — [README.md](README.md) (Credits).                                                                                               |
| crypto_floss                   |  M  | Met       | All crypto is implementable with FLOSS (.NET runtime crypto; the named libraries are FLOSS).                                                                                                                                                                          |
| crypto_keylength               |  M  | Met       | AES-256-GCM for secrets at rest; TLS key lengths meet NIST minimums. Signature validation rejects weak algorithms.                                                                                                                                                    |
| crypto_working                 |  M  | Met       | Fail-closed validation rejects SHA-1 (weak) signatures and other broken configurations — [README.md](README.md) (Security), Security Model wiki.                                                                                                                      |
| crypto_weaknesses              |  S  | Met       | SHA-1-signed assertions are rejected; CA5369-class rules are at `error` — [REVIEW-GATE.md](REVIEW-GATE.md).                                                                                                                                                           |
| crypto_pfs                     |  S  | Met       | Delivery/download runs over TLS that supports PFS (GitHub). The plugin implements no key-agreement protocol of its own, so no additional PFS obligation applies.                                                                                                      |
| crypto_password_storage        |  M  | Met (N/A) | The plugin performs SSO — user authentication is delegated to the identity provider; it stores **no** user authentication passwords. IdP client secrets are stored as AES-256-GCM `ssoenc:v1:` envelopes (not password hashes). Answer `N/A` with this justification. |
| crypto_random                  |  M  | Met       | CSPRNG-only randomness is enforced as an Opengrep repo-invariant — [tools/opengrep/rules.yml](tools/opengrep/rules.yml), [REVIEW-GATE.md](REVIEW-GATE.md) (Security).                                                                                                 |
| delivery_mitm                  |  M  | Met       | HTTPS delivery + per-asset `.sha256`/`.md5` sidecars + a signed **SLSA v1.1 Build L3** provenance attestation — [SECURITY.md](SECURITY.md), [.github/workflows/build.yml](.github/workflows/build.yml).                                                               |
| delivery_unsigned              |  M  | Met       | No hashes/keys are fetched over plain HTTP; release verification is checksum + `gh attestation verify` — [SECURITY.md](SECURITY.md).                                                                                                                                  |
| vulnerabilities_fixed_60_days  |  M  | Met       | No medium-or-higher vulnerability is publicly known unpatched > 60 days; security fixes ship immediately and are never batched — [SECURITY.md](SECURITY.md). Self-attested.                                                                                           |
| vulnerabilities_critical_fixed |  S  | Met       | Security work outranks feature work; fixes released as soon as ready — [SECURITY.md](SECURITY.md).                                                                                                                                                                    |
| no_leaked_credentials          |  M  | Met       | GitHub **secret scanning + push protection** enabled; config secrets redacted on export (`SecretEnvelope`) — [SECURITY.md](SECURITY.md), [REVIEW-GATE.md](REVIEW-GATE.md) (Secret).                                                                                   |

## Analysis

| ID                                     | Lvl | Status    | Evidence                                                                                                                                                                                                 |
| -------------------------------------- | :-: | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| static_analysis                        |  M  | Met       | CodeQL (security-extended) + Opengrep repo-invariant rules on every PR — [.github/workflows/codeql.yml](.github/workflows/codeql.yml), [.github/workflows/opengrep.yml](.github/workflows/opengrep.yml). |
| static_analysis_common_vulnerabilities |  ·  | Met       | CodeQL security-extended runs ~135 taint/dataflow queries across `csharp`, `javascript-typescript`, and `actions` — [REVIEW-GATE.md](REVIEW-GATE.md).                                                    |
| static_analysis_fixed                  |  M  | Met       | Findings are triaged and fixed; CodeQL/analyzer results block or gate merges (e.g. the CA5369 catch-and-fix) — [REVIEW-GATE.md](REVIEW-GATE.md).                                                         |
| static_analysis_often                  |  ·  | Met       | CodeQL and Opengrep run on every push and PR (not merely daily) — see the workflow triggers.                                                                                                             |
| dynamic_analysis                       |  ·  | Met       | SharpFuzz coverage-guided fuzzing of the SAML/OIDC parse surface — [.github/workflows/fuzz.yml](.github/workflows/fuzz.yml).                                                                             |
| dynamic_analysis_unsafe                |  ·  | Met (N/A) | C# is a memory-safe language; a memory-safety dynamic tool is not applicable. Answer `N/A`.                                                                                                              |
| dynamic_analysis_enable_assertions     |  ·  | Met (N/A) | No separate assertion-heavy dynamic build is used; the fuzz harness exercises the parse surface directly. SUGGESTED, answered `N/A`.                                                                     |
| dynamic_analysis_fixed                 |  M  | Met       | Fuzz-surfaced crashes are triaged and fixed like any security finding — [SECURITY.md](SECURITY.md), [REVIEW-GATE.md](REVIEW-GATE.md).                                                                    |

## Beyond passing (silver/gold signals already in place)

Several controls exceed the passing level and pre-stage the silver/gold badges:

- **SHA-pinned GitHub Actions** across all workflows, audited by **zizmor** —
  [.github/workflows/zizmor.yml](.github/workflows/zizmor.yml).
- **OpenSSF Scorecard** weekly, publishing to code scanning —
  [.github/workflows/scorecard.yml](.github/workflows/scorecard.yml).
- **Signed SLSA v1.1 Build L3 provenance** on every stable release —
  [.github/workflows/build.yml](.github/workflows/build.yml), [SECURITY.md](SECURITY.md).
- **Dependabot** on both NuGet and github-actions, with a 7-day cooldown —
  [.github/dependabot.yml](.github/dependabot.yml).
- **dependency-review** (required, `fail-on-severity: low`) + a transitive
  vulnerable-dependency scan + **locked-mode restore** —
  [.github/workflows/dependency-review.yml](.github/workflows/dependency-review.yml), [REVIEW-GATE.md](REVIEW-GATE.md).
- **CODEOWNERS**-enforced review requests + **branch protection** on `main` —
  [.github/CODEOWNERS](.github/CODEOWNERS).
- **Trojan-Source / Unicode guard** (CVE-2021-42574) —
  [.github/workflows/unicode-guard.yml](.github/workflows/unicode-guard.yml).
- A written, class-by-class **review-gate coverage analysis** —
  [REVIEW-GATE.md](REVIEW-GATE.md).

## What the maintainer must do

The agent deliverable (this mapping) is complete. Earning the badge is a maintainer
web action:

1. Sign in at **[bestpractices.dev](https://www.bestpractices.dev)** with the GitHub
   account and add a new project, entering the repository URL
   `https://github.com/iderex/jellyfin-plugin-sso`.
2. Walk the passing questionnaire. For all-but-five items answer **Met** and paste the
   evidence URL from the tables above (the badge form expects a justification URL — the
   linked file / workflow / wiki page is the source).
3. For the five non-plain items, use these answers:
   - **crypto_password_storage** → `N/A`, justification: SSO delegates authentication
     to the identity provider; no user passwords are stored.
   - **dynamic_analysis_unsafe** → `N/A`, justification: C# is memory-safe.
   - **dynamic_analysis_enable_assertions** → `N/A` (or `Met` — the fuzz harness).
   - **version_semver** → `Met` with the four-part Jellyfin-ABI justification, or leave
     unmet (SUGGESTED, non-blocking).
   - **test_most** → answer honestly for the SUGGESTED coverage item; non-blocking.
4. Once passing is reached the form issues a **project ID** and a badge URL of the form
   `https://www.bestpractices.dev/projects/<ID>/badge`. Replace the placeholder in
   [README.md](README.md) (the OpenSSF badge line) with the real project ID.
5. Any genuine gap the live questionnaire surfaces that this document missed should
   become its own tracked issue (per the project's issue-driven process), as the #403
   acceptance criteria require.

## Maintenance

Keep this file in sync with the controls it cites: when a workflow, policy, or
document referenced here changes, update the matching row. The mapping is only useful
if it stays true — the same rule [REVIEW-GATE.md](REVIEW-GATE.md) states for itself.

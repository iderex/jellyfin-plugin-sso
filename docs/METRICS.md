# KPI dashboard

Living scorecard for the SDL goals (SECURE-SDLC.md), and the **RC gate-(d)
delivery-metrics evidence artifact** (#719). Refresh at each stable release
(`scripts/dora-metrics.sh` regenerates the delivery numbers from git/GitHub).
All values are public-derivable from git/GitHub with no extra tooling.

_Last refreshed: 2026-07-21 (#719; delivery + security tables re-run against the
current release topology; test-coverage section #718). Refresh cadence: at each
stable release — this file is the gate-(d) delivery-metrics evidence artifact._

## Security posture

| KPI                                          | Target | Current  | Notes                                                                        |
| -------------------------------------------- | ------ | -------- | ---------------------------------------------------------------------------- |
| Open Code Scanning (CodeQL) alerts           | 0      | **0**    | verified FPs dismissed with rationale                                        |
| Open Dependabot alerts                       | 0      | **0**    | Dependabot nuget+actions on                                                  |
| Secret-scanning / push protection            | on     | **on**   | + private vuln reporting                                                     |
| Exploitable findings unpatched > SLA         | 0      | 0        | SECURITY-FINDINGS.md                                                         |
| Security-decision branches w/o negative test | 0      | 0        | SAML sig/time/audience/replay, account-link, SSRF, logout all have negatives |
| Adversarial review on sensitive diffs        | 100%   | 100%     | every security-surface PR (per-unit bypass/correctness lenses)               |
| SHA-pinned third-party actions               | 100%   | **100%** | zizmor-enforced                                                              |
| Least-privilege workflow permissions         | all    | **all**  | `permissions:` per job                                                       |

## Delivery performance (DORA proxies)

Run `scripts/dora-metrics.sh` (read-only, deterministic) to regenerate; the
operational definitions and small-dataset caveats live on the
[Delivery-Metrics](https://github.com/iderex/jellyfin-plugin-sso/wiki/Delivery-Metrics)
wiki page.

| KPI                   | Current (2026-07-21)                                                                                                                            | Source               |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| Released version      | **4.2.1-stable** (JF10.11 line) + the 4.3.0-beta channel; JF12/5.0 beta-only ([#743](https://github.com/iderex/jellyfin-plugin-sso/issues/743)) | `git tag '*-stable'` |
| Deployment frequency  | 3 stable releases (4.1.1 / 4.2.0 / 4.2.1); <1-day span, rate not yet meaningful                                                                 | dora-metrics.sh §1   |
| Lead time for changes | median 1h 45m, p90 8h 19m                                                                                                                       | dora-metrics.sh §2   |
| Change-failure rate   | **50%** (1/2 judgeable: 4.2.0 → 4.2.1 fast hotfix, 42m)                                                                                         | dora-metrics.sh §3   |
| Mean time to restore  | **42m** (1 pair)                                                                                                                                | dora-metrics.sh §4   |
| Revert rate           | **0%** (0/48 non-merge commits in the stable window)                                                                                            | dora-metrics.sh §5   |
| Open PRs / issues     | **0 / 42**                                                                                                                                      | `gh pr/issue list`   |

Small-dataset caveat: with 3 stable releases these rates are indicative, not
statistically stable — read the trend, not the absolute. The 50% CFR is one fast
same-day hotfix over a two-release judgeable window, not a systemic signal.

## Code health (the "minimal, clean" goal)

Baseline to drive **down** as the God-controller is thinned into pure helpers.
Paths reflect the post-#777/#807 module layout (the flat `Api/` kernel is
dissolved; every type lives in a named module folder).

| File / group                                   | LOC (2026-07-21)           | Direction                                                                    |
| ---------------------------------------------- | -------------------------- | ---------------------------------------------------------------------------- |
| `SSO-Auth/Api/Http/SSOController.cs`           | **1578**                   | ↓ (still the top refactor target; endpoint bodies delegate to flow services) |
| `SSO-Auth/Api/Linking/CanonicalLinkService.cs` | 1028                       | the login/link workflow keystone; tested per branch                          |
| `SSO-Auth/Api/Flows/SamlLoginService.cs`       | 804                        | per-protocol orchestration                                                   |
| `SSO-Auth/Config/PluginConfiguration.cs`       | 767                        | grows with mappings + logout/button config (acceptable)                      |
| `SSO-Auth/Api/Flows/OidcLoginService.cs`       | 686                        | per-protocol orchestration                                                   |
| Production source                              | **120 files, ~19 000 LOC** | modular; each type in its module                                             |
| Test files                                     | **139 files**              | ↑ with each security branch (see coverage below)                             |

### Test coverage (measured in CI, security surface hard-gated) — RC gate (b)

Measured on every PR since #718: the CI `build` job runs the net10.0 test leg
under the MTP CodeCoverage extension (Cobertura), publishes the report as the
`coverage-report` artifact, and `scripts/check-coverage.py` enforces the
security-surface bar. Numbers below are the line-level measurement of
2026-07-21 (12 030 executable lines).

| KPI                                                               | Target                                | Current   | Gate                                            |
| ----------------------------------------------------------------- | ------------------------------------- | --------- | ----------------------------------------------- |
| Security-surface line coverage (auth/authz/linking/abuse modules) | **>= 92%** (pinned bar, ratchets up)  | **93.7%** | **CI-enforced** — below the bar fails the build |
| Whole-codebase line coverage                                      | >= 80% statement (Silver/RC baseline) | **91.9%** | reported + tracked here, not gated              |
| Whole-codebase branch coverage                                    | report (Gold trajectory)              | **82.8%** | reported                                        |

**Why only the security surface hard-gates.** A raw whole-codebase % correlates
weakly with fault-finding, and gating on it invites test-theater on trivial
paths; the standing hard rule remains "every security-decision branch has a
negative test". The enforced bar therefore keys on the modules that decide
authentication, authorization, linking, and abuse-control outcomes (`Saml`,
`Oidc`, `Linking`, `Authz`, `Avatar`, `RateLimit`, `Identity`, `Secrets`,
`Crypto`, `Session`, `Audit`, `Flows`, `Shared`, plus the Config guard types) —
where a coverage drop plausibly means an unexercised security branch. The bar
is set just below the honest first measurement and only moves up; the known
uncovered remainder is concentrated in the hosted background services
(`SsoOnlyReconciliationService`, the LoginButtons branding sync), which run
only inside a live server and are exercised by the E2E pass (#717/#720)
instead.

Gate-(b) evidence for the P8 promotion epic (#716): this section + the CI
`coverage-report` artifact of the release-candidate run. OpenSSF `test_most`
("most branches") can be flipped to Met with 82.8% branch coverage as evidence
once refreshed on the RC build (#713 tracks the OpenSSF side).

**Rule:** a PR that adds behavior should show where it also removed/folded code;
`/quality` reports lines removed vs added. Net controller LOC is tracked release
over release — it must trend down as helpers are extracted.

## How to refresh

`/metrics` runs: open alerts (`gh api .../code-scanning/alerts?state=open`),
Dependabot alerts, merged/open PR + issue counts, `hotfix`/`revert` PR counts,
`wc -l` on the tracked source files, and the test count from `/build-test`.
Update the tables and the "Last refreshed" date; note any KPI that regressed.

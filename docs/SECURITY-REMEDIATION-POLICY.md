# Security remediation & secrets policy

The written policy behind the gates CI already enforces. Rule of this document:
it describes **what the tooling actually does** — if enforcement and policy
ever drift, the policy is corrected or the gate is fixed, never papered over.

## SCA — dependency vulnerabilities

- **Merge gate:** a pull request that introduces or upgrades to a dependency
  with a known vulnerability of **any severity (low and up)** is blocked
  (`dependency-review` runs with `fail-on-severity: low`), transitive
  dependencies included. The build itself also fails on known-vulnerable
  dependencies, so the gate holds even outside PR context.
- **Release gate:** a release is cut from a green `main`; the same checks make
  a release with a known-vulnerable dependency impossible without an explicit,
  documented exception (see _Accepted residuals_).
- **Remediation timeframe** (for a vulnerability newly published against an
  already-merged dependency): critical/high — patch or mitigate in the **next
  release, expedited if exploitation is likely** (target: days, not weeks);
  medium — next regular release; low — next regular release or batched with
  the following one. Dependabot PRs for security updates are prioritized over
  feature work (security before features).
- **Dependabot** watches both ecosystems (NuGet and GitHub Actions); its
  security PRs run the full gate like any other change.

## SAST — static analysis

- **Merge gate:** CodeQL (with the `security-extended` query pack) and the
  repository-specific Opengrep invariant ruleset run on every pull request;
  **any Opengrep finding fails the check outright** (`--error`), and CodeQL
  alerts on the PR block merge until dispositioned. The .NET build runs with
  warnings-as-errors, which promotes analyzer findings to build failures.
- **Disposition of findings:** a finding is either **fixed before merge** or
  **explicitly accepted** with a written rationale (a code comment at the site
  or a note in the PR) — silent dismissal is not an option. False positives in
  the Opengrep ruleset are fixed in the ruleset itself, never waived ad hoc.
- **Accepted residuals** are documented where they live: the
  [Review Gate](https://github.com/iderex/jellyfin-plugin-sso/wiki/Review-Gate)
  wiki page records the known accepted residual(s) of the overall gate stack.

## Secrets management

- **No plaintext secrets in version control — enforced, not aspirational:**
  GitHub secret scanning with **push protection** blocks a credential push
  before it lands; there are no committed credentials, and the repository
  history is clean of them.
- **CI credentials are least-privilege:** workflows start from an explicit
  deny-all (`permissions: {}`) and grant per-job read-only scopes; publishing
  jobs use the ephemeral `GITHUB_TOKEN` with only the scopes the job needs.
  There are no long-lived cloud credentials in this repository; if a cloud
  integration is ever added, it uses **OIDC federation, not stored secrets**.
- **Runtime secrets** (the operator's OIDC client secret, SAML signing keys)
  never appear in the repository or CI at all — they live in the operator's
  plugin configuration, AES-256-GCM-encrypted at rest with a separate key file
  (see [SECURITY.md](../SECURITY.md)), are write-only in the admin API, and are
  redacted from configuration exports.
- **Rotation:** my GitHub credentials use the platform's strong-auth features;
  a leaked or suspected-leaked credential is rotated immediately and the
  incident is noted in the affected release notes if any artifact could have
  been touched.

## Scope

This policy covers the repository, its CI, and its release artifacts. Server
operators' deployment secrets are covered by their own operational practices —
the plugin's contribution is that it never logs, exports, or returns them.

# The review gate

This repository once ran an external automated PR reviewer (GitHub Copilot's
review, and briefly CodeRabbit) that left a comment on every diff. Both were
uninstalled on 2026-07-16: the merge gate is deliberately **internal-only** — no
external review, quality, or analysis service is trusted with this repository's
code. Removing that reviewer left a **review-coverage gap** — the loss of an
independent, whole-diff second perspective on every pull request.

This document records, class by class, what a generic automated PR reviewer
would have flagged and which concrete in-repo control now covers it, then names
the one genuine residual and its disposition. It describes only controls that
exist today; it invents nothing. When a control changes, update this file.

A generic automated reviewer's findings fall into five classes: **correctness**,
**security**, **style / maintainability**, **dependency**, and **secret**. Each
is treated below.

## What runs, and when

- **Every pull request** (branch build): `dotnet build --warnaserror` + `dotnet
test`, Prettier, CodeQL (security-extended), Opengrep repo-invariant rules,
  zizmor workflow audit, the Trojan-Source/Unicode guard, dependency-review, and
  the transitive vulnerable-dependency scan. `build`, `prettier`, and
  `dependency-review` are required status checks on the protected branch (see
  the comment in each workflow); CodeQL is intentionally a non-required check.
- **Every pull request** (advisory, non-gating): the deterministic PR-hygiene
  checks (`pr-hygiene.yml`) — a self-hosted "Danger-style" gate (plain workflow +
  one first-party `github-script` step, no external Danger runtime or bot). It
  checks the pull request _as an object_ rather than the code: that the body
  carries an issue reference (Closes/Refs #N; bots exempt), that a `build.yaml`
  version bump also touches `CHANGELOG.md`, that the diff is not enormous
  (warn ≥400, fail >800 changed non-generated lines unless `override:size`), and
  that an `SSO-Auth/*.cs` change moves a test (warn only). It is deliberately
  **not** a required status check, so it never blocks a merge — it surfaces a
  deterministic hygiene signal the maintainer acts on. See the header of
  `pr-hygiene.yml` and the "Deterministic PR-hygiene" note below.
- **On a weekly schedule** (not per-PR, non-gating by construction): Stryker.NET
  mutation testing (scoped to the SAML/OIDC core), SharpFuzz fuzzing (SAML/OIDC
  parse surface), OpenSSF Scorecard, and the CodeQL baseline re-scan.
- **Process, per pull request**: at least two independent refute-by-default
  review passes on every code PR, escalating to the full four-lens adversarial
  review (plus the audit-integrity and authz domain lenses) on any change to the
  login path, SAML/OIDC crypto, config persistence, or the release pipeline.

## Coverage mapping

### Correctness

A generic reviewer flags logic slips, null dereferences, races, wrong control
flow, and missed edge cases.

- **Compiler as reviewer** — `TreatWarningsAsErrors` (Directory.Build.props) and
  `dotnet build --warnaserror` in CI turn nullable-reference, unreachable-code,
  and unused-symbol warnings into build failures.
- **Roslyn analyzers** — AnalysisMode Recommended plus Roslynator and Meziantou,
  with `CodeAnalysisTreatWarningsAsErrors`, fail the build on the analyzers'
  reliability/correctness rules; the `.editorconfig` pins per-rule severities.
- **Test suite** (`SSO-Auth.Tests`, required) — unit and endpoint tests with a
  negative test for every fail-closed branch.
- **Property-based tests** (`PropertyTests`, FsCheck) — invariants over the pure
  login-decision helpers that must hold for all inputs, not just picked cases.
- **Architecture-conformance fitness functions** (`ArchitectureConformanceTests`)
  — structural invariants that close specific correctness/race classes:
  torn-read-free immutable authorize/outcome variants (#341, #251), the
  TOCTOU revocation re-check immediately before the mint (#232), and the
  once-per-interval throttle discipline on the login-path caches.
- **CodeQL** (security-extended) also catches correctness-adjacent faults
  (null-deref, resource leaks, dead code).
- **Mutation testing** (Stryker, weekly) surfaces correctness cases the tests
  would miss, as a concrete test-writing prompt.
- **Adversarial review** — the `correctness-lens` reads the full touched files
  on login-path changes.

### Security

A generic reviewer flags injection, weak crypto, authz bypass, SSRF, and unsafe
patterns.

- **CodeQL security-extended** — ~135 taint/dataflow queries across `csharp`,
  `javascript-typescript`, and `actions`, on every PR (and the release branches).
- **Security analyzers at error** — `AnalysisModeSecurity=All` plus
  `dotnet_analyzer_diagnostic.category-Security.severity = error`, so every
  Security-category rule fails the build (e.g. CA5369, already caught and fixed).
- **Opengrep repo-invariant rules** (`tools/opengrep/rules.yml`) — greppable,
  language-parser-independent invariants: CSPRNG-only randomness, no
  `Problem()`/`ProblemDetails` leak from the controllers, all config access
  through the `ProviderConfigStore` facade, no raw outbound `HttpClient`, and no
  `gh release` mutation in the pipeline. One rule per invariant, added per
  regression.
- **Fitness functions as un-forgeable-authz analogues** — `VerifiedIdentity`'s
  private constructor with named validation factories (#473), the immutable
  in-flight authorize/outcome sums, and the "controller holds no mutable static
  state / touches no raw socket-DNS / no provider link map" boundary scans make
  whole classes of login-path misuse a failing test rather than a review catch.
- **zizmor** — static analysis of the workflow YAML itself (the release-critical
  attack surface): template-injection, excessive-permissions, unpinned actions,
  dangerous triggers.
- **Trojan-Source / Unicode guard** — rejects bidirectional and invisible
  control characters (CVE-2021-42574) that make source render differently from
  how it executes.
- **Fuzzing** (SharpFuzz, weekly) — coverage-guided fuzzing of the SAML response
  and OIDC discovery/id-token parse surface.
- **Adversarial multi-lens review** — the mandatory more-eyes gate on the
  sensitive surface: bypass, availability, correctness, and integration lenses
  plus the audit-integrity and authz domain lenses, each reading the full
  touched files and their callers and citing the relevant ASVS chapters.

### Style / maintainability

A generic reviewer flags naming, duplication, dead code, and complexity.

- **StyleCop + Roslynator + Meziantou** — style and maintainability rules,
  migrated 1:1 from the legacy ruleset into `.editorconfig`, gated by
  `--warnaserror`.
- **Prettier** (required) — formats and checks `.js` / `.html` / `.md` / `.css`.
- **Fitness functions as design conformance** — helper types must be internal
  and sealed, everything lives under one root namespace, flow logic lives in the
  extracted services, not the controller. These pin the design-consistency an
  automated reviewer would otherwise nag about.
- **PR quality checklist** — the template requires "no duplicated logic",
  "no more code than the problem requires", and self-documenting code, answered
  honestly per PR.

### Dependency

A generic reviewer flags vulnerable or outdated dependencies.

- **dependency-review-action** (required, `fail-on-severity: low`) — blocks a PR
  that introduces or upgrades to a known-vulnerable dependency.
- **Transitive vulnerable scan** — `dotnet list package --vulnerable
--include-transitive` fails the build on any known-vulnerable dependency.
- **Dependabot** — watches both ecosystems (NuGet and github-actions).
- **Locked-mode restore** — committed `packages.lock.json` files with
  `RestoreLockedMode` in CI fail the restore on any drift or tampering.
- **SHA-pinned actions + Scorecard** — every workflow `uses:` is pinned to a
  full commit SHA; the weekly Scorecard scan audits Pinned-Dependencies,
  Token-Permissions, and Dangerous-Workflow posture.

This class is covered more strongly than a generic reviewer could manage.

### Secret

A generic reviewer flags credentials committed to the diff.

- **Secret scanning with push protection** — a leaked identity-provider client
  secret or CI token is blocked before the push lands, not merely commented on
  after the fact. This is a hard gate, stronger than a reviewer's best-effort
  spotting.
- **Config secret redaction** — secrets are wrapped and redacted on config
  export (`SecretEnvelope`, exercised by `ConfigSecretProtectionTests`).

## Residual gap and disposition

**The one class no current control fully reconstitutes:** an _independent_,
per-line, whole-diff second reader on **every** pull request — including the
low-risk, non-login, non-security diffs (routine refactors, tooling, docs) — that
flags local logic slips, off-by-ones, and readability issues the static tools
and the scoped test/fitness/fuzz suites do not specifically target.

Why the existing controls narrow but do not close it:

- The compiler, analyzers, CodeQL, Opengrep, and the test/fitness suites catch
  the **mechanically detectable** subset on every PR, on every surface. They do
  not reason about intent on an arbitrary diff.
- The **adversarial multi-lens review** is deeper than any generic reviewer, but
  it is mandatory only on the login / crypto / config / pipeline surface, and it
  is run by the same solo maintainer (with AI assistance), so on a routine
  low-risk PR it is not a genuinely _independent second party_.
- Mutation testing and fuzzing are **weekly and non-gating**, scoped to the
  SAML/OIDC core — so a test-quality regression or a parser crash on a non-core
  surface is caught on the next weekly run, not at PR time.

**Disposition: accepted residual risk, mitigated not eliminated.** This is a
single-maintainer project by governance — no second human reviewer exists by
design, and re-adding an external automated reviewer is explicitly out of scope
(the merge gate is internal-only). The risk is bounded because:

1. The **highest-risk surface** (the login path and the release pipeline) does
   receive the mandatory adversarial review, so the residual is confined to
   lower-risk diffs.
2. The **mechanically detectable** subset is caught on every PR regardless of
   surface by the compiler, analyzers, CodeQL, Opengrep, and the fitness/test
   suites.
3. Every code PR still gets **at least two independent refute-by-default review
   passes**, which — while not an external party — is a deliberate more-eyes
   process rather than a single unreviewed read.
4. `CONTRIBUTING.md` places the second-reader duty on the author explicitly:
   "understand and own every line you propose", backed by the PR quality
   checklist.

A staged, self-hosted fallback reviewer was scoped for this program but is
deliberately **not adopted**, to keep the gate free of an external service
dependency; if the residual is ever judged too wide, that is the lever to pull.
The direction — an author-independent review perspective on every diff — is the
standing goal; this document records how far the internal gate currently closes
it.

## Deterministic PR-hygiene (#171): what is checked, and what was declined

`pr-hygiene.yml` implements the deterministic, mechanically-decidable subset of
the PR-process checks scoped in #171 — the ones that add real value beyond the
existing CI and do not red-flag a reasonable pull request. Two of the four
acceptance-criteria items were deliberately **not** implemented; that is a
reasoned decline, recorded here so the decision is auditable.

**Implemented (high-confidence, in `pr-hygiene.yml`):**

- **Issue reference** — a non-bot PR whose body carries no `#N` / issue-URL
  reference fails. Closes the issue-driven-linkage gap; nothing else checked it.
- **CHANGELOG on version bump** — a `build.yaml` `version:` change that does not
  also touch `CHANGELOG.md` fails. Deterministic release hygiene; near-zero
  false-positive because only a release PR edits the version line.
- **PR size** — warn ≥400, fail >800 changed lines (generated/lock files
  excluded), with an `override:size` label as the escape hatch for a genuinely
  atomic large change. Reviewer effectiveness degrades on large diffs.
- **Test co-change** — an `SSO-Auth/*.cs` change with no `SSO-Auth.Tests/*`
  change **warns only**, never fails: a docs/comment/refactor edit legitimately
  moves no test, and hard-failing those is exactly the false-positive friction
  the issue warns against.

**Declined, with rationale:**

- **Sensitive-path diffs without a sign-off gate note (AC3).** A regex over the
  PR body for a "security-review sign-off note" would be a fuzzy proxy for a
  control that already exists and is stronger. The login / SAML-OIDC-crypto /
  config-persistence / release-pipeline surface already gets the **mandatory
  adversarial multi-lens review** (this document, above) plus the PR template's
  security checklist; a body-grep cannot tell a genuinely-reviewed PR from one
  that merely pattern-matches the expected wording, so it would produce
  false confidence on the miss and false-positive friction on legitimately
  reviewed PRs whose note is phrased differently. The human gate is the control;
  a deterministic grep would add noise, not assurance.
- **Issue-open triage-lint: type + area + priority + milestone (AC4).** These
  facets are assigned by the maintainer **during triage**, not by the author at
  open time — and community bug/feature issues are filed through the public
  templates, which cannot set them. Enforcing them on `issues.opened` would
  red-flag essentially every externally-filed issue the moment it is created,
  penalising exactly the outside contributors the project wants to welcome, for
  a step that is a maintainer responsibility rather than an author obligation.
  Triage stays a manual maintainer action; automating it as an open-time gate
  trades a small consistency gain for constant, unfair false-positive friction.

If the declined items are ever revisited, the honest form of AC4 is a
maintainer-scoped nudge (run only on issues opened by a maintainer, or as a
periodic untriaged-issue report), not an open-time hard gate — and AC3's value
is already delivered by the adversarial review, not a body-grep.

## Pointers

- `SECURITY.md` — the repository security controls, condensed, and the private
  vulnerability-reporting path.
- `CONTRIBUTING.md` — the build/test commands and the branch → PR flow.
- `.github/workflows/` — the CI workflows named above.
- `.github/workflows/pr-hygiene.yml` — the deterministic PR-hygiene checks (#171).
- `tools/opengrep/rules.yml` — the greppable security invariants.
- `SSO-Auth.Tests/ArchitectureConformanceTests.cs` — the fitness functions.

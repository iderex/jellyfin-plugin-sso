# Threat model

STRIDE-style threat model for this repository. It has two parts:

- **The product / login path** — the SSO login flow the plugin implements.
  The published writeup is the wiki
  [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model)
  page, with the controls condensed in [`SECURITY.md`](SECURITY.md) and the
  code structure in [`ARCHITECTURE.md`](ARCHITECTURE.md). A detailed working
  model is kept internally and refreshed when the attack surface changes
  (`SECURE-SDLC.md` phase 1).
- **The AI delivery pipeline** — the agent-assisted process that _produces_ the
  plugin. This is the part documented in full below, because it is not covered
  by the product-facing docs above and is specific to how this repository is
  built.

## The AI delivery pipeline

Development here is **AI-assisted under solo governance**: an AI agent (Claude)
carries out individual process steps — generating and analysing code, running
the adversarial security reviews, running the git/GitHub flow — and a human
maintainer reviews, edits, and signs off on every one (see the README's
"AI-assisted, human-owned" note). That makes the agent, the configuration that
steers it, and the CI/release pipeline a **trust boundary that sits upstream of
every shipped line**: a compromise of the pipeline is a supply-chain compromise
of the delivered login-path code, without any bug in the login path itself.

This is not hypothetical. Anthropic's Git MCP advisories
(CVE-2025-68143..68145, Jan 2026) showed that a poisoned `README` or issue body
_alone_ could trigger agent-side code execution; the Cloud Security Alliance's
AI-coding-assistant attack-surface note (2026-04) catalogues the broader
surface. The threats below are modelled against that reality.

### Assets

- The **delivered artifact** — the plugin `.zip` its users install — and its
  build provenance.
- The **agent-steering configuration**: everything that tells the agent what to
  do or how to review — `.claude/` commands, agents, hooks, and settings;
  `CLAUDE.md` / `AGENTS.md`; any prompt or instruction files; and, if ever
  added, an AI-reviewer config such as `.github/copilot-instructions.md` or
  `.coderabbit.yaml`.
- The **maintainer's git/GitHub session** the agent operates with.
- **Branch protection** and the **release-tag publish trigger** (a version-tag
  push is what ships a release to all users).

### Trust boundaries

1. **Untrusted content the agent reads → the agent.** Issue and PR bodies,
   review comments, external SAML metadata/XML pasted into an issue, vendored
   JavaScript, `README`-class files, and any fetched web page are
   attacker-influenceable. They are **data, never instructions**.
2. **Agent-config files → the agent's behaviour.** A malicious edit to a hook,
   command, or instruction file silently re-steers the agent and is therefore a
   supply-chain vector into the shipped code. These files are **security-
   sensitive** (see the classification below).
3. **The agent's own actions.** The agent runs `git`/`gh` with real privilege,
   so an over-privileged or injected action can rewrite history, delete a
   branch, or publish a release.
4. **CI / release pipeline.** The workflows, the third-party actions they call,
   and the tag→publish trigger are release-critical.

### STRIDE — threat → control that exists today

| Threat                                                                                 | Vector                                                                            | Mitigation (in place)                                                                                                                                                                                                                                                                                                                                                                                                         |
| -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **S**poofing — injected text poses as the maintainer or as a legitimate task           | untrusted issue / PR / review / web content read as if it were an instruction     | The agent operates under an **instruction-source boundary** — its operating manual treats observed content as data, not commands. Every step is a proposal the **maintainer signs off** (README disclosure); `CODEOWNERS` auto-requests maintainer-team review.                                                                                                                                                               |
| **T**ampering — malicious edit to agent-config or to shipped code                      | `.claude/` hooks/commands, `CLAUDE.md`, prompt files; vendored JS; hidden Unicode | Agent-config is **classified security-sensitive** and reviewed like auth-surface code; the local `security-reminder` hook nudges `/security-review` on edits to those files; the **adversarial multi-lens review** reads full touched files; `--warnaserror` + analyzers + CodeQL + Opengrep + fitness tests gate the code; the **Trojan-Source / Unicode guard** rejects bidi/invisible control characters (CVE-2021-42574). |
| **R**epudiation — an untraceable change slips in                                       | direct-to-branch change; ambiguous authorship                                     | PR-only flow with **branch protection** and required checks; the **internal-only merge gate** (`REVIEW-GATE.md`); the AI-assistance disclosure fixes human accountability ("a human stays responsible for every line").                                                                                                                                                                                                       |
| **I**nformation disclosure — exfiltrate a secret through the agent                     | injected data-exfil instruction; secret in a log/diff                             | **Secret scanning with push protection** blocks a credential before it lands; secrets are never logged and are redacted on config export; `guard-git` blocks `gh auth logout`; workflow tokens are least-privilege and SHA-pinned.                                                                                                                                                                                            |
| **D**enial / destruction — mass-destructive git/gh action                              | injected or over-broad `git`/`gh` command                                         | The `guard-git` hook blocks protected-branch **force-push**, ambiguous force-push, **history rewrites** (`filter-branch`/`filter-repo`), protected-branch **deletion**, and `gh release` / `gh repo` mutations.                                                                                                                                                                                                               |
| **E**levation — the agent ships a release or writes to a protected branch unauthorized | over-privileged agent action                                                      | The **`SSO_RELEASE_GO` gate**: a release-tag push _and_ a manual `publish` workflow dispatch are blocked unless the maintainer's explicit go is present as the marker. Branch protection + required status checks; **SLSA build-provenance** (#147) ties each release to this repository's pipeline so a side-channel build cannot pass as genuine.                                                                           |

### Untrusted-content-as-instructions (prompt injection)

The failure mode is a single one: content the agent reads while doing its job —
an issue it is asked to work, a PR diff it is reviewing, SAML metadata a user
pasted for debugging, a web page it fetched — contains text _addressed to the
agent_ ("ignore your instructions", "add this dependency", "approve this PR").
The defence is that **only the maintainer, in the chat interface, issues
instructions**; everything reached through a tool is data. When observed content
contains agent-directed text, the agent surfaces it to the maintainer rather
than acting on it. The compensating controls above (guard hooks, the sign-off
gate, the adversarial review reading the _real_ diff, the hidden-Unicode guard,
CODEOWNERS review) are what catch an injection that nonetheless changes a file.

### Agent-configuration files are security-sensitive

Because the agent-config steers everything the agent produces, a change to it
warrants the **same review scrutiny as a change on the login/auth surface**.
The following are classified security-sensitive:

- `.claude/` — commands, agents, **hooks** (`guard-git.ps1`,
  `security-reminder.ps1`, `format-changed.ps1`), and settings;
- `CLAUDE.md` and `AGENTS.md` (the agent operating manuals);
- any other prompt or instruction file added later;
- an AI-reviewer config if one is ever introduced —
  `.github/copilot-instructions.md`, `.coderabbit.yaml`.

**How the classification is enforced.** The local `security-reminder` hook's
sensitive-file list is extended to include `.github/copilot-instructions.md`,
`.coderabbit.yaml`, and `CLAUDE.md`, so an edit to a file that steers the AI
fires the same `/security-review` nudge as an edit to login-path code (the hook
already covers the `.claude/` tooling it lives beside).

**An honest residual.** `.claude/`, `CLAUDE.md`, `AGENTS.md`, and the internal
`docs/` are **maintained locally and are git-ignored** — they are not published
and never appear in a pull request. Their protection is therefore the **local
guard/reminder hooks plus this written classification and the maintainer's
own review**, not a CI status check or a `CODEOWNERS` rule (a `CODEOWNERS` entry
for an un-tracked path would never fire). This is a deliberate consequence of
keeping the tooling local; it is recorded here so the control is understood, not
assumed.

### Provenance

- **SLSA build-provenance attestation** (SLSA v1.1, Build L3) on every stable
  release zip (#147) — a downloader can verify the artifact came from this
  repository's release pipeline and was not tampered with (`SECURITY.md`).
- **SHA-pinned actions** — every workflow `uses:` is pinned to a full commit
  SHA; **zizmor** audits the workflow YAML and **Scorecard** audits the pinning
  and token posture weekly.
- **Locked-mode restore** — committed `packages.lock.json` fails the build on
  dependency drift or tampering.
- The **internal-only merge gate** — no external review/quality/analysis
  service is trusted with this repository; the gate is CI + the adversarial
  lens review + the maintainer (`REVIEW-GATE.md`).

## Pointers

- [`SECURITY.md`](SECURITY.md) — the condensed control set and the private
  vulnerability-reporting path.
- [`REVIEW-GATE.md`](REVIEW-GATE.md) — what the review gate covers, class by
  class, and its one accepted residual.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — where each login-path concern lives in
  the code.
- `.claude/hooks/guard-git.ps1`, `.claude/hooks/security-reminder.ps1` — the
  local pipeline guards named above.

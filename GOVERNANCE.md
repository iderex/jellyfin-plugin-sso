# Governance

How this project is run, who holds access, and how decisions are made. The
guiding principle is honesty: this document describes the governance that
actually exists, not the governance a larger project would have.

## Roles and access

This is a **single-person project**. I, **@iderex**, hold admin access to the
repository, write access to all branches, and control of the release pipeline
(version tags, release publication, and the plugin manifest). No one else has
commit, review, or release authority.

Development is **AI-assisted** (see the README's "AI-assisted, human-owned"
section): Claude (Anthropic) executes process steps under my direction, and I
review and sign off on what ships. The additional accounts named in
`.github/CODEOWNERS` operate under the same AI-assisted model and are annotated
as such there — their reviews are **not independent human auditing**, and this
project claims otherwise nowhere. The quality gates that stand in for a review
team are the CI gate (build with warnings-as-errors, the full test suite,
conformance checks, CodeQL, supply-chain checks) and the adversarial multi-lens
security review run on every change to the login path (see the
[Review Gate](https://github.com/iderex/jellyfin-plugin-sso/wiki/Review-Gate)
wiki page).

## Decision-making

- **Changes** follow the gated flow in [CONTRIBUTING.md](CONTRIBUTING.md):
  issue → branch → tests → review gates → PR → CI-green merge.
- **Scope and releases** I decide, guided by the public
  [Roadmap](https://github.com/iderex/jellyfin-plugin-sso/wiki/Roadmap) and its
  maturity ladder; releases follow the
  [Releasing](https://github.com/iderex/jellyfin-plugin-sso/wiki/Releasing)
  (channel/soak promotion).
- **Security decisions outrank feature decisions.** Anything touching the login
  path passes the adversarial review gate before merge.
- Community input is welcome through issues and discussions; the final call is
  mine.

## Granting elevated access

No one but me has standing elevated access. If that ever changes, the bar is: a
track record of high-quality contributions here, a direct conversation with me,
least-privilege scoping (write before admin, never release-signing), and a
public update to this document in the same PR that grants the access. Elevated
permissions are never granted implicitly or in bulk.

## Continuity (bus factor)

A one-person project carries an honest bus factor of one. Mitigations in place:

- Everything needed to build, test, and release is **in the repository** —
  reproducible CI, documented release pipeline, no private build secrets beyond
  standard GitHub tokens.
- The license (GPL-3.0) guarantees the community can fork and continue at any
  time; the archived upstream (`9p4/jellyfin-plugin-sso`) proves the model —
  this project _is_ such a continuation.
- If I can no longer maintain it, the intent is to archive the repository with
  a clear notice rather than leave it silently stale.

Structural one-person limits (what badge levels this ceiling caps) are tracked
openly in the maturity-map work
([#749](https://github.com/iderex/jellyfin-plugin-sso/issues/749)).

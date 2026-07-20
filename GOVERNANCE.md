# Governance

How this project is run, who holds access, and how decisions are made. The
guiding principle is honesty: this document describes the governance that
actually exists, not the governance a larger project would have.

## Roles and access

This is a **single-maintainer project**. The maintainer — **@iderex** — holds
admin access to the repository, write access to all branches, and control of
the release pipeline (version tags, release publication, and the plugin
manifest). There are no other people with commit, review, or release authority.

Development is **AI-assisted** (see the README's "AI-assisted, human-owned"
section): Claude (Anthropic) executes process steps under the maintainer's
direction, and the maintainer reviews and signs off on what ships. The
additional accounts named in `.github/CODEOWNERS` operate under the same
AI-assisted model and are annotated as such there — their reviews are **not
independent human auditing**, and this project does not claim otherwise. The
quality gates that stand in for a review team are the CI gate (build with
warnings-as-errors, the full test suite, conformance checks, CodeQL, supply-chain
checks) and the adversarial multi-lens security review run on every change to
the login path (see the [Review Gate](https://github.com/iderex/jellyfin-plugin-sso/wiki/Review-Gate)
wiki page).

## Decision-making

- **Changes** follow the gated flow in [CONTRIBUTING.md](CONTRIBUTING.md):
  issue → branch → tests → review gates → PR → CI-green merge.
- **Scope and releases** are decided by the maintainer, guided by the public
  [Roadmap](https://github.com/iderex/jellyfin-plugin-sso/wiki/Roadmap) and its
  maturity ladder; releases follow the
  [Release Policy](https://github.com/iderex/jellyfin-plugin-sso/wiki/Release-Policy)
  (channel/soak promotion).
- **Security decisions outrank feature decisions.** Anything touching the login
  path passes the adversarial review gate before merge.
- Community input is welcome through issues and discussions; the maintainer has
  the final say.

## Granting elevated access

No standing elevated access is granted to anyone beyond the maintainer. If that
ever changes, the bar is: a track record of high-quality contributions here, a
direct conversation with the maintainer, least-privilege scoping (write before
admin, never release-signing), and a public update to this document in the same
PR that grants the access. Elevated permissions are never granted implicitly or
in bulk.

## Continuity (bus factor)

A solo project carries an honest bus factor of one. Mitigations in place:

- Everything needed to build, test, and release is **in the repository** —
  reproducible CI, documented release pipeline, no private build secrets beyond
  standard GitHub tokens.
- The license (GPL-3.0) guarantees the community can fork and continue at any
  time; the archived upstream (`9p4/jellyfin-plugin-sso`) proves the model —
  this project _is_ such a continuation.
- If the project becomes unmaintained, the intent is to archive the repository
  with a clear notice rather than leave it silently stale.

Structural solo-maintainer limits (what badge levels this ceiling caps) are
tracked openly in the maturity-map work
([#749](https://github.com/iderex/jellyfin-plugin-sso/issues/749)).

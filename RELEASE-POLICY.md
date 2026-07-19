# Release policy — versioning and the beta soak (canary) stage

This is the policy the publish workflows and the changelog point at. It defines
the four-part version scheme, the two release channels, and — the substance of
this document — the **beta soak**: the formal canary stage a build passes
through before a stable tag is cut.

For an authentication plugin a bad stable release is a mass-lockout event (see
[ROLLBACK.md](ROLLBACK.md)). The soak stage is the availability control that
sits _before_ rollback: it puts every stable candidate in front of real,
opt-in beta installs for a defined window so a load-time or login-path
regression is caught on beta testers, not on the whole fleet.

---

## 1. Versioning

Versions follow the four-part `X.Y.Z.W` scheme, class-encoded:

- **X — breaking**, **Y — feature**, **Z — bug-fix**, **W — security**.

The maintainer sets the next _release target_ `X.Y.Z` in `build.yaml`
(`build-jf12.yaml` for the JF12 line) per the change class of what has landed —
a patch bumps `Z`, a feature bumps `Y`, a breaking change bumps `X`. That target
is what the beta builds toward and what the matching `-stable` tag releases; the
publish job checks the tag's numeric prefix equals `build.yaml`'s `version`.

## 2. Channels and how a release is triggered

Jellyfin has no in-manifest channel flag, so the channels are **separate
manifest branches**:

| Channel    | Manifest branch    | `ignorePrereleases` | Trigger                                                                    |
| ---------- | ------------------ | ------------------- | -------------------------------------------------------------------------- |
| **beta**   | `manifest-beta`    | `false`             | Daily scheduler ([nightly-betas.yml](.github/workflows/nightly-betas.yml)) |
| **stable** | `manifest-release` | `true`              | A maintainer-pushed `-stable` tag                                          |

- **Beta** is minted by [`publish-beta.yml`](.github/workflows/publish-beta.yml)
  (JF10.11, from `main`) and
  [`publish-jf12-beta.yml`](.github/workflows/publish-jf12-beta.yml) (JF12, from
  `4.2`), which the daily `nightly-betas.yml` scheduler dispatches at 04:00 UTC.
  Each leg has a **gate job** that skips the build unless its branch advanced
  since that lineage's last beta, so an unchanged day mints nothing. The beta
  version is the next target `X.Y.Z` with the workflow run number as the fourth
  octet (`X.Y.Z.<run>`), released as the prerelease `X.Y.Z-beta`.
- **Stable** is cut only by a maintainer **pushing a tag by hand** —
  `X.Y.Z-stable` ([`publish.yml`](.github/workflows/publish.yml), JF10.11) or
  `X.Y.Z-JF12-stable`
  ([`publish-jf12-stable.yml`](.github/workflows/publish-jf12-stable.yml), the
  5.0 line, dormant until Jellyfin 12.0 GA). The tag push is protected-branch /
  version-tag gated by `guard-git.ps1`. **There is no automatic promotion from
  beta to stable** — the promotion gate below is a human gate, and the stable
  tag is the act of clearing it.

Releases are **immutable** (issue #146): assets are sealed on publish and tags
are single-use. That is why the beta job uses a draft → attach → publish flow
and why a burned tag can never be re-cut.

## 3. The release maturity ladder

Each stable version climbs this ladder before it reaches the stable manifest.
This is a **per-release** ladder (distinct from the product-wide maturity ladder
in the README — _In-Development → Alpha → …_ — which describes the plugin as a
whole).

| Rung                   | Where it lives                     | Audience                   | What it means                                                  |
| ---------------------- | ---------------------------------- | -------------------------- | -------------------------------------------------------------- |
| **Unreleased**         | `main` HEAD (or `4.2` for JF12)    | CI only                    | Merged, green, but not yet built for install.                  |
| **Beta (canary soak)** | `manifest-beta`, `X.Y.Z-beta`      | Opt-in beta installers     | Installable prerelease of the exact commit a stable would tag. |
| **Stable**             | `manifest-release`, `X.Y.Z-stable` | Everyone on the stable URL | Promoted after clearing the soak + the promotion gate.         |

**The beta build _is_ the canary.** It is a real installable build of the same
commit a stable tag would point at, served automatically to everyone on the beta
repository URL. Promoting it to stable is publishing the identical source under a
`-stable` tag; the soak is the observation window in between.

## 4. The soak window (N)

**Default N = 7 calendar days.** A stable candidate must have been published as
the **newest** beta on `manifest-beta`, unchanged, for at least N days with **no
regression report** filed against it before its `-stable` tag is pushed.

Definition and rules:

- **Newest-and-unchanged.** The soak clock is on the specific commit the stable
  tag will point at. To run the soak, ensure the current newest beta is built
  from that commit (dispatch `publish-beta.yml` if `main` has moved past the last
  daily beta), then hold `main` — merge only fixes that are themselves
  stable-blockers.
- **A new beta resets the clock.** If any commit lands during the window (a soak
  fix or otherwise), a new beta supersedes the candidate and the N-day clock
  restarts on the new commit. You cannot promote a commit older than the newest
  soaked beta.
- **"No regression report"** means no open bug attributing a fault to that beta
  (or a newer beta) — a load failure, a broken login path, or any behaviour the
  previous stable did not have. Pre-existing, unrelated open issues do not block.
- **Install count is not measured.** This plugin ships **no telemetry** by
  design (compliance/privacy posture), so the gate is **time-plus-evidence**, not
  an install counter: the N-day window plus the manual E2E checklist (§5) stand
  in for a measured install threshold. N is a floor the maintainer may lengthen
  for a risky change; §6 is the only rule that shortens it.

## 5. The promotion gate

All of the following must hold before pushing an `X.Y.Z-stable` (or
`X.Y.Z-JF12-stable`) tag. This is the checklist `/release-prep` runs, and it
composes the two existing pre-publish checklists rather than duplicating them.

- [ ] **Soak satisfied.** The candidate commit's beta has been the newest
      `manifest-beta` build for **≥ N days** (default 7) with no regression
      report against it (§4) — or §6's security-shortening rule is invoked with a
      written reason.
- [ ] **Manual E2E checklist passed** against the beta build on a real server:
      every item in [RELEASE-QA-CHECKLIST.md](RELEASE-QA-CHECKLIST.md) (real-IdP
      OIDC/SAML login, proxy attribution, packaging/install/upgrade, dashboard
      rendering). These are exactly the behaviours CI cannot exercise, so the
      soak is where they are verified.
- [ ] **Rollback path confirmed.** The pre-publish downgrade smoke check in
      [ROLLBACK.md §7](ROLLBACK.md#7-e2e-downgrade-smoke-check-wire-into-release-prep)
      passes: the new manifest retains prior versions and a downgrade to the
      previous stable still loads and logs in without secret re-entry (or, if a
      format boundary is crossed, ROLLBACK.md §3 and `CHANGELOG.md` are updated).
- [ ] **Version matches the tag.** `build.yaml` (`build-jf12.yaml` for JF12)
      `version` equals the tag's numeric `X.Y.Z` prefix (the publish job also
      enforces this) and the change class matches the `W`-part bump in the
      four-part version.
- [ ] **Changelog updated.** `CHANGELOG.md` has the release's entry.

Clearing every box is the precondition for the tag push; the tag push is the
promotion. Nothing promotes a beta automatically.

## 6. Security-patch shortening

A fix for an **exploitable vulnerability** or an active **mass-lockout
regression** may shorten N — down to zero — because shipping the fix fast
outweighs a full soak. When N is shortened:

- Record the reason in the release notes and `CHANGELOG.md` (the `W` security
  bump documents the class).
- Still run the §5 manual E2E checklist and the ROLLBACK.md §7 downgrade smoke —
  those guard against the fix itself causing a mass-lockout, which the soak would
  otherwise have caught. The soak time is what shortens, not the E2E gate.
- Prefer **fix-forward** (ROLLBACK.md §6): a higher patch version pulls the
  fleet forward. A shortened soak is the release-side counterpart to a
  fix-forward.

## 7. Rollback tie-in

The soak lowers the probability that a stable needs rollback; it does not remove
the need for one. The two are complementary controls:

- **Before promotion:** the soak (this document) is the preventive gate.
- **After a bad promotion:** [ROLLBACK.md](ROLLBACK.md) is the containment —
  fix-forward with a higher patch version, or de-list the bad version from
  `manifest-release`, never delete the immutable release or reuse its tag.

The ROLLBACK.md §7 downgrade smoke is shared by both: it is a promotion-gate
item here _and_ the rollback runbook's pre-publish check, so the rollback path
is proven to work on the same candidate the soak just cleared.

## 8. Coordination with the immutable-releases / nightly redesign (#146)

Issue #146 (done) replaced the old mutable rolling `nightly` tag with the
immutable **daily beta channel** used here: the scheduler mints a dated,
single-use `X.Y.Z-beta.<run>` release into `manifest-beta` instead of moving one
tag. This soak policy is defined on that redesigned channel — the canary is the
daily beta, not a rolling nightly tag. The JF12 line (`publish-jf12-beta.yml` →
`X.Y.Z-JF12-beta`, shared `manifest-beta`) soaks the same way; its stable leg
stays dormant until Jellyfin 12.0 GA, at which point a `X.Y.Z-JF12-stable` tag
clears this same gate.

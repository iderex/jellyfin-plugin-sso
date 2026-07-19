# DORA delivery metrics

How this repository measures delivery performance, and the honest limits of
those measurements. The four DORA keys — deployment frequency, lead time for
changes, change-failure rate (CFR), mean time to restore (MTTR) — are derived
from data this project already produces: `X.Y.Z-stable` release tags, git commit
history, and the `bug`-labelled issue timeline. No external analytics service is
involved (the merge gate is internal-only).

`scripts/dora-metrics.sh` computes every number below. It is **read-only** (local
git objects plus optional read-only `gh` queries) and **deterministic** (same
repo state → same report). It writes nothing to git or GitHub.

```sh
scripts/dora-metrics.sh
```

`gh` is optional: with it authenticated, the report adds the closed-`bug`-issue
corpus as a corroborating change-failure signal; without it, the four keys are
still computed from git alone.

## Why the definitions are adapted

The canonical DORA definitions assume a continuously deployed service with an
incident tracker and production telemetry. This is a **self-hosted, single-binary
Jellyfin plugin** with **solo governance**: "production" is a released `.dll` a
server admin installs, there is no central runtime we observe, and there is no
separate incident system. Each key is therefore operationalised against the
delivery artifacts that actually exist here. Where that makes a metric an
approximation, it is stated — measured, never assumed.

## The delivery model this measures

- **A deployment = one `X.Y.Z-stable` release tag.** Pre-production tags
  (`*-beta`, `*-JF12-beta`, `nightly`, `v*`) are excluded — they are not shipped
  to the stable channel.
- **A change = a non-merge commit** that first ships in a given stable release,
  i.e. a commit in the range `(previous-stable .. this-stable]`.
- **A failure = a release that needed a same-line patch remediation.** Because
  there is no runtime incident feed, the observable proxy for "this deployment
  caused a problem" is: the next stable release on the same `X.Y` line is a
  patch (`Z`) bump — a hotfix. This is the standard DORA CFR proxy and it is
  auto-derivable from tag topology, so CFR stays measured, not assumed.

## The four keys

### 1. Deployment frequency

Count of `*-stable` tags, with the calendar span between the first and last, and
a per-week / per-month rate.

- **Limitation:** the rate needs a span of at least a day to be meaningful; while
  all stable releases sit within one day the script reports the count and marks
  the rate `n/a` rather than printing a misleading extrapolated figure.

### 2. Lead time for changes

For every stable release that has a predecessor stable release, each non-merge
commit in `(predecessor .. release]` contributes `release_date −
commit_author_date`. Reported as median, p90, min, and max across all such
commits.

- **Limitation — earliest tag skipped:** the oldest stable tag has no predecessor
  stable tag, so its interval would reach back to the repository root and swamp
  the distribution. That interval is excluded; lead time is computed only over
  intervals bounded by two stable tags.
- **Limitation — author date:** commit author date can precede the real "work
  started" moment (rebases, cherry-picks). It is the most faithful signal
  available from git without heavier PR archaeology.

### 3. Change-failure rate (CFR)

`failures / judgeable releases`, where a release is a **failure** if its immediate
same-line successor is a patch bump (a hotfix), and **judgeable** means every
release except the newest (nothing follows the newest yet, so it cannot be
judged — it is excluded from the denominator, not scored as a pass).

Corroborating signals printed alongside, which do **not** change the primary
count: the number of explicit `Revert` commits across the stable window, and
(with `gh`) the count of closed `bug`-labelled issues.

- **Limitation — small denominator:** with only a handful of releases, one hotfix
  swings CFR by tens of percent. Read the trend across many releases, not a
  single value.
- **Limitation — topology, not causation:** a patch bump is assumed to be a
  remediation. A deliberately-planned patch would be miscounted as a failure. The
  script prints the time gap so a reader can tell a rushed hotfix (minutes) from
  a long-planned patch (weeks); the `HOTFIX_WINDOW_DAYS` annotation flags the
  fast ones.

### 4. Mean time to restore (MTTR)

For each failure→hotfix pair, `hotfix_date − failed_release_date`; reported as
mean and median across pairs.

- **Limitation — upper bound:** this measures release-to-release recovery. The
  defect is usually discovered some time _after_ the release, so this overstates
  user-facing time-to-restore. It is a consistent, conservative proxy.

## Supplementary AI-risk / delivery-stability indicators

Most changes here are agent-authored under solo governance. DORA's 2025/26
guidance flags **instability of agent-authored change** as the leading delivery
risk, so the report tracks three leading indicators beyond the four keys. The
first two are git-derived; the third is tracked by hand.

| Indicator                  | Definition                                                                         | Source                    | Cadence                    |
| -------------------------- | ---------------------------------------------------------------------------------- | ------------------------- | -------------------------- |
| **Revert rate**            | `Revert` commits ÷ non-merge commits across the stable window                      | git (auto)                | Per release                |
| **Rework signal**          | count of `fixup`/`amend`/`re-fix`/`follow-up` commit subjects in the stable window | git (auto, heuristic)     | Per release                |
| **Review-finding density** | real `/security-review` findings (FIX or reasoned DECLINE) per merged PR           | `/security-review` output | Per PR; reviewed per phase |

- **Rework signal is a heuristic:** it matches commit-subject prefixes, so it
  under-counts silent reworks and is only a directional smell, not an exact
  rework rate.
- **Review-finding density is not auto-derivable:** it needs the adversarial-review
  lens output, which lives in the review record, not in git. It is recorded
  manually per PR and reviewed once per delivery phase. Rising density on
  agent-authored diffs is the signal to tighten the gate.

## Stated cadence

Run `scripts/dora-metrics.sh` **at each stable release** and record the four keys
plus the two git-derived indicators. Review-finding density is logged **per PR**
and read **per delivery phase**. The stability gates (green CI, the adversarial
`/security-review`, maintainer sign-off) remain the firm merge bar; these metrics
observe delivery, they do not relax the gate.

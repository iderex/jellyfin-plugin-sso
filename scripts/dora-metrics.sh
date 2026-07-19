#!/usr/bin/env bash
#
# DORA four-key delivery metrics for jellyfin-plugin-sso (issue #175).
#
# Derives the four DORA keys (deployment frequency, lead time for changes, change-failure
# rate, mean time to restore) plus two cheap AI-risk indicators (revert rate, rework signal)
# from THIS repo's actual delivery data: `*-stable` release tags, git commit history, and —
# when the `gh` CLI is authenticated — the `bug`-labelled issue timeline. No new tooling.
#
# The operational definitions, and where a metric is only an approximation given the small
# dataset, are documented in DORA-METRICS.md at the repo root. Read that first.
#
# The script is READ-ONLY and deterministic: it only reads local git objects and (optionally)
# makes read-only `gh` queries. It never writes to git or GitHub. Re-running it on the same
# repo state produces the same report.
#
# Usage:  scripts/dora-metrics.sh
# Requires: git (mandatory), gh (optional — enriches the change-failure signal).
#
set -euo pipefail

# --- Configuration (repo-specific delivery conventions) ---------------------------------------
# A production "deployment" for this plugin is a stable release, tagged `X.Y.Z-stable`.
# Beta / JF12-beta / nightly tags are pre-production and are deliberately excluded.
STABLE_GLOB='*-stable'
# A patch-level (Z) bump on the same X.Y line is treated as a hotfix / remediation of the
# preceding release on that line — the standard DORA change-failure proxy. HOTFIX_WINDOW_DAYS
# only annotates the report (fast hotfix vs. long-planned patch); it does NOT gate the CFR count.
HOTFIX_WINDOW_DAYS=7

# --- Preconditions ----------------------------------------------------------------------------
command -v git >/dev/null 2>&1 || { echo "error: git is required" >&2; exit 1; }
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "error: not a git repo" >&2; exit 1; }

GH_AVAILABLE=0
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  GH_AVAILABLE=1
fi

now_epoch=$(date +%s)

# --- Helpers ----------------------------------------------------------------------------------
# Render a duration in seconds as a compact human string (e.g. "2d 3h", "41m").
human_duration() {
  local s=$1 d h m
  if (( s < 0 )); then s=0; fi
  d=$(( s / 86400 )); s=$(( s % 86400 ))
  h=$(( s / 3600 ));  s=$(( s % 3600 ))
  m=$(( s / 60 ))
  if   (( d > 0 )); then printf '%dd %dh' "$d" "$h"
  elif (( h > 0 )); then printf '%dh %dm' "$h" "$m"
  else                   printf '%dm' "$m"
  fi
}

# Median of the numbers on stdin (one per line). Empty input -> empty string.
median() {
  sort -n | awk '{ a[NR]=$1 } END {
    if (NR==0) { exit }
    if (NR%2==1) { printf "%d", a[(NR+1)/2] }
    else         { printf "%d", int((a[NR/2]+a[NR/2+1])/2) }
  }'
}

# p90 (nearest-rank) of the numbers on stdin. Empty input -> empty string.
p90() {
  sort -n | awk '{ a[NR]=$1 } END {
    if (NR==0) { exit }
    r=int(0.9*NR + 0.9999); if (r<1) r=1; if (r>NR) r=NR
    printf "%d", a[r]
  }'
}

# --- Collect stable releases (chronological) --------------------------------------------------
# Each row: <epoch>\t<iso-date>\t<tag>   sorted oldest -> newest by tag creation date.
mapfile -t STABLE_ROWS < <(
  git for-each-ref --sort=creatordate \
    --format='%(creatordate:unix)%09%(creatordate:short)%09%(refname:short)' \
    "refs/tags/${STABLE_GLOB}"
)

echo "=================================================================="
echo " DORA delivery metrics — jellyfin-plugin-sso"
echo " generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')  (read-only, deterministic)"
echo " gh enrichment: $([ "$GH_AVAILABLE" = 1 ] && echo 'available' || echo 'unavailable (git-only)')"
echo "=================================================================="

if (( ${#STABLE_ROWS[@]} == 0 )); then
  echo
  echo "No ${STABLE_GLOB} tags found — no production deployments to measure yet."
  exit 0
fi

# Parse the rows into parallel arrays.
declare -a TAG_EPOCH TAG_DATE TAG_NAME TAG_MAJOR TAG_MINOR TAG_PATCH
for row in "${STABLE_ROWS[@]}"; do
  IFS=$'\t' read -r ep dt nm <<<"$row"
  ver=${nm%-stable}                       # 4.2.1-stable -> 4.2.1
  IFS='.' read -r maj min pat <<<"$ver"
  TAG_EPOCH+=("$ep"); TAG_DATE+=("$dt"); TAG_NAME+=("$nm")
  TAG_MAJOR+=("${maj:-0}"); TAG_MINOR+=("${min:-0}"); TAG_PATCH+=("${pat:-0}")
done
N=${#TAG_NAME[@]}

# --- 1. Deployment frequency ------------------------------------------------------------------
first_ep=${TAG_EPOCH[0]}
last_ep=${TAG_EPOCH[$((N-1))]}
span_days=$(( (last_ep - first_ep) / 86400 ))
echo
echo "1) DEPLOYMENT FREQUENCY"
echo "   Definition: count of ${STABLE_GLOB} release tags (pre-prod beta/nightly excluded)."
echo "   Stable releases: $N"
printf '   Window: %s -> %s' "${TAG_DATE[0]}" "${TAG_DATE[$((N-1))]}"
if (( span_days > 0 )); then
  # Use awk for fractional rates.
  awk -v n="$N" -v days="$span_days" 'BEGIN {
    printf "  (%d days)\n", days
    printf "   Rate: %.2f releases/week, %.2f releases/month\n", (n-1)/days*7, (n-1)/days*30
  }'
else
  echo "  (all releases within a single day)"
  echo "   Rate: n/a — release history spans <1 day; frequency not yet meaningful."
fi
echo "   Releases:"
for ((i=0;i<N;i++)); do printf '     %s  %s\n' "${TAG_DATE[i]}" "${TAG_NAME[i]}"; done

# --- 2. Lead time for changes -----------------------------------------------------------------
# For every stable release that has a predecessor stable release, take each non-merge commit in
# (predecessor..release] and measure release_date - commit_author_date. Aggregate across all such
# intervals. The earliest stable tag has no predecessor and is skipped (documented limitation).
echo
echo "2) LEAD TIME FOR CHANGES"
echo "   Definition: per non-merge commit, time from author date to the ${STABLE_GLOB} tag that"
echo "   first shipped it. Aggregated over intervals that have a predecessor stable tag."
lead_tmp=$(mktemp)
intervals=0
for ((i=1;i<N;i++)); do
  prev=${TAG_NAME[$((i-1))]}; cur=${TAG_NAME[i]}; cur_ep=${TAG_EPOCH[i]}
  cnt=0
  while IFS= read -r cae; do
    [ -z "$cae" ] && continue
    echo $(( cur_ep - cae )) >>"$lead_tmp"
    cnt=$((cnt+1))
  done < <(git log --no-merges --format='%at' "${prev}..${cur}")
  intervals=$((intervals+1))
  printf '   %s -> %s: %d change-commits\n' "$prev" "$cur" "$cnt"
done
if (( intervals == 0 )); then
  echo "   Only one stable release exists — no predecessor interval; lead time not computable yet."
elif [ ! -s "$lead_tmp" ]; then
  echo "   No non-merge commits between stable tags."
else
  med=$(median <"$lead_tmp"); p90v=$(p90 <"$lead_tmp")
  mn=$(sort -n "$lead_tmp" | head -1); mx=$(sort -n "$lead_tmp" | tail -1)
  echo "   Median: $(human_duration "$med")   p90: $(human_duration "$p90v")   min: $(human_duration "$mn")   max: $(human_duration "$mx")"
fi
rm -f "$lead_tmp"

# --- 3. Change-failure rate -------------------------------------------------------------------
# A stable release R is counted as a failure if the next stable release on the same X.Y line is a
# patch (Z) bump — i.e. a remediation was needed. The newest release cannot yet be judged (nothing
# follows it) and is excluded from the denominator. Reverts and bug-labelled issues are reported as
# corroborating signal but do not change the primary count.
echo
echo "3) CHANGE-FAILURE RATE (CFR)"
echo "   Definition: fraction of judgeable stable releases followed by a same-line patch hotfix."
failures=0
declare -a FAIL_IDX HOTFIX_IDX
for ((i=0;i<N-1;i++)); do
  # Find the immediate next stable release (chronological successor is index i+1).
  j=$((i+1))
  if [ "${TAG_MAJOR[i]}" = "${TAG_MAJOR[j]}" ] && [ "${TAG_MINOR[i]}" = "${TAG_MINOR[j]}" ] \
     && (( 10#${TAG_PATCH[j]} > 10#${TAG_PATCH[i]} )); then
    failures=$((failures+1))
    FAIL_IDX+=("$i"); HOTFIX_IDX+=("$j")
    gap=$(( TAG_EPOCH[j] - TAG_EPOCH[i] ))
    fast=""
    (( gap <= HOTFIX_WINDOW_DAYS*86400 )) && fast=" (within ${HOTFIX_WINDOW_DAYS}d window: fast hotfix)"
    printf '   FAIL: %s -> hotfixed by %s after %s%s\n' \
      "${TAG_NAME[i]}" "${TAG_NAME[j]}" "$(human_duration "$gap")" "$fast"
  fi
done
judgeable=$((N-1))   # every release except the newest can, in principle, be judged
if (( judgeable > 0 )); then
  awk -v f="$failures" -v d="$judgeable" 'BEGIN { printf "   CFR: %d/%d = %.0f%%\n", f, d, f/d*100 }'
else
  echo "   CFR: n/a — only one stable release; no release can yet be judged."
fi

# Corroborating signal: explicit git reverts across the stable window.
revert_count=$(git log --no-merges --grep='^Revert' -i -E --format='%h' \
  "${TAG_NAME[0]}..${TAG_NAME[$((N-1))]}" 2>/dev/null | wc -l | tr -d ' ')
echo "   Signal: $revert_count explicit revert commit(s) between first and latest stable tag."

if (( GH_AVAILABLE == 1 )); then
  bug_closed=$(gh issue list --label bug --state closed --limit 200 \
    --json closedAt --jq "[.[] | select(.closedAt != null)] | length" 2>/dev/null || echo "?")
  echo "   Signal: $bug_closed closed \`bug\`-labelled issue(s) total (production-defect corpus)."
else
  echo "   Signal: bug-issue corpus skipped (gh unavailable)."
fi

# --- 4. Mean time to restore ------------------------------------------------------------------
# For each failure (release -> its hotfix), restore time = hotfix_date - failed_release_date. This
# measures release-to-release recovery; it is an UPPER bound on user-facing downtime since the
# defect is usually discovered after the release, not at it (documented limitation).
echo
echo "4) MEAN TIME TO RESTORE (MTTR)"
echo "   Definition: time from a failing stable release to the stable release that fixes it."
if (( ${#FAIL_IDX[@]} == 0 )); then
  echo "   No failure->hotfix pairs detected; MTTR not applicable."
else
  mttr_tmp=$(mktemp)
  for k in "${!FAIL_IDX[@]}"; do
    fi=${FAIL_IDX[k]}; hi=${HOTFIX_IDX[k]}
    echo $(( TAG_EPOCH[hi] - TAG_EPOCH[fi] )) >>"$mttr_tmp"
  done
  total=0; cnt=0
  while IFS= read -r v; do total=$((total+v)); cnt=$((cnt+1)); done <"$mttr_tmp"
  mean=$(( total / cnt ))
  med=$(median <"$mttr_tmp")
  echo "   Pairs: $cnt   Mean: $(human_duration "$mean")   Median: $(human_duration "$med")"
  rm -f "$mttr_tmp"
fi

# --- 5. Supplementary AI-risk indicators (cheap, git-derived) ---------------------------------
# The DORA 2025/26 guidance flags instability in agent-authored change as the leading risk; revert
# rate and a rework signal are the cheapest leading indicators derivable from git. Review-finding
# density needs /security-review output and is tracked manually (see DORA-METRICS.md).
echo
echo "5) AI-RISK / DELIVERY-STABILITY INDICATORS (supplementary)"
range="${TAG_NAME[0]}..${TAG_NAME[$((N-1))]}"
total_commits=$(git log --no-merges --format='%h' "$range" 2>/dev/null | wc -l | tr -d ' ')
if (( total_commits > 0 )); then
  awk -v r="$revert_count" -v t="$total_commits" 'BEGIN {
    printf "   Revert rate: %d/%d non-merge commits = %.1f%% (across the stable window)\n", r, t, r/t*100
  }'
else
  echo "   Revert rate: n/a — no commits in the stable window."
fi
# Rework signal: fixup/amend-style subjects landing on top of recent work.
rework=$(git log --no-merges -i -E --grep='^(fixup|amend|re-?fix|follow-?up)' --format='%h' "$range" 2>/dev/null | wc -l | tr -d ' ')
echo "   Rework signal: $rework fixup/follow-up commit subject(s) in the stable window (heuristic)."
echo "   Review-finding density: manually tracked per /security-review — see DORA-METRICS.md."

echo
echo "=================================================================="
echo " Small-dataset caveat: with $N stable release(s), rates are indicative,"
echo " not statistically stable. Interpret trend, not absolute value."
echo "=================================================================="

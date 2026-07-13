#!/usr/bin/env bash
#
# Jellyfin compatibility gate: verify the plugin metadata is internally consistent and correctly
# targets its Jellyfin ABI, so a packaged plugin actually loads on the intended server generation.
# Compile-time API compatibility is already enforced by building against the pinned Jellyfin.*
# packages with --warnaserror; this catches the metadata/ABI drift that a build cannot.
#
# Runtime SSO behavior against a live Jellyfin + identity provider is verified separately by a
# manual end-to-end check on a real server — it cannot be exercised headlessly.
set -euo pipefail

csproj="SSO-Auth/SSO-Auth.csproj"
buildyaml="build.yaml"
fail=0

need() { # value description
  local value="$1"
  local description="$2"
  if [[ -z "$value" ]]; then echo "::error::could not read $description" >&2; fail=1; fi
}
check() { # description actual expected
  local description="$1"
  local actual="$2"
  local expected="$3"
  if [[ "$actual" != "$expected" ]]; then echo "::error::$description mismatch: '$actual' vs '$expected'" >&2; fail=1; else echo "ok: $description = $actual"; fi
}

# `|| true` so a missing match yields an empty value handled by need()/fail below, rather than
# aborting the whole script via `set -e`/`pipefail` before a clear error can be printed.
tfm=$(grep -oP '(?<=<TargetFramework>)[^<]+' "$csproj" | head -1 || true); need "$tfm" "csproj TargetFramework"
asmver=$(grep -oP '(?<=<AssemblyVersion>)[^<]+' "$csproj" | head -1 || true); need "$asmver" "csproj AssemblyVersion"
filever=$(grep -oP '(?<=<FileVersion>)[^<]+' "$csproj" | head -1 || true); need "$filever" "csproj FileVersion"
controller=$(grep -oP 'Jellyfin\.Controller"\s+Version="\K[^"]+' "$csproj" | head -1 || true); need "$controller" "Jellyfin.Controller version"
model=$(grep -oP 'Jellyfin\.Model"\s+Version="\K[^"]+' "$csproj" | head -1 || true); need "$model" "Jellyfin.Model version"

# The Jellyfin packages take their version from the $(JellyfinVersion) property (#142, so the
# abi-floor CI job can override it); resolve it to the property's default so the metadata checks below
# compare real version numbers rather than the literal '$(JellyfinVersion)'.
jellyfinversion=$(grep -oP '<JellyfinVersion[^>]*>\K[^<]+' "$csproj" | head -1 || true); need "$jellyfinversion" "csproj JellyfinVersion default"
[[ "$controller" == '$(JellyfinVersion)' ]] && controller="$jellyfinversion"
[[ "$model" == '$(JellyfinVersion)' ]] && model="$jellyfinversion"

byframework=$(grep -oP 'framework:\s*"?\K[^"[:space:]]+' "$buildyaml" | head -1 || true); need "$byframework" "build.yaml framework"
byversion=$(grep -oP '^version:\s*"?\K[^"[:space:]]+' "$buildyaml" | head -1 || true); need "$byversion" "build.yaml version"
abi=$(grep -oP 'targetAbi:\s*"?\K[^"[:space:]]+' "$buildyaml" | head -1 || true); need "$abi" "build.yaml targetAbi"

[[ "$fail" -eq 0 ]] || { echo "aborting: could not read all metadata"; exit 1; }

check "target framework (csproj vs build.yaml)" "$tfm" "$byframework"
check "plugin version (build.yaml vs AssemblyVersion)" "$byversion" "$asmver"
check "FileVersion vs AssemblyVersion" "$filever" "$asmver"
check "Jellyfin Controller vs Model package version" "$controller" "$model"
# targetAbi is the minimum supported server ABI; its major.minor must match the SDK we build against.
check "targetAbi major.minor vs Jellyfin.Controller" "$(echo "$abi" | cut -d. -f1-2)" "$(echo "$controller" | cut -d. -f1-2)"

if [[ "$fail" -ne 0 ]]; then
  echo "Jellyfin compatibility metadata is inconsistent."
  exit 1
fi
echo "Jellyfin compatibility metadata is consistent."

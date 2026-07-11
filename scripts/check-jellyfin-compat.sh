#!/usr/bin/env bash
#
# Jellyfin compatibility gate: verify the plugin metadata is internally consistent and correctly
# targets its Jellyfin ABI, so a packaged plugin actually loads on the intended server generation.
# Compile-time API compatibility is already enforced by building against the pinned Jellyfin.*
# packages with --warnaserror; this catches the metadata/ABI drift that a build cannot.
#
# Runtime SSO behavior against a live Jellyfin + identity provider is verified separately by the
# manual end-to-end checklist (docs/E2E-CHECKLIST.md) — it cannot be exercised headlessly.
set -euo pipefail

csproj="SSO-Auth/SSO-Auth.csproj"
buildyaml="build.yaml"
fail=0

need() { # value description
  if [ -z "$1" ]; then echo "::error::could not read $2"; fail=1; fi
}
check() { # description actual expected
  if [ "$2" != "$3" ]; then echo "::error::$1 mismatch: '$2' vs '$3'"; fail=1; else echo "ok: $1 = $2"; fi
}

tfm=$(grep -oP '(?<=<TargetFramework>)[^<]+' "$csproj" | head -1); need "$tfm" "csproj TargetFramework"
asmver=$(grep -oP '(?<=<AssemblyVersion>)[^<]+' "$csproj" | head -1); need "$asmver" "csproj AssemblyVersion"
filever=$(grep -oP '(?<=<FileVersion>)[^<]+' "$csproj" | head -1); need "$filever" "csproj FileVersion"
controller=$(grep -oP 'Jellyfin\.Controller"\s+Version="\K[^"]+' "$csproj" | head -1); need "$controller" "Jellyfin.Controller version"
model=$(grep -oP 'Jellyfin\.Model"\s+Version="\K[^"]+' "$csproj" | head -1); need "$model" "Jellyfin.Model version"

byframework=$(grep -oP 'framework:\s*"?\K[^"[:space:]]+' "$buildyaml" | head -1); need "$byframework" "build.yaml framework"
byversion=$(grep -oP '^version:\s*"?\K[^"[:space:]]+' "$buildyaml" | head -1); need "$byversion" "build.yaml version"
abi=$(grep -oP 'targetAbi:\s*"?\K[^"[:space:]]+' "$buildyaml" | head -1); need "$abi" "build.yaml targetAbi"

[ "$fail" -eq 0 ] || { echo "aborting: could not read all metadata"; exit 1; }

check "target framework (csproj vs build.yaml)" "$tfm" "$byframework"
check "plugin version (build.yaml vs AssemblyVersion)" "$byversion" "$asmver"
check "FileVersion vs AssemblyVersion" "$filever" "$asmver"
check "Jellyfin Controller vs Model package version" "$controller" "$model"
# targetAbi is the minimum supported server ABI; its major.minor must match the SDK we build against.
check "targetAbi major.minor vs Jellyfin.Controller" "$(echo "$abi" | cut -d. -f1-2)" "$(echo "$controller" | cut -d. -f1-2)"

if [ "$fail" -ne 0 ]; then
  echo "Jellyfin compatibility metadata is inconsistent."
  exit 1
fi
echo "Jellyfin compatibility metadata is consistent."

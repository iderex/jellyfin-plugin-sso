#!/usr/bin/env python3
"""Coverage gate for the RC coverage goal (#718).

Parses the Cobertura report `dotnet test --coverage` emits and enforces the
security-surface LINE-coverage bar: the modules that take security decisions
(SAML validation, OIDC state/issuer/PKCE, account linking, authz, rate limit,
avatar SSRF, network trust, logout, secrets, session mint, audit) must stay at
or above the pinned threshold, or the job fails. The whole-codebase number is
reported (the >=80% line RC baseline is tracked in docs/METRICS.md) but
deliberately not enforced, so the gate cannot be tripped by a trivially-thin
non-critical path; only the security surface hard-gates.

Counting is per executable line (lines-covered / lines-valid), never a
per-class average, so a large uncovered class cannot hide behind many small
covered ones. Only each class's class-level <lines> block is counted - the
per-method <line> entries duplicate the same lines and would double-count.
Fail-closed: a missing report, an unparsable report, or zero matched
security-surface lines is an error, not a pass.

Usage: check-coverage.py <coverage.cobertura.xml>
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath, PureWindowsPath

# The security-decision surface: every Api module whose classes decide an
# authentication, authorization, linking, session, network-trust, or
# abuse-control outcome. `Shared` carries the rate-limit gate and the
# served-flow responses; `Flows` is the per-protocol login orchestration; `Net`
# holds the SSRF/public-address verdicts; `Logout` the session-termination
# store; `Provider` the provider-identity validation. The deliberately ungated
# remainder is `Http` (the controller boundary, gated by its endpoint tests and
# the conformance rules), `Routing`/`LoginButtons` (page furniture), and the
# non-guard Config persistence types. Config's security-guard types are matched
# by file name below.
SECURITY_MODULES = {
    "Audit",
    "Authz",
    "Avatar",
    "Crypto",
    "Flows",
    "Identity",
    "Linking",
    "Logout",
    "Net",
    "Oidc",
    "Provider",
    "RateLimit",
    "Saml",
    "Secrets",
    "Session",
    "Shared",
}
SECURITY_CONFIG_FILES = {
    "SsoOnlyLoginGuard.cs",
    "ServerManagedFields.cs",
    "WriteOnlySecretConverter.cs",
    "ConfigImport.cs",
    "ProviderConfigValidator.cs",
    "ProviderConfigStore.cs",
}

# The pinned bar. Set just below the first honest measurement (93.4% on
# 2026-07-21, line-level over 5124 security-surface lines) so real regressions
# fail while instrumentation jitter does not; ratchet it up as the number
# climbs, never down without a documented decision.
SECURITY_LINE_BAR = 92.0


def module_of(filename: str) -> str | None:
    """Returns the Api module name of a source path, or None.

    A file directly under Api/ (no module folder) yields None; that layout is
    structurally impossible - the FlatApi_HoldsNoSourceFiles conformance test
    keeps the flat Api root empty - so nothing can hide there from this gate.
    """
    parts = PureWindowsPath(filename.replace("/", "\\")).parts
    if "Api" in parts:
        idx = parts.index("Api")
        if idx + 1 < len(parts) - 1:
            return parts[idx + 1]
    if "Config" in parts and parts[-1] in SECURITY_CONFIG_FILES:
        return "Config-guard"
    return None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check-coverage.py <coverage.cobertura.xml>", file=sys.stderr)
        return 2
    try:
        root = ET.parse(sys.argv[1]).getroot()
    except (OSError, ET.ParseError) as err:
        print(f"::error::Could not read the coverage report: {err}", file=sys.stderr)
        return 1

    total_valid = total_covered = 0
    sec_valid = sec_covered = 0
    for cls in root.iter("class"):
        filename = cls.get("filename", "")
        module = module_of(filename)
        is_security = module in SECURITY_MODULES or module == "Config-guard"
        # The class-level <lines> child only: cls.iter("line") would also walk
        # the per-method <line> copies and double-count every line.
        lines_block = cls.find("lines")
        if lines_block is None:
            continue
        for line in lines_block.iter("line"):
            hits = int(line.get("hits", "0"))
            total_valid += 1
            total_covered += 1 if hits > 0 else 0
            if is_security:
                sec_valid += 1
                sec_covered += 1 if hits > 0 else 0

    if total_valid == 0 or sec_valid == 0:
        print("::error::The coverage report contains no matched lines - refusing to pass an empty measurement.", file=sys.stderr)
        return 1

    overall = 100.0 * total_covered / total_valid
    security = 100.0 * sec_covered / sec_valid
    print(f"Overall line coverage:          {overall:.1f}% ({total_covered}/{total_valid} lines)")
    print(f"Security-surface line coverage: {security:.1f}% ({sec_covered}/{sec_valid} lines)")
    print(f"Security-surface bar (pinned):  {SECURITY_LINE_BAR:.1f}%")

    if security < SECURITY_LINE_BAR:
        print(
            f"::error::Security-surface line coverage {security:.1f}% fell below the pinned "
            f"{SECURITY_LINE_BAR:.1f}% bar (#718). Cover the security-decision paths you touched, "
            "or raise coverage elsewhere on the surface - the bar does not move down.",
            file=sys.stderr,
        )
        return 1
    print("Coverage gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

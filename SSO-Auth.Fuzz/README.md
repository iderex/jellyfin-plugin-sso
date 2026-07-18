# Fuzzing the untrusted-input parse surface (#402)

This project is the coverage-guided fuzz harness prototype for the plugin's login-path parsers, and the
written evaluation behind [Scorecard alert #36 (Fuzzing)](https://github.com/iderex/jellyfin-plugin-sso/issues/402).
It is the concrete harness the weekly scheduled job (#174) runs.

It is **out of band**: not part of `SSO-Auth.sln`, so a normal `dotnet build` / `dotnet test` and every
per-PR CI job never restore SharpFuzz or build it. It is compiled and driven only by the scheduled Linux
fuzzing job, exactly as the acceptance criteria require ("scheduled, non-blocking").

## The attack surface we target

The login endpoints are anonymous and hand attacker-controlled bytes straight into parsers before any
signature or claim is trusted. Those byte-level entry points are the classic fuzzing sweet spot, and they
are what the harness drives (selected per run by the `SSO_FUZZ_TARGET` environment variable):

| Target (`SSO_FUZZ_TARGET`) | Entry point                                                                             | Untrusted input                                                                                      |
| -------------------------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `saml` (default)           | `SamlResponseLoader.TryParse` → `SamlResponse` ctor + `IsValid` + every claim getter    | The Base64 `SAMLResponse` form field (Base64 decode → hardened XML DOM load → signature/claim reads) |
| `discovery`                | `PkceDiscovery.SupportsS256` and `OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer` | The raw OpenID discovery JSON fetched at challenge                                                   |
| `idtoken`                  | `OidcResponseIssuer.IdTokenIssuer` (`new JsonWebToken(token)`)                          | The raw id_token JWT string                                                                          |

The property under test is uniform: on **any** input the entry point must terminate with a fail-closed
result (`false` / `null` / a rejection) **or** one of the exceptions it explicitly maps — it must never
leak an unmapped exception (which on the real callback becomes an unauthenticated HTTP 500 / DoS) and
must never hang. A crash libFuzzer records is therefore a genuine finding: an exception type the
fail-closed filters do not catch, or a hang.

### What is deliberately out of scope

- **Signature forgery / "unexpected accept".** Coverage-guided fuzzing over random bytes cannot forge an
  XML-DSig or JWT signature that verifies against the pinned key, so it cannot reach an auth _bypass_; it
  finds _crashers_, not accepts. The accept-side invariants (a response is valid only with a correctly
  scoped, correctly signed assertion) are pinned by the `SamlResponse` / `OidcIdTokenValidator` unit
  tests and the FsCheck property suite instead.
- **The full `OidcIdTokenValidator.ValidateAsync`.** Its signature/issuer/audience/lifetime checks need a
  populated `OidcClientOptions` (discovery JWKS, client id, clock skew) and an `async` boundary, which do
  not fit libFuzzer's synchronous single-`ReadOnlySpan<byte>` contract cleanly. The **parse** half of the
  id_token surface (`IdTokenIssuer`) is fuzzed here; the **validation** half stays covered by
  `OidcIdTokenValidatorTests`. Wiring a `ValidateAsync` target with a fixed key set is the natural first
  expansion for #174.

## Why SharpFuzz, not ClusterFuzzLite (or OSS-Fuzz)

The acceptance criteria ask us to pick between ClusterFuzzLite and SharpFuzz, or document why neither
fits. They are not really alternatives — one is the .NET fuzzing _engine_, the other a CI _runner_:

- **OSS-Fuzz** has **no .NET support**, so the Scorecard-preferred managed-fuzzing path is unavailable to
  us. (This is also why #174 is framed as a _self-hosted_ weekly job.)
- **SharpFuzz** is the only mature coverage-guided fuzzer for .NET. It instruments the target IL and
  drives it under libFuzzer. **This is the engine we adopt**, and this project is built on it.
- **ClusterFuzzLite** is a CI _harness_ around libFuzzer that Scorecard recognises. It _can_ drive a
  SharpFuzz target, but only through a `.clusterfuzzlite/` Dockerfile + `build.sh` that reimplements the
  instrumentation build, plus its own workflow — a non-trivial, CI/supply-chain-touching addition that
  belongs in its own gated change, not this evaluation prototype.

**Decision:** adopt **SharpFuzz** as the engine now (this harness + seed corpus + the per-entry-point
targets). Run it from a **plain scheduled GitHub Actions Linux job** (#174) to start; treat wrapping it in
ClusterFuzzLite purely for the Scorecard badge as an optional, separately-gated follow-up. The security
value is the fuzzing itself, which the scheduled job delivers regardless of whether Scorecard credits it.

## Feasibility: local Windows vs CI Linux (honest)

- The **managed harness compiles cross-platform** — it builds cleanly on the maintainer's Windows box
  (validated in Debug and Release under `--warnaserror`), so it cannot silently bitrot when touched.
- **Actual fuzzing is Linux-only.** The `sharpfuzz` instrumentation CLI and the libFuzzer runtime are
  Linux-oriented; a coverage-guided run on Windows is impractical. So the _run_ lives in CI, never on the
  maintainer's machine. This is expected and is why #174 is a scheduled Linux job.
- Because the project is not in the solution, the per-PR CI never builds it. The weekly job is what keeps
  it compiling and running; that is an accepted trade-off for a non-shipping prototype.

## Value assessment vs. the existing gate

The FsCheck property suite (`PropertyTests.cs`, #126) covers the **pure login-decision helpers**
(role→privilege mapping monotonicity, the OIDC "valid ⇒ username" invariant) — it does **not** touch the
**byte-level parse path**. The `SamlResponseParsingTests` already pin the known malformed-input classes
(non-Base64, malformed XML, prohibited DOCTYPE, null/empty, oversized, garbage certificate, malformed
signature element) as fail-closed. Fuzzing is **complementary**: it searches the same parse path for an
_un-enumerated_ crasher — an exception type or a hang the hand-written cases and the explicit
`catch` filters did not anticipate — which is precisely the residual risk unit and property tests cannot
exhaust. The marginal value is modest (the raw parsing is delegated to already-hardened platform/library
parsers — `System.Xml` with DTD prohibited, `Newtonsoft.Json`, `Microsoft.IdentityModel`), but real and
low-maintenance, and it is the surface #174 already committed to.

## Running it (Linux)

```sh
# 1. Build the harness (Release).
dotnet build SSO-Auth.Fuzz/SSO-Auth.Fuzz.csproj -c Release

# 2. Instrument the plugin assembly SharpFuzz will fuzz through.
dotnet tool install --global SharpFuzz.CommandLine
sharpfuzz SSO-Auth.Fuzz/bin/Release/net9.0/SSO-Auth.dll

# 3. Fuzz one target, seeded from its corpus (libFuzzer flags after --).
export SSO_FUZZ_TARGET=saml   # or: discovery | idtoken
dotnet SSO-Auth.Fuzz/bin/Release/net9.0/SSO-Auth.Fuzz.dll \
    SSO-Auth.Fuzz/corpus/$SSO_FUZZ_TARGET -max_total_time=300
```

A non-zero exit with a written `crash-*` input is a finding. **Do not fix it in the harness.** Minimise
the reproducer, file it as its own security issue (GHSA path if it turns out to be exploitable rather than
a plain 500/DoS), and fix the parser in a separate change — the harness only surfaces findings.

### Smoke mode (any platform, no libFuzzer)

Because libFuzzer is Linux-only, set `SSO_FUZZ_SMOKE=1` to replay a corpus directory through the selected
target **once** and exit — no instrumentation, no native runtime. It proves the dispatch + parse wiring
runs and that every seed is handled fail-closed, so the harness can be validated on Windows and as a cheap
CI sanity check. This is how the prototype was validated at delivery (all three targets, exit 0):

```sh
export SSO_FUZZ_SMOKE=1 SSO_FUZZ_TARGET=saml   # or: discovery | idtoken
dotnet SSO-Auth.Fuzz/bin/Release/net9.0/SSO-Auth.Fuzz.dll SSO-Auth.Fuzz/corpus/$SSO_FUZZ_TARGET
```

## The seed corpus

`corpus/<target>/` holds representative seeds so the fuzzer starts from meaningful coverage rather than
random noise: a well-formed and several malformed shapes per target (a minimal signed-shaped SAML
response, a DOCTYPE body, non-Base64; a full and a minimal discovery document plus a type-confused one; a
`none`-alg JWT and a non-JWT). libFuzzer expands the corpus from these as it explores.

## Scorecard alert #36 and #174

This prototype does not itself flip the Scorecard Fuzzing check — that check only credits a wired-in
ClusterFuzzLite/OSS-Fuzz integration, which we deliberately deferred above. So alert #36 is **re-dismissed
with this documented outcome**: SharpFuzz adopted as the engine, this harness + corpus landed, and the
recurring run tracked by #174 (weekly scheduled Linux job). Adopting ClusterFuzzLite later, if we want the
badge, is the remaining optional step.

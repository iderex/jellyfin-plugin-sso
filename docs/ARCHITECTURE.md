# Architecture

How the plugin is structured, why, and the contract every change follows. This
document is normative: the folder layout, the module dependency graph, and the
extension rules below are enforced by conformance tests (fitness functions) in
`SSO-Auth.Tests/ArchitectureConformanceTests.cs`, not by convention alone.

## Layering

The plugin is one assembly under the root namespace `Jellyfin.Plugin.SSO_Auth`
(the underscore is load-bearing — it is part of the published plugin identity and
must not be renamed). Inside it:

- **`Config/`** — the persisted configuration model (`PluginConfiguration`,
  `OidConfig`/`SamlConfig` which share `ProviderConfigBase`) and its store.
- **`Api/`** — the behaviour, split into **module folders**, each a namespace
  `Jellyfin.Plugin.SSO_Auth.Api.<Module>`. A module is the unit of the dependency
  graph below.
- The web binding (the `SSOController`) and the composition root live in the Api
  layer's kernel (see _Shared kernel_).

The design favours the codebase's existing grain: **sealed types, immutable
record/variant state, typed values over raw strings, sum types that make illegal
states unrepresentable, fail-closed defaults, no ambient time** (time comes
through an injected clock), and **mutable keyed state only inside store-like
types**. These are pinned by conformance tests and must not regress.

## The Api module map and dependency DAG

Modules form a **directed acyclic graph**: a module may import only the modules
listed as its allowed dependencies, and a cycle is rejected. This is enforced by
`ApiModule_ImportsOnlyItsAllowedApiModules` — each module is one `InlineData`
case declaring its allowed edges; an import to any other Api module fails the
test. Importing the flat `Api` core (the shared kernel) and non-`Api` namespaces
(e.g. `Config`) is permitted.

| Module      | Purpose                                            | May depend on                                     |
| ----------- | -------------------------------------------------- | ------------------------------------------------- |
| `Net`       | Networking / SSRF / URL primitives                 | — (leaf)                                          |
| `Secrets`   | Secrets at rest (envelope, store, config wrapping) | — (leaf)                                          |
| `Audit`     | Append-only SSO audit logging                      | — (leaf)                                          |
| `Authz`     | Role → permission mapping                          | — (leaf)                                          |
| `Avatar`    | Avatar fetch + SSRF-gated validation               | `Net`                                             |
| `RateLimit` | Login throttling (buckets, gates, keys)            | `Net`                                             |
| `Provider`  | Provider config / naming / test-result             | `Net`, `RateLimit`                                |
| `Linking`   | Account link resolution / adoption / revocation    | `Audit`, `Provider`, `RateLimit`                  |
| `Saml`      | SAML core, validators, caches, metadata            | `Authz`, `RateLimit`                              |
| `Oidc`      | OIDC flow, discovery, id_token, state              | `Authz`, `Avatar`, `Net`, `Provider`, `RateLimit` |
| `Flows`     | Per-protocol login orchestration services          | (orchestration — depends downward)                |
| `Shared`    | Shared served-page / flow-response helpers         | (shared — depends downward)                       |

`Saml` and `Oidc` are **sibling protocol modules**: neither imports the other.
Dependencies point _into_ the low-level leaves (`Net`, `Secrets`, `Audit`,
`Authz`), never out of them.

## The shared kernel (flat `Api`)

Not everything is a module yet. The types still in the flat `Api` namespace are a
deliberate **shared kernel + composition root**, kept flat _on purpose_ because
they are genuinely entangled with more than one module and cannot be moved into a
single module without creating a dependency cycle:

- **`VerifiedIdentity`** — the protocol-validated identity. It is _constructed by_
  the `Oidc` and `Saml` validators and _references_ their types, so it sits in a
  bidirectional relationship with both protocol modules.
- **`SessionMinter`** ⇄ **`Avatar`**, **`SsoUrlBuilder`** ⇄ **`Oidc`** — the same
  shape of mutual coupling.
- The session/login-result types (`SessionParameters`, `LoginOutcome`,
  `AuthResponse`, `SsoOnlyLoginService`, `SsoOnlyReconciliationService`,
  `SsoAuthenticationProviders`, `LoginStatusMapper`), the web/delivery layer
  (`SSOController`, `RequestHelpers`, `RouteSuffix`, `ChallengePath`,
  `PublicReason`, `AuthPageCsp`, `ProviderConnectionTester`), and the generic
  `KeyedLockStore`.

Cleanly modularising these requires **dependency inversion** — extracting shared
contracts (e.g. a common `ILoginService`, a protocol-agnostic identity assembly)
so the arrows point one way — which is a design change, not a mechanical move.
That work is tracked in **#790**. Until it lands, the flat `Api` kernel is the
intentional home for these types. The goal of an **empty flat `Api`** (every file
in a module) becomes enforceable — as a conformance test — only _after_ #790
inverts those dependencies.

## How it is enforced (fitness functions)

`ArchitectureConformanceTests` runs in `dotnet test` and encodes the structure as
executable rules, including:

- `ApiModule_ImportsOnlyItsAllowedApiModules` — the module dependency DAG above.
- `EverythingLivesUnderThePluginRootNamespace` — no type escapes the root.
- Immutability / construction rules: `AuthorizeStates_AreImmutableVariants`,
  `SamlLoginOutcome_IsImmutable`, `VerifiedIdentity_IsConstructedOnlyByProtocolValidators`.
- Boundary rules: `Controller_DelegatesOidcFlowToTheFlowService` (and the SAML /
  login-completion equivalents), `Controller_HoldsNoMutableStaticState`,
  `Controller_NeverTouchesRawSocketsOrDns`, `Controller_NeverTouchesProviderLinkMaps`.
- Discipline rules: `MutableKeyedState_LivesOnlyInsideStoreLikeTypes`,
  `OidcAuthorizeState_IsKeyedOnUtc_NotMachineLocalTime`, the `IntervalGate`
  throttle-cursor rules, `ProviderFormFieldIds_MatchOidConfigProperties`.

**Every new structural property is locked in as a new rule here** — that is the
mechanism by which the architecture stays perfect over time rather than drifting.

## The extension contract

Every change — new feature, file, or type — respects all three of the following,
at **plan, implement, and review**, to the professionally soundest best practice,
none merely "good enough":

1. **Software architecture** — follows the idioms above (sealed/immutable/typed/
   sum-types, fail-closed, thin controller, no ambient time, keyed state only in
   stores). New behaviour does not bolt on against the grain.
2. **Folder structure** — new code lands in the **right module folder +
   namespace**; nothing is dumped back into the flat kernel. A genuinely new
   concern gets a **new module** (folder + namespace + a DAG `InlineData` case),
   not a smear across the tree.
3. **Object-oriented structure** — shared behaviour lives behind a **shared
   abstraction** with protocols/variants as specializations, realised
   **composition- and interface-first, with shallow inheritance only where it is
   genuinely `is-a`** (not a deep inheritance tower). `ProviderConfigBase`
   (shared by `OidConfig`/`SamlConfig`) is the model to follow; the broader
   OIDC/SAML shared-contract work is #790. A third IdP type must slot into the
   shared abstraction, not fork a third parallel path.

**This applies to the whole repository, not only `Api/`.** In particular the
**test project mirrors the source module structure** — a module's tests live in
the matching folder (`SSO-Auth.Tests/<Module>/`), so a test is as easy to place
and find as the code it covers — and the same tidiness and best-practice bar
holds for every other part of the tree (build/packaging, docs, tooling). Nothing
is left as an untidy flat pile. Bringing the test project and the rest of the
repo up to this bar is tracked in #791.

**Enforce, don't trust the eye:** when a change establishes a new structural
property, add a conformance fitness function for it in the same PR. The review
phase checks architecture + folder placement + OO fit explicitly, alongside
correctness and security.

_See #777 (the module migration this describes), #790 (the shared protocol
abstraction / kernel decomposition), and #791 (applying this structure to the
test project and the whole repo)._

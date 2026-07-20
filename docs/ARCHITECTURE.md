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
- The web binding (the `SSOController`) and the composition root live in the
  `Api/Http` module (see _The kernel is dissolved_).

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
test. Importing non-`Api` namespaces (e.g. `Config`) is permitted; there is no
longer a flat `Api` core to import (see _The kernel is dissolved_ below).

| Module         | Purpose                                                                             | May depend on                                                                                       |
| -------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `Net`          | Networking / SSRF / URL primitives                                                  | — (leaf)                                                                                            |
| `Secrets`      | Secrets at rest (envelope, store, config wrapping)                                  | — (leaf)                                                                                            |
| `Audit`        | Append-only SSO audit logging                                                       | — (leaf)                                                                                            |
| `Authz`        | Role → permission mapping                                                           | — (leaf)                                                                                            |
| `Routing`      | Route-shape contract (suffix reader, path classifier)                               | — (leaf)                                                                                            |
| `Crypto`       | Shared asymmetric signing-key strength policy (min RSA bits / approved EC curves)   | — (leaf)                                                                                            |
| `LoginButtons` | Login-page button rendering + branding-sync hosted service (#722)                   | — (leaf)                                                                                            |
| `Logout`       | Single Logout session-state store (#727)                                            | — (leaf)                                                                                            |
| `Avatar`       | Avatar fetch + SSRF-gated validation                                                | `Net`, `RateLimit`                                                                                  |
| `RateLimit`    | Login throttling (buckets, gates, keys)                                             | `Net`                                                                                               |
| `Provider`     | Provider config / naming / test-result                                              | `Net`, `RateLimit`                                                                                  |
| `Linking`      | Account link resolution / adoption / revocation                                     | `Audit`, `Provider`, `RateLimit`                                                                    |
| `Identity`     | The protocol-validated identity keystone                                            | `Authz`, `Provider`                                                                                 |
| `Session`      | Session mint + login outcomes + SSO-only                                            | `Authz`, `Avatar`, `Linking`                                                                        |
| `Saml`         | SAML core, validators, caches, metadata                                             | `Authz`, `Identity`, `RateLimit`, `Session`                                                         |
| `Oidc`         | OIDC flow, discovery, id_token, state                                               | `Authz`, `Avatar`, `Identity`, `Net`, `Provider`, `RateLimit`, `Routing`                            |
| `Flows`        | Per-protocol login orchestration services                                           | `Audit`, `Identity`, `Linking`, `Net`, `Oidc`, `Provider`, `RateLimit`, `Saml`, `Session`, `Shared` |
| `Shared`       | Shared served-page / flow-response helpers                                          | `Avatar`, `Linking`, `RateLimit`, `Routing`, `Session`                                              |
| `Http`         | The web boundary: `SSOController`, request helpers, the admin test-connection probe | the composition top — fronts every flow (wide by design); nothing imports it back                   |

`Saml` and `Oidc` are **sibling protocol modules**: neither imports the other.
Dependencies point _into_ the low-level leaves (`Net`, `Secrets`, `Audit`,
`Authz`, `Routing`), never out of them. `Http` is the single composition boundary
at the top of the DAG.

## The kernel is dissolved (flat `Api` is empty)

There is **no flat `Api` kernel**. Every type lives in a named module subfolder,
and a conformance test — `FlatApi_HoldsNoSourceFiles_EveryApiTypeLivesInAModule`
— fails if any `.cs` file appears directly in `SSO-Auth/Api/`.

Getting here (the #777 module split and its #807 finale) required real
**dependency inversion**, not a mechanical move: the former kernel's
entanglements were broken by extracting shared contracts so the arrows point one
way. In particular the protocol-validated
identity became the neutral `Identity` keystone (constructed by the `Oidc`/`Saml`
validators through a factory, not referencing their types); the session/login
result types became the `Session` module; the served-page and rate-limit-gate
helpers became `Shared`; the route-shape primitives became the `Routing` leaf; the
per-protocol login services became `Flows`; and the web boundary — the controller,
its request helpers, and the admin test-connection probe — became the `Http`
module. The SSO-managed `AuthenticationProviderId` the controller once owned is now
a pinned literal (`SsoManagedProviderId`, #837), decoupled from the controller's
type location so `Http` could move without touching persisted accounts.

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
   namespace**; the flat `Api` root stays empty (a conformance test enforces it).
   A genuinely new concern gets a **new module** (folder + namespace + a DAG
   `InlineData` case), not a smear across the tree.
3. **Object-oriented structure** — shared behaviour lives in a **single concrete
   home reached by composition**, not duplicated across protocols. An **interface
   or abstract contract earns its place only when ≥2 real consumers dispatch
   through it polymorphically**; until then a concrete type is clearer and an
   interface is speculative (composition- and interface-first, shallow
   inheritance only where it is genuinely `is-a`, never a deep inheritance
   tower). `ProviderConfigBase` (the genuine `is-a` shared by
   `OidConfig`/`SamlConfig`) and the `ValidatedLogin` → `VerifiedIdentity`
   keystone both protocol validators feed are the models; a third IdP type slots
   into those shared homes, not a third parallel path. The full object-oriented
   rule is the canonical
   [Coding Standards](https://github.com/iderex/jellyfin-plugin-sso/wiki/Coding-Standards);
   the OIDC/SAML seam evaluation that settled it is #790.

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

_See #777 (the module migration this describes) and its #807 finale (the flat
`Api` kernel dissolved and locked empty), #790 (the ongoing OIDC/SAML shared-
protocol-abstraction evaluation), and #791 (applying this structure to the test
project and the whole repo)._

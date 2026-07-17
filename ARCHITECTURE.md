# Architecture: the login flow, end to end

A map for a new contributor working from a fork, a source tarball, or offline —
so a first change can be placed onto the flow instead of reverse-engineered
from `SSO-Auth/Api/SSOController.cs` (currently ~1,525 lines) and its ~45
helper types. It complements, and does not replace, the wiki
[Login Flow](https://github.com/iderex/jellyfin-plugin-sso/wiki/Login-Flow)
page.

This page keeps two things apart on purpose:

- **Current state** — what is in the tree today, verified against the code at
  the time of writing. Every type and method named below exists.
- **Target direction ([#318](https://github.com/iderex/jellyfin-plugin-sso/issues/318))**
  — the unified OO architecture the codebase is migrating toward, one small
  behaviour-preserving PR at a time. It is marked as such everywhere it
  appears; nothing here describes the target as if it already existed.

## 1. The login flow today

Both protocols follow the same shape — challenge (redirect to the identity
provider), callback (render an intermediate auth page), auth (mint the
session) — with the SAML validation done inline rather than through a
separate client library.

### OpenID Connect

```
OidChallenge  (GET  OID/p/{provider}, OID/start/{provider})
  -> PrepareLoginAsync (Duende OidcClient)      -- discovery + PKCE (S256) check
  -> OidcStateStore.TryAdd                      -- registers the in-flight authorize state
  -> AuthorizeStateBinding                      -- binds the state to the initiating browser (cookie)
  -> redirect to the provider

OidPost       (GET  OID/r/{provider}, OID/redirect/{provider})   -- the provider's callback
  -> OidcStateStore.PeekCurrent                 -- looks up the pending state (does not consume it)
  -> OidcClient.ProcessResponseAsync            -- token exchange + id_token signature validation
  -> OidcResponseIssuer.IsRejected              -- RFC 9207 issuer mix-up check
  -> OidcAuthorizeStateBuilder.Build             -- derives username/roles/admin/folders from claims
  -> renders the intermediate auth page (WebResponse.Generator)

OidAuth       (POST OID/Auth/{provider})         -- the auth page posts back here to mint the session
  -> OidcStateStore.TryRedeem                    -- one-time atomic claim of the authorize state
  -> CanonicalLinkService.ResolveOrCreateAsync    -- resolve/adopt/create the Jellyfin account link
  -> SessionMinter.MintAsync                      -- permissions + avatar + AuthenticateDirect
  -> LoginOutcome -> LoginStatusMapper.ToActionResult
```

### SAML 2.0

```
SamlChallenge (GET  SAML/p/{provider}, SAML/start/{provider})
  -> SamlAuthnRequest                            -- hand-rolled AuthnRequest (Saml.cs)
  -> SamlRequestCache.Register                    -- outstanding-request correlation (InResponseTo)
  -> AuthorizeStateBinding                        -- binds the request to the initiating browser (cookie)
  -> redirect to the IdP

SamlPost      (POST SAML/p/{provider}, SAML/post/{provider})    -- the IdP's ACS callback
  -> SamlResponseLoader.TryParse                  -- parses + validates the signed response (Saml.cs core)
  -> SamlLoginPolicy.IsLoginAllowed                -- role allow-list check
  -> renders the intermediate auth page (WebResponse.Generator)

SamlAuth      (POST SAML/Auth/{provider})          -- the auth page posts back here to mint the session
  -> SamlResponseLoader.TryParse + validation (again -- a caller can skip the page and POST directly)
  -> SamlRequestCache.TryConsume                   -- InResponseTo correlation + browser-binding check
  -> SamlReplayCache                               -- one-time-use assertion ID (replay protection)
  -> SamlAuthorizeStateBuilder.Build                -- derives admin/roles/folders from assertion attributes
  -> CanonicalLinkService.ResolveOrCreateAsync
  -> SessionMinter.MintAsync
  -> LoginOutcome -> LoginStatusMapper.ToActionResult
```

Both auth endpoints call the identical two-step tail —
`CanonicalLinkService.ResolveOrCreateAsync` then `SessionMinter.MintAsync` —
today as two calls repeated at each of the four login/link sites (login +
account-linking, per protocol), not through a shared extracted method. Folding
that tail into one shared collaborator is target-direction step 11
(`LoginCompletionService`, #318 §3) — not yet done.

### Process-wide stores

A handful of state stores live as `private static readonly` fields on
`SSOController` (not dependency-injected — there is no
`IPluginServiceRegistrator` in source, so a `static readonly` field is today's
only way to get one process-wide instance):

| Store                 | Guards                                                                                     |
| --------------------- | ------------------------------------------------------------------------------------------ |
| `OidcStateStore`      | in-flight OIDC authorize state; capacity cap, lifetime, throttled-sweep via `IntervalGate` |
| `SamlReplayCache`     | one-time-use SAML assertion IDs (replay protection)                                        |
| `SamlRequestCache`    | outstanding SAML `AuthnRequest` IDs for `InResponseTo` correlation                         |
| `DiscoveryFactsCache` | per-discovery-URL PKCE-S256 / RFC 9207 `iss` facts, 15-minute TTL                          |
| `SsoRateLimiter`      | opt-in per-client rate limiting on the anonymous login endpoints                           |

### The uniform outcome

`LoginOutcome` (`SSO-Auth/Api/LoginOutcome.cs`) is a closed, internal sum type
with exactly three cases: `Success(AuthenticationResult)`, `Rejected(PublicReason)`,
`Denied`. There is deliberately no `Error` case — anything unexpected
propagates as an exception and surfaces as a genuine 500, so a client-caused
condition can never silently become one, and a login-path helper cannot report
an ambiguous "maybe okay" result. `LoginStatusMapper.ToActionResult` is the
single place an outcome becomes an HTTP response; both its outer switch (over
`LoginOutcome`) and its inner switch (over `PublicReason`) throw
`InvalidOperationException` on anything unmapped, so a case added to either
enum without a mapped response fails loudly (a compile-time-adjacent
guarantee, not a silent fall-through). `AccountLinkForbiddenException`, thrown
by `CanonicalLinkService.ResolveOrCreateAsync`, is caught at each of the four
call sites and mapped to `Rejected(PublicReason.AccountLinkForbidden)` — a 403.

## 2. The tier model and naming standard

Four tiers, each discoverable by suffix or namespace, enforced as fitness
functions in `SSO-Auth.Tests/ArchitectureConformanceTests.cs` (runs in
`dotnet test`, so every PR is checked):

| Tier                         | Suffix / shape                                                                        | Example                                          | Rule                                                            |
| ---------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------ | --------------------------------------------------------------- |
| HTTP boundary                | `*Controller`, derives `ControllerBase`                                               | `SSOController`                                  | `Controllers_DeriveFromControllerBase`                          |
| Flow (stateful collaborator) | `*Service`, internal sealed                                                           | `CanonicalLinkService`, `SessionMinter`          | `FlowServices_AreInternalAndSealed`                             |
| Pure leaves                  | `*Validator/*Builder/*Mapper/*Resolver/*Policy/*Extractor`, internal sealed or static | `LoginStatusMapper`, `OidcAuthorizeStateBuilder` | `SingleResponsibilityHelpers_Are…` (internal, sealed-or-static) |
| Keyed runtime state          | `*Store/*Cache/*Gate/*Limiter`                                                        | `OidcStateStore`, `SsoRateLimiter`               | `MutableKeyedState_LivesOnlyInsideStoreLikeTypes`               |

All production types live under the `Jellyfin.Plugin.SSO_Auth` root namespace
(`EverythingLivesUnderThePluginRootNamespace`); helper types are internal by
default, never part of the plugin's public surface
(`SingleResponsibilityHelpers_AreInternal_NotPartOfThePublicSurface`) and
sealed or static leaves, never an inheritance base
(`…_AreSealedOrStatic_NotAnInheritanceBase`). Two call-level invariants are
locked in as source scans over every controller file rather than by
reflection: the controller touches no provider link map directly
(`Controller_NeverTouchesProviderLinkMaps` — that stays confined to
`CanonicalLinkService` and `ServerManagedFields.Preserve`) and no raw
socket/DNS surface (`Controller_NeverTouchesRawSocketsOrDns`).

### Target direction (#318) — not yet implemented

The [#318 target-architecture design note](https://github.com/iderex/jellyfin-plugin-sso/issues/318)
plans a further decomposition on top of the same four tiers, landed as a
sequence of small, independently gated PRs (tracked on the
[SSO Roadmap board](https://github.com/users/iderex/projects/1)):

- **A flow-service spine per protocol** — `OidcLoginService` / `SamlLoginService`
  under a new `Api/Flows/` namespace, each owning its protocol's process-wide
  stores as its own `static readonly` fields (a pure relocation, not a
  lifetime change — no service registrator exists to promote them to DI). The
  controller shrinks to route/model-binding plus one call into a flow
  service.
- **`LoginCompletionService`** — the shared resolve → mint → audit → outcome
  tail described above, extracted once so both protocols call one
  collaborator instead of duplicating the same four call sites.
- **`VerifiedIdentity`** — a protocol-agnostic record only the two protocol
  validators can construct (private constructor + factory), generalizing the
  existing OIDC `RedeemedState`. `LoginCompletionService` accepts only a
  `VerifiedIdentity`, so reaching account-resolution with an unvalidated
  response becomes a compile error rather than something a review has to
  catch — the fail-closed keystone of the migration.

None of the three exist in the tree yet. The ordered step list, the
parallelization map, and the maintainer decisions still open are in the
#318 design-note comment; this page is deliberately step 0 of that plan — a
map of the current shape so later migration PRs and their reviews do not have
to reconstruct it from scratch.

## 3. Security invariants a change must not regress

- **Fail closed by construction, not by convention.** A missing signature, an
  out-of-bounds time window, a wrong audience, a replayed assertion, an
  unresolved identity, or an unmapped `LoginOutcome`/`PublicReason` case is
  rejected or throws — never defaults to success. `LoginStatusMapper`'s two
  exhaustive switches are the enforcement point; see §1.
- **A throwing accessor turned into a guarded `Try*` accessor is a fail-open
  hazard.** Replacing a throw with a miss-branch (`is not { } x`) on the login
  path silently converts implicit fail-closed into fail-open unless the new
  miss-branch is explicitly re-decided as a rejection, with a reject-path
  test covering it. Every store lookup on this page (`PeekCurrent`,
  `TryRedeem`, `TryConsume`, `FindOidConfig`/`FindSamlConfig`) already follows
  this pattern — preserve it when extracting or refactoring around them.
- **Guard order is a preserved invariant.** For example, the disabled-provider
  check in `OidAuth`/`SamlAuth` runs _before_ the state/replay consume, so a
  disabled provider cannot be used to burn a legitimate user's in-flight
  state. Reordering guards during a refactor is a behaviour change, not a
  pure move — it needs the same review a semantics change gets.
- **Log-forging sanitization is inline, not delegated.** A value that reaches
  a log call and originated from the request (provider name, claims,
  `relayState`, roles) is sanitized at the call site
  (`x?.ReplaceLineEndings(string.Empty)`), because CodeQL's `cs/log-forging`
  sanitizers are not propagated across a helper-method boundary. Wrapping the
  sanitization in a shared helper defeats the analysis, not just the style.
- **Secrets are never logged and never round-tripped.** `OidSecret` and
  signing keys are write-only: a config read never returns the stored secret,
  and no log line carries one.

## What lives where

| Concern                                                     | File(s)                                                                                                                  |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| HTTP endpoints, provider admin CRUD                         | `SSO-Auth/Api/SSOController.cs`                                                                                          |
| OIDC state / discovery caching                              | `OidcStateStore.cs`, `PendingState.cs`, `RedeemedState.cs`, `TimedAuthorizeState.cs`                                     |
| OIDC claim/role derivation                                  | `OidcAuthorizeStateBuilder.cs`, `OidcRoleExtractor.cs`, `OidcResponseIssuer.cs`, `OidcIdTokenValidator.cs`               |
| SAML core (parsing, signature, XML hardening)               | `Saml.cs`, `SamlResponseLoader.cs`, `SamlCertificate.cs`, `SamlRecipientValidator.cs`                                    |
| SAML request/replay correlation                             | `SamlRequestCache.cs`, `SamlReplayCache.cs`, `SamlAuthorizeStateBuilder.cs`, `SamlLoginPolicy.cs`                        |
| Account linking (resolve/adopt/create/revoke)               | `Linking/CanonicalLinkService.cs`, `AccountLinkResolver.cs`, `AdoptionEligibilityResolver.cs`, `CanonicalLinkRevoker.cs` |
| Session minting (permissions, avatar, `AuthenticateDirect`) | `SessionMinter.cs`, `SessionParameters.cs`, `AvatarService.cs`                                                           |
| The uniform outcome / HTTP mapping                          | `LoginOutcome.cs`, `LoginStatusMapper.cs`, `PublicReason.cs`                                                             |
| Rate limiting / browser binding                             | `SsoRateLimiter.cs`, `AuthorizeStateBinding.cs`, `IntervalGate.cs`                                                       |
| Config persistence                                          | `Config/PluginConfiguration.cs`, `ProviderConfigStore` (see `Config/`)                                                   |
| Structural rules (fitness functions)                        | `SSO-Auth.Tests/ArchitectureConformanceTests.cs`                                                                         |

## See also

- [Login Flow](https://github.com/iderex/jellyfin-plugin-sso/wiki/Login-Flow) —
  the wiki walkthrough this page complements.
- [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model) —
  the fuller threat-model-level writeup.
- [#318](https://github.com/iderex/jellyfin-plugin-sso/issues/318) — the
  target-architecture design note this page's §2 target section summarizes.

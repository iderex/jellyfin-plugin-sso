# SSO-only login (`DisablePasswordLogin`) — STRIDE threat model & design constraints

**Status: NOT IMPLEMENTED.** This document is the mandatory pre-build design
step for issue #165 (P4 — Feature parity). It threat-models an opt-in
_SSO-only login_ mode — one that disables Jellyfin's native password login so
users must authenticate through SSO — **before any code is written**, because
the feature changes the authentication surface and, done naively, is a
mass-lockout footgun. No `DisablePasswordLogin` setting, last-admin guard, or
break-glass toggle exists in the plugin today. Building the feature is a
separate work item; it must satisfy the acceptance criteria and conformance
tests at the end of this document.

The headline finding is in [§2](#2-can-the-plugin-even-enforce-this-the-honest-answer):
**the plugin cannot flip a single global "password login off" switch, because
Jellyfin core has none.** SSO-only can only be approximated per-user by
repointing each account's `AuthenticationProviderId` away from the default
password provider — the exact lever the plugin already pulls for the accounts it
creates. That reframes the whole feature and its safety net.

---

## 1. How authentication works today (the grounding facts)

Every claim below is anchored in current `4.3` code so the threat model rests on
what the plugin actually does, not on how SSO plugins generally behave.

### 1.1 SSO is a parallel path that bypasses password auth entirely

The plugin does **not** implement `IAuthenticationProvider`. It never sits on
Jellyfin's `/Users/AuthenticateByName` password path. Instead it exposes its own
controller routes (`SSO-Auth/Api/SSOController.cs`) and, once a protocol response
is verified, mints a session directly:

- `SSO-Auth/Api/SessionMinter.cs:119` calls
  `_sessionManager.AuthenticateDirect(authRequest)` — it hands Jellyfin an
  already-authenticated request and receives an `AuthenticationResult`. No
  password is ever presented to Jellyfin on the SSO path.

Consequence: **native password login and SSO login are two independent doors.**
Turning one off does nothing to the other. Disabling password login does not
touch the SSO path; a broken SSO provider does not re-open the password path.
This independence is precisely what makes "SSO-only" a lockout risk — if the SSO
door jams and the password door is bolted, everyone is outside.

### 1.2 The only lever the plugin has over password login is `AuthenticationProviderId`

When the plugin **creates** an account for a first-time SSO user
(`SSO-Auth/Api/Linking/CanonicalLinkService.cs:453-456`):

```csharp
var user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
user.AuthenticationProviderId = typeof(SSOController).FullName;
user.Password = _cryptoProvider.CreatePasswordHash(
    Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))).ToString();
```

Two things happen, and it matters which one is load-bearing:

1. **`AuthenticationProviderId` is set to `SSOController`'s full type name** —
   which is **not** a registered `IAuthenticationProvider`. Jellyfin routes a
   user's password authentication to the provider whose type name equals their
   `AuthenticationProviderId`; when that name resolves to no registered provider,
   core substitutes its `InvalidAuthenticationProvider`, which rejects every
   password. This is the same mechanism the SSO-revoke path relies on in reverse:
   `CanonicalLinkService.cs:741` sets `user.AuthenticationProviderId = provider`
   to switch an account **back** to a real (password) provider when SSO is
   revoked. So `AuthenticationProviderId` **is** the plugin's password-login
   on/off switch — per user.
2. **A random 64-byte password is also set.** This is defence-in-depth: even if
   core ever fell through to the default password provider for that account, the
   password is unguessable. The plugin does not rely on (2) alone, and (2) is
   destructive (it overwrites any existing password) — see the lockout analysis.

**There is no server-wide equivalent.** `AuthenticationProviderId` is a
per-`User` field. Jellyfin exposes no global "disable password authentication"
setting, and the plugin cannot intercept core's `/Users/AuthenticateByName`
endpoint. Any "SSO-only" mode is therefore an **iteration over users**, flipping
each account's provider id — not a single toggle.

### 1.3 Admin / permission model

- Admin config endpoints are gated by Jellyfin's elevation policy:
  `[Authorize(Policy = Policies.RequiresElevation)]` guards every mutating SSO
  admin route (`SSOController.cs` — `OID/Add`, `OID/Del`, `SAML/Add`, `SAML/Del`,
  `Config/Import`, `Unregister`, …). Only an authenticated **administrator** can
  change plugin configuration.
- Administrator status is a per-user permission,
  `PermissionKind.IsAdministrator`, applied on the SSO path at
  `SessionMinter.cs:63` from the resolved login's `IsAdmin` flag (which SSO
  derives from the provider's admin-role claim, gated by the per-provider
  `EnableAuthorization` master switch, `SessionMinter.cs:61`).
- User enumeration for a guard is available: `IUserManager.Users` lists all
  accounts, each carrying its `AuthenticationProviderId`, `HasPassword`, and
  `IsAdministrator` permission.

### 1.4 There is already a manual break-glass doctrine

`providers.md` (the "Upgrading from a username-keyed version" runbook) already
tells operators: **"Keep a break-glass admin that does _not_ depend on SSO …
make sure at least one Jellyfin administrator has a normal password login
(Dashboard → Users), or you will be left editing config on disk."** SSO-only
mode makes that advice mandatory rather than advisory, and the feature must
enforce it rather than merely document it.

### 1.5 Configuration & audit substrate the feature will reuse

- `DisablePasswordLogin` is a **server-wide** concern, so it belongs on the
  top-level `PluginConfiguration` (`SSO-Auth/Config/PluginConfiguration.cs`),
  alongside `EnableRateLimit` — not on a per-provider `OidConfig`/`SamlConfig`.
- The plugin already has a **fail-closed refuse-to-save** precedent:
  `SSO-Auth/Config/ProviderConfigValidator.cs` throws before anything is
  persisted when an incoming config is invalid (`ProviderConfigStore.Save`
  gates on it). The last-admin guard is a new predicate in that same style.
- Audit entries go through `SSO-Auth/Api/SsoAudit.cs` (structured
  `[SSO Audit]` log lines, line-ending-sanitised). This is Jellyfin's ordinary
  log — **not** a tamper-evident hash chain — which bounds what Repudiation
  mitigation can honestly claim (see S/R below).

---

## 2. Can the plugin even enforce this? The honest answer

**Partially, and only per-user.** There is no global switch to own.

| Question                                                            | Answer                                                                                                                                                                                                           |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Can the plugin disable password login with one server setting?      | **No.** Jellyfin core has no such setting, and the plugin does not sit on the password endpoint.                                                                                                                 |
| Can the plugin disable password login for a given user?             | **Yes** — by setting that user's `AuthenticationProviderId` to a non-password provider (the `SSOController`-name lever it already uses for created accounts).                                                    |
| Can the plugin guarantee an SSO-only account cannot use a password? | **Yes**, via `AuthenticationProviderId` → `InvalidAuthenticationProvider`. The random password is belt-and-braces, not the primary barrier.                                                                      |
| Can the plugin re-enable password login without SSO?                | **Yes** — reverse the field back to `DefaultAuthenticationProvider` (the revoke path already does this at `CanonicalLinkService.cs:741`). This is the in-band break-glass.                                       |
| Can the plugin _reach into every account_ to flip it?               | **Yes** for enumeration (`IUserManager.Users`), but flipping an existing password admin is destructive-ish (it changes how they log in) and must be explicit, reversible, and never applied to the exempt admin. |

**Design consequence:** SSO-only mode is implemented as "for every user _except a
protected break-glass admin set_, ensure `AuthenticationProviderId` is not the
default password provider," plus a guard that **refuses to enter the mode unless
a working login path for at least one admin is provable.** The feature is a
managed per-user field flip with a safety interlock, not a global bolt.

---

## 3. The mass-lockout threat (risk #1) and the safety-net options

**Threat.** Enabling `DisablePasswordLogin` removes the password door for admins.
If the SSO door is then misconfigured, the IdP is down, the client secret
rotates, the discovery URL breaks, a role claim stops mapping to admin, or a
provider is deleted — **no one can obtain an administrator session.** The org is
locked out of its own server. Recovery then means editing `config.xml`/the
Jellyfin database on disk. For a self-hosted single-org tool this is the
catastrophic-availability event; it dwarfs every other risk here.

### Safety-net options considered

- **(A) Always keep ≥1 local admin exempt (a break-glass admin that keeps its
  password door).** The mode never flips the exempt admin's
  `AuthenticationProviderId`; that account can always log in with a password. The
  admin operating the toggle designates (or the plugin auto-selects) the exempt
  account. Simple, always-available, and matches the doctrine already in
  `providers.md`. Cost: one admin account is, by design, still password-reachable
  — so SSO-only is "SSO-only for everyone _but_ the break-glass admin," which is
  the honest and safe reading of the feature.
- **(B) A break-glass / recovery path (reversible toggle without SSO).** Turning
  `DisablePasswordLogin` **off** must not itself require SSO. It is a plain admin
  config write (or, if fully locked out, a `config.xml` edit that the runbook
  documents). Re-enabling restores each affected account's
  `AuthenticationProviderId` to the default provider. This is recovery, and it
  composes with (A) rather than replacing it.
- **(C) Refuse to enable if it would strand the last admin (fail-closed
  interlock).** Before persisting `DisablePasswordLogin = true`, prove that at
  least one administrator retains a working login path — either the exempt
  password admin of (A), or an admin with a live, enabled SSO canonical link on
  an **enabled** provider. If neither is provable, **reject the save with a clear
  message** and change nothing. Mirrors `ProviderConfigValidator`.
- **(D) Auto re-enable password login on SSO failure.** _Rejected._ It is a
  fail-**open** control: an attacker who can DoS the IdP (or forge a "provider
  down" signal) would re-open the password door — turning an availability blip
  into a security downgrade, and violating "fail closed." The break-glass admin
  (A) + the reversible toggle (B) already give a safe, deliberate, human-driven
  recovery. Availability is served by keeping a door that was **never** closed,
  not by auto-unbolting one under duress.

### Recommendation

**Adopt (A) + (B) + (C) together; reject (D).**

1. **(C) is the gate.** `DisablePasswordLogin` cannot be turned on unless the
   guard proves a surviving admin login path. Default state is **off**
   (fail-closed for upgrades: no existing install silently loses its password
   door).
2. **(A) is the guaranteed survivor.** Require an explicitly designated
   **break-glass admin** whose password door the mode never touches. The guard in
   (C) is satisfied most simply and most robustly by this account's continued
   existence — it does not depend on any IdP being reachable, which is the entire
   point. Refuse to enable if no such admin is designated (or if the designated
   account is not actually an enabled administrator with a usable password).
3. **(B) is the exit.** The toggle is reversible **without SSO**; the off-switch
   restores password login for the affected accounts. Document the on-disk
   `config.xml` recovery for the total-lockout case, exactly like the existing
   `providers.md` runbook.

The strongest, simplest guarantee is: **SSO-only never removes the last
password-capable administrator; there is always a designated break-glass admin
whose password login survives, and the mode refuses to activate otherwise.**
Preferring the password-admin survivor over "an admin has an SSO link" for the
guard is deliberate — an SSO link's usability depends on the IdP being up, which
is exactly the thing that fails in the lockout scenario. An SSO-linked admin MAY
count toward the guard as a secondary condition, but MUST NOT be the _only_
thing standing between the org and a locked server.

---

## 4. STRIDE

Scope of the change: a new server-wide `DisablePasswordLogin` config flag, an
admin toggle to set it, a validation guard that refuses unsafe activation, and a
routine that repoints affected users' `AuthenticationProviderId`. Threats below
are specific to that surface.

### S — Spoofing (SSO must become the _only_ path; no bypass survives)

- **T-S1 — a residual password door.** If the flip misses any admin account
  (race, new admin created after activation, an account whose provider id was not
  repointed), that account still accepts a password — SSO-only is a fiction for
  it. _Mitigation:_ the enforcement is **per-user and continuous**, not one-shot:
  (a) apply on activation to all non-exempt users; (b) re-apply on the SSO login
  path and on user-creation so a newly created/native account cannot linger on
  the password provider while the mode is on; (c) a conformance test asserts no
  non-exempt account keeps the default password provider while `DisablePasswordLogin`
  is on.
- **T-S2 — the exempt break-glass admin _is_ the intended residual door.** That
  is by design, but it means the break-glass account is now the softest target.
  _Mitigation:_ it must be an ordinary strong-password admin; document that its
  password is the org's root-of-recovery and should be strong and stored offline.
  The plugin does not weaken it and does not expose it via SSO.
- **T-S3 — SSO path spoofing is out of scope here** — it is covered by the
  existing verification stack (`OidcIdTokenValidator`, `SamlAssertionValidator`,
  issuer/audience/replay checks). SSO-only does not relax any of it; note only
  that SSO-only **raises the blast radius** of any SSO-auth bypass, because SSO
  becomes the primary door. This argues for keeping (A)'s password admin as an
  out-of-band check on a compromised IdP.

### T — Tampering (the toggle is admin-only, integrity-checked)

- **T-T1 — non-admin flips the flag.** _Mitigation:_ the toggle route carries
  `[Authorize(Policy = Policies.RequiresElevation)]` like every other mutating
  SSO admin endpoint. Fail-closed: no elevation → 403, no change.
- **T-T2 — the flag is set in config to `true` while no safe admin exists**
  (hand-edited `config.xml`, config import). _Mitigation:_ the guard (C) runs on
  **every** persistence path, not just the UI toggle — `ProviderConfigStore.Save`
  and `Config/Import` must both re-validate. A config that asserts SSO-only with
  no surviving admin login path is rejected fail-closed, matching the existing
  `ProviderConfigValidator` model.
- **SoD note (honest limitation):** ECM-style separation-of-duties (author of a
  record cannot approve it) **does not exist in Jellyfin** — any single admin can
  both design and activate this. The feature cannot manufacture dual control on
  top of Jellyfin's single-admin model. The mitigation is the fail-closed guard +
  audit, not SoD. State this limitation in the feature's docs rather than
  implying a control that is not there.

### R — Repudiation (the toggle is audited)

- **T-R1 — an admin enables/disables SSO-only and later denies it, or a lockout
  has no forensic trail.** _Mitigation:_ emit an `SsoAudit` entry on **both**
  transitions (enable and disable), recording actor (the elevated user), the new
  state, and the guard outcome (which admin(s) satisfied the survivor check).
  Add an entry when the guard **refuses** an activation, so a blocked lockout
  attempt is visible.
- **Honest limitation:** `SsoAudit` writes to Jellyfin's ordinary application
  log — it is **not** a tamper-evident hash chain, so an attacker with host/log
  access can alter it. Do not claim audit-grade non-repudiation; claim
  operational traceability. (This is the plugin's standing audit posture, not a
  regression introduced here.)

### I — Information disclosure

- **T-I1 — the guard's error message leaks which accounts are admins / their
  login state.** _Mitigation:_ the refusal message states the _reason_ ("cannot
  enable SSO-only: no administrator would retain a working login path; designate
  a break-glass admin first") without enumerating usernames/emails. Follow the
  plugin's existing `PublicReason` discipline — actionable, not a user roster.
- **T-I2 — logs.** Reuse `SsoAudit`'s line-ending sanitisation; log the actor and
  counts, not full account dumps. No secrets are involved in this feature.

### D — Denial of service (mass lockout **is** the DoS; availability is paramount)

- **T-D1 — the whole-org lockout of [§3].** This is the dominant threat of the
  entire feature. _Mitigation:_ the (A)+(B)+(C) safety net — a guaranteed
  password-capable break-glass admin, a reversible no-SSO off-switch, and a
  fail-closed activation guard. The design's success criterion is that **no
  reachable configuration of this feature can leave zero working admin logins.**
- **T-D2 — self-inflicted lockout by deleting/disabling the break-glass admin
  _after_ activation.** Activation-time proof is not enough; the exempt admin
  could later be deleted, demoted, or password-cleared while SSO-only stays on.
  _Mitigation:_ treat the survivor condition as an **invariant, re-checked at the
  moments it can break** — at minimum, refuse to persist SSO-only if the guard no
  longer holds, and (defence-in-depth) log a prominent warning if the last safe
  admin path disappears while the mode is active. Full core-side interception of
  "admin deleted" is a Jellyfin event the plugin may not receive; where the
  plugin cannot observe the event, the runbook (B) is the backstop. Be honest in
  docs about which transitions are enforced vs. documented.
- **T-D3 — SSO provider outage with SSO-only on.** _Mitigation:_ the break-glass
  password admin (A) is the by-design escape hatch; it does not depend on the
  IdP. This is why the guard must not accept "an admin has an SSO link" as the
  _sole_ survivor.
- **T-D4 — availability of the login endpoints themselves** (rate-limit
  lockout) is an existing concern governed by `SsoRateLimiter` /
  `EnableRateLimit`; SSO-only does not change it, but note that with SSO-only on,
  throttling the SSO endpoints has a larger blast radius (it is now the primary
  door). Keep the limiter's "throttle, never permanently lock" posture.

### E — Elevation of privilege (the safety net must not become a bypass)

- **T-E1 — the break-glass exemption as a privilege backdoor.** The exempt admin
  keeps a password door; if an attacker can get themselves _designated_ as the
  break-glass admin, or point the exemption at an account they control, they mint
  a permanent password-authenticable admin immune to SSO-only. _Mitigation:_
  designating/changing the break-glass admin is itself an elevated,
  `RequiresElevation` + audited operation; the exemption may only point at an
  account that is **already** an administrator (it cannot _grant_ admin, only
  spare an existing one's password door); changing it is logged.
- **T-E2 — the re-enable/off path as an elevation.** Turning SSO-only off
  re-opens password login for many accounts at once. _Mitigation:_ it is an
  elevated + audited operation; it restores `DefaultAuthenticationProvider` and
  nothing more — it must **not** reset or reveal passwords, only restore the
  provider routing, so no account gains a _known_ password from the toggle.
- **T-E3 — repointing `AuthenticationProviderId` must never grant rights.** The
  enforcement routine only changes the auth-provider routing field; it must not
  touch `IsAdministrator`, folder, or Live TV permissions. Keep it strictly
  orthogonal to the permission-granting code in `SessionMinter` so a bug here
  cannot escalate anyone.

---

## 5. Interaction with Jellyfin — how "disable password login" is actually enforced

Restating [§1.2]/[§2] as the concrete enforcement contract the implementation
must honor:

1. **There is no Jellyfin-core global setting** to disable password
   authentication, and the plugin cannot hook core's `/Users/AuthenticateByName`.
   The feature is therefore **plugin-driven per-user enforcement**, not a core
   setting the plugin merely toggles.
2. **The enforced mechanism is `User.AuthenticationProviderId`.** For each
   non-exempt account, the plugin sets it to a non-password provider id (the
   `SSOController`-name lever already proven in
   `CanonicalLinkService.cs:454`), which routes password attempts to core's
   `InvalidAuthenticationProvider` and rejects them. Re-enabling restores
   `DefaultAuthenticationProvider` (as the revoke path already does,
   `CanonicalLinkService.cs:741`).
3. **The plugin must _not_ rely on overwriting passwords** as the disabling
   mechanism for existing accounts — that is destructive and irreversible (you
   cannot restore the user's prior password on re-enable). Overwriting the
   password is acceptable only for accounts the plugin itself creates (which never
   had a user-chosen password); for pre-existing accounts, flip the provider id,
   leave the stored password hash alone, so (B) re-enable is lossless.
4. **Honesty in the UI/docs:** the config page must state that SSO-only is
   enforced by the plugin per account and that a designated break-glass admin
   retains password login by design — i.e. it is "SSO-only for all users except
   the break-glass admin," not an absolute server-wide password kill-switch.
   Overstating it would be a security-relevant misrepresentation.

---

## 6. Acceptance criteria

Extends issue #165's list; each maps to a conformance test in [§7].

1. `DisablePasswordLogin` is a **server-wide** opt-in on `PluginConfiguration`,
   **default `false`** (upgrade-safe: no install silently loses its password
   door).
2. A **break-glass admin** is designatable; the mode never repoints that
   account's `AuthenticationProviderId`, so it always retains password login.
3. Enabling `DisablePasswordLogin` is **refused, fail-closed, with a clear
   non-enumerating message**, unless the guard proves at least one administrator
   retains a working login path — satisfied canonically by an enabled admin with
   a usable password (the break-glass admin). The guard runs on **every**
   persistence path (UI save, `Config/Import`, and re-validation on load).
4. A **break-glass recovery path exists and is reversible without SSO**: turning
   the flag off is a plain elevated admin write (documented `config.xml` edit for
   the total-lockout case) and restores `DefaultAuthenticationProvider` for the
   affected accounts **without** resetting or exposing any password.
5. While the mode is on, **no non-exempt account retains the default password
   provider** — enforced on activation and re-asserted on the SSO login and
   user-creation paths (no residual password door, T-S1).
6. Setting/changing the break-glass designation and toggling the mode are
   **`RequiresElevation`-gated and audited** on both transitions (and on guard
   refusal). The exemption can only point at an **already-administrator** account
   (it never grants admin).
7. The enforcement routine changes **only** `AuthenticationProviderId`; it never
   alters `IsAdministrator`, folder, or Live-TV permissions (T-E3).
8. Docs state honestly that (a) there is no global Jellyfin kill-switch, (b) the
   break-glass admin is a deliberate residual password door, and (c) Jellyfin
   offers no SoD, so a single admin can both design and activate the mode.

## 7. Conformance / negative tests the implementation must ship

Every fail-closed branch gets a negative test (repo rule). Mirror the existing
suites (`ProviderConfigValidatorTests`, `SessionMinterTests`,
`SSOControllerUnregisterTests`).

- **`Enable_refused_when_no_admin_would_retain_a_login_path`** — guard rejects
  activation and persists nothing when the only admin(s) would lose password
  login and have no live SSO admin link. (The central lockout branch.)
- **`Enable_allowed_when_a_break_glass_password_admin_exists`** — positive path:
  designated password admin present → activation succeeds; that admin's
  `AuthenticationProviderId` is unchanged.
- **`Enabling_does_not_strand_via_config_import`** — the same guard fires on
  `Config/Import` (and on config load), not only the UI toggle; an imported
  config asserting SSO-only with no safe admin is rejected.
- **`Break_glass_admin_provider_id_never_repointed`** — after activation, the
  exempt admin still routes to the password provider.
- **`No_nonexempt_account_keeps_password_provider_while_mode_on`** — invariant
  check across `IUserManager.Users` after activation and after a subsequent SSO
  login / user creation (T-S1).
- **`Disable_restores_default_provider_without_touching_password_hash`** —
  re-enable is lossless: provider id restored to `DefaultAuthenticationProvider`,
  stored password hash byte-for-byte unchanged (T-E2, criterion 4).
- **`Toggle_and_designation_require_elevation`** — non-elevated caller gets 403,
  no state change, for both the mode toggle and the break-glass designation.
- **`Break_glass_designation_rejects_non_admin_target`** — exemption cannot point
  at a non-administrator (T-E1); it cannot grant admin.
- **`Enable_and_disable_and_refusal_are_audited`** — an `SsoAudit` entry is
  emitted on enable, on disable, and on guard refusal, with actor + outcome and
  no username enumeration.
- **`Enforcement_routine_touches_only_authentication_provider_id`** — property/
  unit test that the repoint routine leaves `IsAdministrator`, folder, and
  Live-TV permissions untouched (T-E3).
- **`Guard_does_not_count_sso_link_on_disabled_or_deleted_provider`** — an admin
  whose only path is an SSO link on a **disabled/deleted** provider does **not**
  satisfy the survivor guard (reuses the `IsIdentityStillLinked` /
  `requireEnabled` semantics from `CanonicalLinkService.cs:731-736`).

---

## 8. Summary for the reviewer

- **Can the plugin enforce SSO-only?** Only **per-user**, by repointing
  `AuthenticationProviderId` (the lever it already uses at
  `CanonicalLinkService.cs:454`). **No global Jellyfin password kill-switch
  exists**, and the plugin cannot intercept core's password endpoint — so the
  honest framing is "SSO-only for every account except a designated break-glass
  admin."
- **Recommended safety net:** **(A) a mandatory designated break-glass password
  admin + (B) a reversible, no-SSO off-switch + (C) a fail-closed activation
  guard** that refuses to enable the mode unless a working admin login path is
  provable. **Reject (D) auto-re-enable-on-SSO-failure** — it is fail-open.
- **#1 risk:** whole-org mass lockout (a DoS). The design's success criterion is
  that **no reachable configuration can leave zero working admin logins**, and
  the break-glass admin — which does not depend on the IdP — is the guaranteed
  survivor.
- **Honest limitations to carry into the docs:** no SoD in Jellyfin (single
  admin can self-approve), `SsoAudit` is a plain log (not tamper-evident), and
  post-activation deletion of the break-glass admin is only partially
  observable by the plugin — the runbook is the backstop.

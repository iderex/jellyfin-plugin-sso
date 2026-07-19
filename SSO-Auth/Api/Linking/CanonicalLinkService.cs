using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The outcome of a manual link-creation request. Closed by convention (the controller's mapper throws
/// on an unhandled arm), so a new outcome forces a new mapping rather than a silent fall-through.
/// </summary>
internal enum CanonicalLinkWriteResult
{
    /// <summary>The link was created.</summary>
    Created,

    /// <summary>The SSO identity did not resolve a usable key; nothing was written.</summary>
    EmptyKey,

    /// <summary>No provider of that mode/name exists; nothing was written.</summary>
    UnknownProvider,
}

/// <summary>
/// The outcome of a manual unlink request. Closed by convention (the controller's mapper throws on an
/// unhandled arm).
/// </summary>
internal enum CanonicalLinkRemoveResult
{
    /// <summary>The link was removed.</summary>
    Removed,

    /// <summary>No link is registered for that canonical name.</summary>
    NotFound,

    /// <summary>A link exists but is registered to a different Jellyfin user; nothing was removed.</summary>
    Mismatch,

    /// <summary>No provider of that mode/name exists; nothing was removed.</summary>
    UnknownProvider,
}

/// <summary>
/// The issuer binding of a resolved subject-keyed OpenID link against the current login's issuer (#186).
/// SAML (any non-OpenID mode) and a login with no resolved subject link are <see cref="NotBound"/>.
/// </summary>
internal enum IssuerBinding
{
    /// <summary>Issuer binding does not apply (SAML / any non-OpenID mode, or no subject link resolved).</summary>
    NotBound,

    /// <summary>The link's stored issuer ordinally equals the login's issuer — proceed, no write.</summary>
    Match,

    /// <summary>The link carries no stored issuer (a legacy/un-stamped link) — eligible for trust-on-first-use stamping.</summary>
    Absent,

    /// <summary>The link's stored issuer differs from the login's — refuse the login (fail closed).</summary>
    Mismatch,
}

/// <summary>
/// The outcome of a manual unlink, together with whether the target user still holds any other canonical
/// SSO link after it. The remainder is meaningful only when <see cref="Result"/> is
/// <see cref="CanonicalLinkRemoveResult.Removed"/> (the other outcomes change no state); the controller
/// uses it to revoke the user's active tokens ONLY when the unlink removed their LAST link, matching the
/// hard-lockdown posture of Unregister (#440/#468) without logging out a user who still has a working SSO
/// identity.
/// </summary>
/// <param name="Result">The remove outcome.</param>
/// <param name="UserRetainsAnyLink">
/// Whether any SAML or OpenID provider still holds a canonical link pointing at the unlinked user,
/// evaluated in the SAME transaction as the removal. Only defined when <paramref name="Result"/> is
/// <see cref="CanonicalLinkRemoveResult.Removed"/>; false on the no-op outcomes.
/// </param>
internal readonly record struct CanonicalLinkRemoval(CanonicalLinkRemoveResult Result, bool UserRetainsAnyLink);

/// <summary>
/// The account-linking workflow behind the SSO login and admin endpoints: it resolves an SSO identity
/// to a Jellyfin account (reusing an existing canonical link, adopting a pre-existing account, or
/// creating one), migrates legacy username-keyed links to the stable subject key (#155), and revokes
/// links. The controller keeps the HTTP boundary, the authorization guards, and the one-time-use
/// replay/state consume; this service keeps the account-resolution decision (via the pure
/// <see cref="AccountLinkResolver"/>) and every read/write of a provider's canonical-links map, all
/// through the <see cref="ProviderConfigStore"/> facade so each check-then-write stays under one lock.
/// </summary>
internal sealed class CanonicalLinkService
{
    // The once-per-interval throttle for the two terminal pending-legacy-link warnings (the
    // CreateNewAccount-orphan and RejectNameTaken-migratable branches). It is PROCESS-WIDE (static) on
    // purpose: this service is constructed per request by the controller, so an instance field would
    // reset every login and throttle nothing. During an upgrade window a hot login loop for a
    // not-yet-migrated user would otherwise re-emit the same warning on every attempt (CWE-400,
    // log-volume — #362/#358); the shared gate bounds that to one line per interval across all requests.
    // A one-minute interval matches the sibling cap-warn gates (OidcStateStore / SamlRequestCache, #246).
    // Tests inject a fresh gate + a fake clock so the throttle is deterministic and never leaks its cursor
    // across cases.
    private static readonly IntervalGate SharedLegacyLinkWarnGate = new(TimeSpan.FromMinutes(1));

    private readonly IUserManager _userManager;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ProviderConfigStore _configStore;
    private readonly ILogger _logger;
    private readonly IntervalGate _legacyLinkWarnGate;
    private readonly Func<DateTime> _clock;

    internal CanonicalLinkService(
        IUserManager userManager,
        ICryptoProvider cryptoProvider,
        ProviderConfigStore configStore,
        ILogger logger,
        IntervalGate legacyLinkWarnGate = null,
        Func<DateTime> clock = null)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        _configStore = configStore ?? throw new ArgumentNullException(nameof(configStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Production leaves both null and gets the process-wide gate + wall clock; tests pass a fresh gate
        // and a fake clock so the throttle stays deterministic and isolated per case.
        _legacyLinkWarnGate = legacyLinkWarnGate ?? SharedLegacyLinkWarnGate;
        _clock = clock ?? (() => DateTime.UtcNow);
    }

    /// <summary>
    /// Resolves the SSO login's stable identity to a Jellyfin user, creating or adopting the account per
    /// the provider's policy, and returns its id. Throws <see cref="AccountLinkForbiddenException"/> when
    /// the login must be refused (no identity resolved, or a pre-existing account may not be adopted).
    /// </summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the login authenticated against.</param>
    /// <param name="canonicalKey">The stable identity key (OpenID sub / SAML NameID).</param>
    /// <param name="username">The display name the account is provisioned/adopted under.</param>
    /// <param name="allowExistingAccountLink">Whether adopting a pre-existing unlinked account is permitted.</param>
    /// <param name="adoptionGate">
    /// The extra proof a same-named adoption must clear (#218): a privileged target is always refused, and
    /// when the gate requires a verified email the login must carry <c>email_verified == true</c>. Default
    /// (<see cref="AdoptionGate.None"/>) is the SAML/legacy posture: admin refusal only.
    /// </param>
    /// <param name="issuer">
    /// The OpenID login's id_token issuer, used to issuer-bind the canonical link (#186): a resolved link
    /// whose stored issuer does not match this value is refused (fail closed, after an apparent repoint),
    /// and a link with no stored issuer is stamped with this value on first use (trust-on-first-use). Null
    /// for SAML and for a token that carried no <c>iss</c>; both skip the binding.
    /// </param>
    /// <returns>The resolved Jellyfin user id.</returns>
    internal async Task<Guid> ResolveOrCreateAsync(ProviderMode mode, string provider, string canonicalKey, string username, bool allowExistingAccountLink, AdoptionGate adoptionGate = default, string issuer = null)
    {
        // Defense in depth (#95, #155): a login that resolved no stable identity key (OpenID sub /
        // SAML NameID) or no username must never create, adopt, or look up an account. Both callbacks
        // reject such logins before calling here; this belt keeps the invariant if a caller forgets.
        if (string.IsNullOrWhiteSpace(canonicalKey) || string.IsNullOrWhiteSpace(username))
        {
            throw new AccountLinkForbiddenException("The SSO login did not resolve an identity; refusing to create or link an account.");
        }

        // Read candidates -> refuse a repoint -> maybe migrate/stamp -> resolve -> act. The two locked
        // transactions (the candidate read and, on the legacy path, the migrate-and-resolve) stay whole
        // inside their own helpers; each fail-closed branch keeps its verbatim log line one level down.
        var candidates = ReadResolutionCandidates(mode, provider, canonicalKey, username, issuer);

        RefuseRepointedIssuer(candidates, mode, provider, username);

        // The account currently bearing the display name, resolved once (outside the config lock — it is
        // a user-manager read, not a config read). It is both the same-name adoption candidate for the
        // Resolve gate below AND, when it IS the legacy link's target, the proof that following the legacy
        // username key is still true same-name matching rather than handing over an account that was
        // renamed away from this name (#361). A legacy link whose target no longer holds the name is left
        // for the terminal branches to label (a fresh-account orphan, or a reject), never followed.
        var existingAccount = _userManager.GetUserByName(username);
        Guid? existingAccountUserId = existingAccount?.Id;
        bool legacyNameStillHeldByTarget = candidates.LegacyLink.HasValue && existingAccountUserId == candidates.LegacyLink;

        var (linkedUserId, migrateLegacy) = AccountLinkResolver.ResolveCanonicalLink(candidates.SubjectLink, candidates.LegacyLink, legacyNameStillHeldByTarget, allowExistingAccountLink);
        if (migrateLegacy)
        {
            // Migration fires only when the account currently bearing the name IS the legacy target
            // (legacyNameStillHeldByTarget), so that target is exactly existingAccount (non-null here).
            linkedUserId = MigrateLegacyLinkIfEligible(mode, provider, canonicalKey, username, issuer, existingAccount!);
        }
        else if (candidates.SubjectLink.HasValue && candidates.SubjectIssuer == IssuerBinding.Absent)
        {
            // Trust-on-first-use migration (#186): the resolved subject link carries no stored issuer — it
            // was minted before this store existed, or by a null-issuer path. The provider is unchanged
            // (we did not hit the mismatch refusal above), so the login's issuer IS the one the link was
            // minted under; stamp it now so a later same-URL issuer swap is caught. No lockout on upgrade:
            // an existing user's first post-upgrade login stamps and proceeds. Skipped when the login
            // carries no issuer — there is nothing safe to bind to, so the link stays un-stamped.
            StampIssuer(mode, provider, canonicalKey, issuer);
        }

        // A legacy link that survives here un-migrated (flag off — or flag on but the name no longer
        // resolves to the recorded target, #354/#361) is not logged at this point: its terminal outcome
        // decides the right message. It splits into a refusal (the name is still taken) or a
        // fresh-account creation (the name was freed by a rename), and only the outcome
        // branch below can label it accurately — the fresh-account case is a SUCCESSFUL login that
        // silently orphans the original account, not a "refused" one, so a single pre-gate line would
        // mislabel exactly the event an operator most needs to see. Each terminal branch emits its one
        // line through the shared once-per-interval gate (#362): a hot login loop for a not-yet-migrated
        // user is bounded to one warning per interval instead of one per attempt, so an upgrade window is
        // a heartbeat naming who still needs migrating rather than a flood. Only the WARNING FREQUENCY is
        // throttled — the refusal throw and the fresh-account creation still run on every login.

        // Adoption of a pre-existing unlinked account still matches on the display name resolved above.
        var decision = AccountLinkResolver.Resolve(linkedUserId, existingAccountUserId, allowExistingAccountLink);
        switch (decision.Action)
        {
            case AccountLinkAction.UseExistingLink:
                return decision.UserId;

            case AccountLinkAction.AdoptExistingAccount:
                // existingAccount is non-null here (adoption is only chosen when a named account resolved).
                return AdoptExistingAccount(mode, provider, canonicalKey, username, issuer, existingAccount!, adoptionGate, decision.UserId);

            case AccountLinkAction.CreateNewAccount:
                return await CreateNewAccountAsync(mode, provider, canonicalKey, username, issuer, candidates.LegacyLink).ConfigureAwait(false);

            case AccountLinkAction.RejectNameTaken:
                throw RejectNameTaken(candidates.LegacyLink, mode, provider, username);

            default:
                throw new InvalidOperationException($"Unhandled account-link action: {decision.Action}");
        }
    }

    // Reads both candidate links (subject-keyed and legacy username-keyed) AND the subject link's issuer
    // binding in ONE pass under the config lock, so the whole verdict is linearized against a concurrent
    // migration or issuer stamp/repoint.
    //
    // The link is keyed on the stable identity. A legacy OpenID link (#155) was keyed on the mutable
    // username instead; when no subject-keyed link exists yet but a legacy one resolves, the caller
    // adopts and re-keys it, locking it to the subject so a later provider-side rename cannot detach it.
    // Because the legacy key is a name the identity provider controls, following it is name-based account
    // matching, so it honors AllowExistingAccountLink exactly like same-named adoption (#354): with the
    // flag off, a login whose preferred_username points at another user's entry is refused by the
    // adoption gate instead of being handed that account. Even with the flag on it is followed ONLY while
    // the recorded target still bears the name (#361); a target renamed away from it is not handed over
    // on the strength of a stale name key. Only OpenID differs key from name; SAML passes key == name.
    // Both candidates are read in ONE pass under the config lock: with separate reads, a concurrent
    // login's migration could commit between them, so this login would see the subject key before the
    // re-key and the legacy key after it, resolve neither, and bounce a legitimate user off the adoption
    // gate with a spurious 403. A link whose target user was deleted counts as absent (dangling links are
    // dead, not identities).
    private ResolutionCandidates ReadResolutionCandidates(ProviderMode mode, string provider, string canonicalKey, string username, string issuer)
    {
        return _configStore.Read(configuration =>
        {
            // The login callbacks resolve the provider before calling, so it is normally present and
            // enabled. If it was deleted OR DISABLED in the race between that lookup and here, fail
            // CLOSED: refuse rather than fall through to the adoption gate, whose create/adopt arms
            // would otherwise mint a session with the provider's pre-delete/pre-disable settings (#373,
            // #380 — a missing provider must never default the login to valid, and the same holds for a
            // disabled one). Residual window, documented honestly: the mint itself always runs OUTSIDE
            // the config lock, so a delete/disable after the LAST guarded transaction of any arm — this
            // single read on the UseExistingLink path, the link write on adopt/create, the migration on
            // the legacy path — still mints once. The guards move the final checkpoint later; #343's
            // "disabling takes effect immediately" stays best-effort for an in-flight request unless the
            // lock were held through minting.
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links))
            {
                throw new AccountLinkForbiddenException("The SSO provider is no longer configured or is disabled; refusing to resolve or create an account.");
            }

            Guid? bySubject = links.TryGetValue(canonicalKey, out var s) && _userManager.GetUserById(s) != null
                ? s : null;
            Guid? byName = bySubject is null
                && !string.Equals(canonicalKey, username, StringComparison.Ordinal)
                && links.TryGetValue(username, out var n) && _userManager.GetUserById(n) != null
                ? n : (Guid?)null;

            // Classify the subject link's issuer binding in the SAME locked read (#186), so the verdict
            // cannot tear against a concurrent stamp or repoint. NotBound unless a subject link resolved
            // for an OpenID provider.
            var issuerVerdict = bySubject is null
                ? IssuerBinding.NotBound
                : ClassifyIssuer(configuration, mode, provider, canonicalKey, issuer);
            return new ResolutionCandidates(bySubject, byName, issuerVerdict);
        });
    }

    // Non-inert issuer binding (#186): the subject-keyed link this identity resolves to was minted under a
    // DIFFERENT issuer than the login now presents — an admin repointed the provider entry at another
    // identity provider behind the same discovery URL, or (with the URL edited) the belt has not yet run.
    // Refuse rather than map this login onto the old link's account; a colliding `sub` from a new IdP
    // (realistic for short numeric subjects like "1") no longer inherits the old user. Fail closed,
    // self-healing: the admin re-establishes the link, or an endpoint edit clears the stale links
    // (ServerManagedFields belt). This is the check that MUST fire at runtime — the prior review rejected
    // an inert take; a rejection test pins that it does. A login with no issuer while the link has one
    // lands here too (ClassifyIssuer treats it as a mismatch), so a token omitting `iss` cannot slip past
    // a stamped binding.
    private void RefuseRepointedIssuer(ResolutionCandidates candidates, ProviderMode mode, string provider, string username)
    {
        if (candidates.SubjectLink.HasValue && candidates.SubjectIssuer == IssuerBinding.Mismatch)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "OpenID login for {Name} via {Mode}/{Provider} refused: the account link's stored issuer does not match the login's issuer (the provider entry may have been repointed at a different identity provider). Re-establish the link via the admin endpoints.",
                    username?.ReplaceLineEndings(string.Empty),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty));
            }

            throw new AccountLinkForbiddenException("The account link was minted under a different issuer; refusing to resolve it after an apparent provider repoint.");
        }
    }

    // The #155 legacy re-key, gated by the admin refusal and folded into ONE config transaction (#363).
    // Returns the authoritative user id the identity now resolves to (the value the login binds to), or
    // throws when an administrator target must not be adopted by name. The name contains "Migrate", so the
    // #363 conformance rule pins its Guid? return type.
    private Guid? MigrateLegacyLinkIfEligible(ProviderMode mode, string provider, string canonicalKey, string username, string issuer, User existingAccount)
    {
        // The legacy re-key is name-based account matching too (#218): migration fires only when the
        // account currently bearing the name IS the legacy target (legacyNameStillHeldByTarget), so
        // that target is exactly existingAccount. Apply the admin refusal here as well — an attacker
        // presenting a new subject with a victim admin's preferred_username would otherwise re-key the
        // admin's legacy link onto their own subject and take the account over. Admin-only gate
        // (AdoptionGate.None): the verified-email requirement is deliberately not applied to the
        // re-key, which continues a relationship established under the pre-#155 scheme rather than
        // forming a new one. Link an admin account explicitly via the admin endpoint instead.
        if (AdoptionEligibilityResolver.Resolve(existingAccount.HasPermission(PermissionKind.IsAdministrator), AdoptionGate.None) != AdoptionVerdict.Allow)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: a legacy username-keyed link points at an administrator account, which is not adopted by name. Link it explicitly via the admin endpoints.",
                    username?.ReplaceLineEndings(string.Empty),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty));
            }

            throw new AccountLinkForbiddenException();
        }

        // Re-key the legacy link AND re-resolve the identity in ONE config transaction (#363), then
        // bind the login to the value that transaction returns. The candidate resolution above was a
        // separate lock acquisition, so a concurrent login could migrate this same identity between
        // that snapshot and the re-key; taking the authoritative mapping from inside the re-key
        // transaction — rather than the pre-migration snapshot's linkedUserId — closes that window
        // instead of reasoning about its (previously argued-benign) safety. A concurrent winner's live
        // subject link is used as-is; the deleted-target edge resolves to null so the login falls
        // through to the create/adopt gate rather than binding to a dead account.
        var migratedUserId = MigrateAndResolveCanonicalLink(mode, provider, canonicalKey, username, issuer);
        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation(
                "Migrated {Mode}/{Provider} canonical link from the legacy username key to the stable subject key.",
                mode.ToToken(),
                provider?.ReplaceLineEndings(string.Empty));
        }

        return migratedUserId;
    }

    // Adopts the pre-existing account that shares the display name, after clearing the eligibility gate.
    // existingAccount is non-null (the caller passes it only when a named account resolved), so the admin
    // read cannot NRE.
    private Guid AdoptExistingAccount(ProviderMode mode, string provider, string canonicalKey, string username, string issuer, User existingAccount, AdoptionGate adoptionGate, Guid candidateUserId)
    {
        // Same-name adoption trusts the identity provider to make usernames unique and
        // non-reassignable (#218): a new principal asserting an existing user's name is otherwise
        // routed straight to that account. Before writing the link, clear the eligibility gate —
        // an administrator target is never adopted by name (link it explicitly via the admin
        // endpoint), and a provider that requires a verified email must have carried
        // email_verified == true. Fail closed: a refusal writes no link and emits no adoption audit.
        var verdict = AdoptionEligibilityResolver.Resolve(
            existingAccount.HasPermission(PermissionKind.IsAdministrator),
            adoptionGate);
        if (verdict != AdoptionVerdict.Allow)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused adoption of a pre-existing account: {Reason}.",
                    username?.ReplaceLineEndings(string.Empty),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty),
                    DescribeAdoptionRefusal(verdict));
            }

            throw new AccountLinkForbiddenException();
        }

        // Atomic check-then-link (#133): if a concurrent first-login already linked this
        // identity, that winner is used and no second write or duplicate audit occurs. The link
        // write also stamps the login's issuer (#186), so the adopted link is issuer-bound.
        var (adoptedUserId, wrote) = LinkCanonicalIfAbsent(mode, provider, canonicalKey, candidateUserId, issuer);
        if (wrote)
        {
            SsoAudit.AccountAdopted(_logger, mode == ProviderMode.Oid ? "OpenID" : "SAML", provider, username);
        }

        return adoptedUserId;
    }

    // Maps an adoption refusal verdict to a fixed, non-PII reason phrase for the log line above. The
    // AdoptionVerdict is a reason CODE (RefusePrivileged / RefuseUnverifiedEmail), never an email or any
    // user data — but logging the enum value directly makes CodeQL's cs/exposure-of-private-information
    // heuristic trip on the "Email" in the RefuseUnverifiedEmail member name (a false positive, latent on
    // main and surfaced only once the log moved into this small helper where the flow is interprocedural).
    // Returning a literal phrase per arm keeps the refusal reason in the audit line — and reads clearer than
    // the raw enum name — while cutting the data flow the heuristic followed. The Allow arm is unreachable
    // (the caller logs only on a refusal); it is a belt for a future verdict value.
    private static string DescribeAdoptionRefusal(AdoptionVerdict verdict) => verdict switch
    {
        AdoptionVerdict.RefusePrivileged => "the target account is an administrator; link it explicitly via the admin endpoints",
        AdoptionVerdict.RefuseUnverifiedEmail => "the provider requires a verified email for adoption and the login carried none",
        _ => "the account is not eligible for name-based adoption",
    };

    // Provisions a fresh Jellyfin account for this identity and links it on the subject key, warning first
    // when a now-orphaned legacy link is being left behind.
    private async Task<Guid> CreateNewAccountAsync(ProviderMode mode, string provider, string canonicalKey, string username, string issuer, Guid? legacyLink)
    {
        if (legacyLink.HasValue && _legacyLinkWarnGate.TryEnter(_clock()))
        {
            // The dangerous, previously-silent case (#354/#361): a legacy username-keyed link
            // exists and its target still exists, but no live account bears the name anymore (the
            // account was renamed on the Jellyfin side), so the legacy link was NOT followed —
            // whether adoption is off, or on but the name no longer resolves to the recorded target
            // (#361, the stale-name superset the flag-on arm used to hand over). We are about to
            // provision a FRESH account under this subject, leaving the original — the one the
            // legacy key points at — orphaned from this identity. This warning is the single
            // observable signal of that outcome; recover by linking the original account to this
            // subject via the admin endpoints. See the upgrade runbook in the Provider-Setup wiki
            // page (https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup). Throttled
            // through the shared once-per-interval gate (#362) so a login loop cannot flood it; the
            // account is still provisioned on every login regardless of whether the line is emitted.
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider}: a legacy username-keyed link exists but no live account bears the name (it was renamed on the Jellyfin side), so a fresh account is being provisioned and the original account is now orphaned. Re-link it to this subject via the admin endpoints.",
                    username?.ReplaceLineEndings(string.Empty),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty));
            }
        }

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation("SSO user {Name} doesn't exist, creating...", username?.ReplaceLineEndings(string.Empty));
        }

        var user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
        user.AuthenticationProviderId = typeof(SSOController).FullName;
        // https://jonathancrozier.com/blog/how-to-generate-a-cryptographically-secure-random-string-in-dot-net-with-c-sharp
        user.Password = _cryptoProvider.CreatePasswordHash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))).ToString();

        // Atomic check-then-link (#133): if a concurrent first-login for the same identity
        // linked meanwhile, use its account — this freshly created user is left unlinked rather
        // than overwriting the winner's link (a rare, benign orphan, not a duplicate login). The
        // link write stamps the login's issuer (#186), so the new link is issuer-bound.
        var (effectiveUserId, _) = LinkCanonicalIfAbsent(mode, provider, canonicalKey, user.Id, issuer);
        return effectiveUserId;
    }

    // Logs the name-taken refusal (distinguishing a pending migratable legacy link from an ordinary #95
    // collision) and RETURNS the exception the caller throws, so the terminal switch arm reads as the
    // refusal it is. The refusal throws on every login; only the WARNING is throttled through the shared
    // once-per-interval gate (#362) so a login loop for a not-yet-migrated user cannot flood the log.
    private AccountLinkForbiddenException RejectNameTaken(Guid? legacyLink, ProviderMode mode, string provider, string username)
    {
        if (legacyLink.HasValue)
        {
            // Refused, but specifically because a legacy username-keyed link (#354) is pending
            // and a live account still bears the name — the migratable case, distinct from an
            // ordinary #95 name collision. Throttled through the shared once-per-interval gate
            // (#362) so a login loop for a not-yet-migrated user cannot flood it; the refusal
            // still throws on every login regardless of whether this line is emitted.
            if (_legacyLinkWarnGate.TryEnter(_clock()))
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning(
                        "SSO login for {Name} via {Mode}/{Provider} refused: a legacy username-keyed link is pending but AllowExistingAccountLink is off and a live account still bears the name. Enable AllowExistingAccountLink (a short controlled window) or link the account via the admin endpoints to migrate it.",
                        username?.ReplaceLineEndings(string.Empty),
                        mode.ToToken(),
                        provider?.ReplaceLineEndings(string.Empty));
                }
            }
        }
        else
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: a pre-existing unlinked Jellyfin account exists and AllowExistingAccountLink is disabled for this provider.",
                    username?.ReplaceLineEndings(string.Empty),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty));
            }
        }

        return new AccountLinkForbiddenException();
    }

    /// <summary>
    /// Creates a manual canonical link (admin/self linking) from a provider-side identity to a Jellyfin
    /// user, under the config lock. HTTP-free: the controller maps the returned result to a response.
    /// </summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="providerUserId">The provider-side identity key (OpenID sub / SAML NameID).</param>
    /// <param name="jellyfinUserId">The Jellyfin user to link the identity to.</param>
    /// <param name="issuer">The OpenID id_token issuer to issuer-bind the new link to (#186); null for SAML or an unauthenticated admin link, which leaves the link un-stamped (trust-on-first-use applies on its first login).</param>
    /// <returns>The write outcome.</returns>
    internal CanonicalLinkWriteResult TryCreateLink(ProviderMode mode, string provider, string providerUserId, Guid jellyfinUserId, string issuer = null)
    {
        // Fail closed (#95), linking-side choke point: an SSO identity that did not resolve must not
        // create a link — an empty or whitespace key would persist a dead link no login can ever redeem.
        // Checked BEFORE the provider lookup so the two refusals keep their distinct response bodies
        // ("did not resolve an identity" vs "no matching provider"); reordering is observable.
        if (string.IsNullOrWhiteSpace(providerUserId))
        {
            return CanonicalLinkWriteResult.EmptyKey;
        }

        return _configStore.Mutate(configuration =>
        {
            // Link creation is a GRANT of future login capability, and both callers (the self-or-admin
            // link endpoints) already gate Enabled at the controller — so requiring it here too costs no
            // reachable workflow and closes the same mid-flight-disable window the login-path write guard
            // closes (#380): without it, a link could still be written for a provider disabled between
            // the controller gate and this transaction, surviving a cleanup sweep and minting on
            // re-enable. Steady-state result is unchanged (UnknownProvider, as the controller yields).
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links))
            {
                return CanonicalLinkWriteResult.UnknownProvider;
            }

            links[providerUserId] = jellyfinUserId;
            StampIssuerInPlace(configuration, mode, provider, providerUserId, issuer);
            return CanonicalLinkWriteResult.Created;
        });
    }

    /// <summary>
    /// Removes a manual canonical link, but only when it is registered to the given Jellyfin user, under
    /// the config lock. HTTP-free: the controller maps the returned result to a response. The find,
    /// ownership check, and removal are one read-modify-write so they cannot interleave with a concurrent
    /// write to the same map.
    /// </summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="canonicalName">The provider-side identity key whose link is removed.</param>
    /// <param name="jellyfinUserId">The Jellyfin user the link must belong to.</param>
    /// <returns>The remove outcome, plus whether the user retains any other link (#468).</returns>
    internal CanonicalLinkRemoval TryRemoveLink(ProviderMode mode, string provider, string canonicalName, Guid jellyfinUserId)
    {
        // Kept as ONE Mutate (find, ownership check, remove, and the last-link check cannot interleave). A
        // no-result outcome still persists the unchanged config. For NotFound / Mismatch that already
        // matched the old controller code (its mutate callback ran to completion and persisted a no-op);
        // for UnknownProvider it is a deliberate small delta — the old code threw KeyNotFoundException out
        // of the callback before the persist, so the unknown-provider DELETE did not write, whereas this
        // returns UnknownProvider normally and Mutate<T> then persists. The config content and the HTTP
        // response are byte-identical either way, it is admin-gated, and it adds no new capability (the
        // valid-provider + bogus-name DELETE already forced the same no-op write). A read-probe-then-
        // mutate would avoid the write but reintroduce the resolve/act race this deliberately excludes.
        return _configStore.Mutate(configuration =>
        {
            // Removal REVOKES a grant, so it must keep working on a disabled provider —
            // disable-then-clean-up is the normal workflow, and gating a revocation on Enabled would
            // fail-open nothing while blocking exactly that cleanup (#380). Only absence is unknown here.
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: false, out var links))
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.UnknownProvider, UserRetainsAnyLink: false);
            }

            if (!links.TryGetValue(canonicalName, out var linkedId))
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.NotFound, UserRetainsAnyLink: false);
            }

            if (linkedId != jellyfinUserId)
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.Mismatch, UserRetainsAnyLink: false);
            }

            links.Remove(canonicalName);

            // Drop the OpenID issuer entry alongside the link (#186), so the issuer map does not accumulate
            // orphans and a later re-link of the same sub is not judged against a stale binding. No-op for SAML.
            RemoveIssuer(configuration, mode, provider, canonicalName);

            // Whether the user keeps any other canonical link across ALL providers, read in the SAME
            // transaction as the removal (#468): computing it here rather than in a second lock acquisition
            // means a concurrent link add/remove cannot interleave between the remove and the check and
            // mislead the controller's last-link revocation decision. Fail toward availability at the exact
            // boundary — the user is deemed to still have SSO access unless this proves otherwise.
            var retainsAnyLink = UserHasAnyLink(configuration, jellyfinUserId);
            return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.Removed, retainsAnyLink);
        });
    }

    /// <summary>
    /// Projects, for one protocol, a provider -> [canonical keys linked to this user] map, materialized
    /// under the config lock. Each provider's matches are realized with <c>ToList</c> (#157/F-10) so the
    /// result is a detached snapshot that cannot tear against a concurrent login writing a link during
    /// JSON serialization.
    /// </summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="jellyfinUserId">The Jellyfin user whose links are listed.</param>
    /// <returns>A provider -> link-key-list map.</returns>
    internal SerializableDictionary<string, IEnumerable<string>> LinksByUser(ProviderMode mode, Guid jellyfinUserId)
    {
        return _configStore.Read(configuration =>
        {
            // Both arms project (name, links) tuples through ProviderConfigBase.CanonicalLinks, so the
            // per-mode twin queries are one shape. A provider stored with a null config object (reachable
            // today via #350's null-body add) yields null links and is skipped rather than dereferenced —
            // same fail-closed treatment TryGetLinks gives it, so the read side cannot NRE into a 500 on
            // a state the write side can produce.
            var providerLinks = mode == ProviderMode.Saml
                ? configuration.SamlConfigs.Select(p => (p.Key, p.Value?.CanonicalLinks))
                : configuration.OidConfigs.Select(p => (p.Key, p.Value?.CanonicalLinks));

            var mappings = new SerializableDictionary<string, IEnumerable<string>>();
            foreach (var (provider, links) in providerLinks)
            {
                if (links != null)
                {
                    mappings[provider] = links
                        .Where(link => link.Value == jellyfinUserId)
                        .Select(link => link.Key)
                        .ToList();
                }
            }

            return mappings;
        });
    }

    /// <summary>
    /// Removes every canonical link pointing at the given user across all SAML and OpenID providers, so
    /// an SSO login no longer resolves to the account. Runs under the config lock and returns the number
    /// of links removed.
    /// </summary>
    /// <param name="userId">The Jellyfin user whose links are revoked.</param>
    /// <returns>The number of links removed.</returns>
    internal int RemoveUserEverywhere(Guid userId)
    {
        return _configStore.Mutate(configuration =>
        {
            int removed = 0;

            // One loop over both protocols' providers (covariant Concat over the shared base). Skip a
            // provider stored with a null config object (reachable via #350); it holds no links to revoke,
            // and dereferencing it would NRE into a 500 — the same fail-closed skip TryGetLinks uses.
            foreach (var config in configuration.SamlConfigs.Values.Concat<ProviderConfigBase>(configuration.OidConfigs.Values))
            {
                if (config?.CanonicalLinks is { } links)
                {
                    removed += CanonicalLinkRevoker.RemoveUser(links, userId);
                }

                // Prune orphaned OpenID issuer entries (#186): after the revoke, any issuer keyed on a sub
                // no longer present in the links map is dead weight and must not linger to spuriously bind
                // (or refuse) a future re-link of that sub. SAML has no issuer map.
                if (config is OidConfig oid && oid.CanonicalLinks is { } liveLinks)
                {
                    foreach (var staleKey in oid.CanonicalLinkIssuers.Keys.Where(k => !liveLinks.ContainsKey(k)).ToList())
                    {
                        oid.CanonicalLinkIssuers.Remove(staleKey);
                    }
                }
            }

            return removed;
        });
    }

    // Whether any SAML or OpenID provider still holds a canonical link pointing at the user, read under the
    // caller's already-held config lock (#468). A provider stored with a null config object (reachable via
    // the null-body add, #350) holds no links and is skipped rather than dereferenced — the same fail-closed
    // treatment TryGetLinks / RemoveUserEverywhere give it. Short-circuits on the first match. Static and
    // parameterized on the live configuration so it composes inside an existing Read/Mutate transaction
    // without taking the lock again.
    private static bool UserHasAnyLink(PluginConfiguration configuration, Guid userId)
    {
        foreach (var config in configuration.SamlConfigs.Values.Concat<ProviderConfigBase>(configuration.OidConfigs.Values))
        {
            if (config?.CanonicalLinks is { } links && links.ContainsValue(userId))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Whether the SSO identity may still mint a session for the given user: the provider exists and is
    /// enabled, its canonical-links map still holds <paramref name="canonicalKey"/> pointing at
    /// <paramref name="userId"/>, and that user still exists. Read under the config lock, so it is
    /// linearized against a concurrent revocation (<see cref="RemoveUserEverywhere"/> /
    /// <see cref="TryRemoveLink"/>) or a mid-flight provider disable.
    /// </summary>
    /// <remarks>
    /// The in-flight revocation gate (#232): a login resolves the account under the config lock but the
    /// session mint runs after the lock is released, so an admin Unregister (or a link delete, or a
    /// provider disable) that lands in that gap would otherwise still mint a session for the just-revoked
    /// identity. The mint flow re-reads this predicate twice — before applying the user side effects (so a
    /// revoked login persists no grants) and again as the last check before the mint (so a revocation
    /// landing mid-mint still yields no session). The final check does not close the race outright — a
    /// revocation committing between it and the mint call still mints once — but it shrinks the window to
    /// that single unavoidable gap (the mint cannot be held under the lock, which is async). Every unknown
    /// resolves to false (missing/whitespace key, missing or disabled provider, missing/mismatched link,
    /// deleted target), so it is fail closed.
    /// </remarks>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the login authenticated against.</param>
    /// <param name="canonicalKey">The stable identity key the link is stored under (OpenID sub / SAML NameID).</param>
    /// <param name="userId">The Jellyfin user the login resolved to.</param>
    /// <returns>True only when a live, enabled link for this identity still points at the user.</returns>
    internal bool IsIdentityStillLinked(ProviderMode mode, string provider, string canonicalKey, Guid userId)
    {
        if (string.IsNullOrWhiteSpace(canonicalKey))
        {
            return false;
        }

        return _configStore.Read(configuration =>
            TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links)
            && links.TryGetValue(canonicalKey, out var linkedId)
            && linkedId == userId
            && _userManager.GetUserById(linkedId) != null);
    }

    // Atomically links canonicalKey to candidateUserId unless a live link already exists for it (#133).
    // The existence check and the write are ONE Mutate read-modify-write, so two concurrent first-logins
    // for the same identity cannot both write or both adopt: the loser observes the winner's link and
    // reports WroteLink=false (so the caller does not re-emit the adoption audit). The link write goes
    // straight into the config (no discarded ActionResult), so a failure to persist propagates rather
    // than falling through as a successful adoption.
    private (Guid EffectiveUserId, bool WroteLink) LinkCanonicalIfAbsent(ProviderMode mode, string provider, string canonicalKey, Guid candidateUserId, string issuer)
    {
        return _configStore.Mutate(configuration =>
        {
            // The login path resolved the provider before reaching here. If it was deleted or disabled
            // in the race since, fail CLOSED: refuse rather than return a session with no link written
            // (#373, #380). A freshly created user may be left orphaned, the same benign outcome as the
            // #133 race loser.
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links))
            {
                throw new AccountLinkForbiddenException("The SSO provider is no longer configured or is disabled; refusing to link an account.");
            }

            Guid? existing = links.TryGetValue(canonicalKey, out var current) && _userManager.GetUserById(current) != null
                ? current
                : (Guid?)null;

            var (effectiveUserId, wroteLink) = AccountLinkResolver.ResolveLinkWrite(existing, candidateUserId);
            if (wroteLink)
            {
                links[canonicalKey] = effectiveUserId;

                // A link written under this login carries this login's issuer (#186). The #133 race loser
                // (wroteLink == false) uses the winner's already-stamped link, so it stamps nothing.
                StampIssuerInPlace(configuration, mode, provider, canonicalKey, issuer);
            }

            return (effectiveUserId, wroteLink);
        });
    }

    // Re-keys a canonical link from the legacy username key to the stable subject key (#155) AND returns
    // the authoritative user id the identity now resolves to, in ONE config transaction (#363). The
    // caller resolved the candidates in an earlier lock acquisition, so folding the re-key and the
    // re-resolution into this single transaction — and having the caller bind to the returned id rather
    // than that earlier snapshot — removes the window a concurrent login could interpose in between the
    // snapshot and the re-key. Idempotent under concurrency: if the legacy key is already gone (a
    // concurrent login migrated first) the move is a no-op, and a LIVE subject key is never overwritten —
    // only a dangling one (its target user deleted), which would otherwise block the hand-off on every
    // subsequent login. Returns null only when neither key resolves a live account (the dangling edge), so
    // the login fails closed into the create/adopt gate rather than binding to a dead account.
    private Guid? MigrateAndResolveCanonicalLink(ProviderMode mode, string provider, string canonicalKey, string legacyKey, string issuer)
    {
        return _configStore.Mutate<Guid?>(configuration =>
        {
            // The candidate-resolving read passed the provider enabled; if it was deleted or disabled in
            // the window since, fail CLOSED: throw rather than no-op, because the caller would otherwise
            // bind to the pre-window legacy id and mint a session for a provider that no longer exists or
            // was just switched off (#373, #380).
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links))
            {
                throw new AccountLinkForbiddenException("The SSO provider is no longer configured or is disabled; refusing to migrate the account link.");
            }

            // Re-key only a legacy entry that still needs it: the subject key must be absent or dangling
            // (never overwrite a live subject link a concurrent login already established). When we re-key,
            // the identity now resolves subject-keyed to the legacy target, so that IS the authoritative id
            // — returning the moved value (rather than re-reading and filtering) preserves the prior
            // behaviour on the deleted-mid-migration race, where the caller bound to the legacy id and
            // failed closed downstream.
            if (links.TryGetValue(legacyKey, out var legacyUserId)
                && (!links.TryGetValue(canonicalKey, out var subjectUserId) || _userManager.GetUserById(subjectUserId) == null))
            {
                links.Remove(legacyKey);
                links[canonicalKey] = legacyUserId;

                // The re-keyed link is a fresh subject-keyed link written under THIS login, so stamp its
                // issuer (#186). The legacy key carried no issuer (it predates the store); the new key is
                // bound to the login that migrated it, matching the create/adopt write paths.
                StampIssuerInPlace(configuration, mode, provider, canonicalKey, issuer);
                return legacyUserId;
            }

            // Nothing to migrate: a concurrent login already re-keyed, or the legacy key is gone. Bind to
            // the authoritative subject link, treating a dangling one (target deleted) as absent.
            return links.TryGetValue(canonicalKey, out var live) && _userManager.GetUserById(live) != null
                ? live
                : (Guid?)null;
        });
    }

    // The provider's canonical-links map via TryGetValue rather than the throwing indexer, so an unknown
    // provider on the reachable admin link/unlink paths is a false return the caller maps to
    // UnknownProvider — finishing the #241 removal of KeyNotFoundException-as-control-flow. Returns true
    // and a non-null map only when the provider exists AND has a config object; a missing provider — or a
    // null-valued entry (reachable today via the null-body add, #350) — returns false, so the caller fails
    // closed (UnknownProvider on admin paths, a reject on login paths) instead of dereferencing null. With
    // requireEnabled, a DISABLED provider is treated like an absent one — every GRANT path (the login
    // guards and the link-create write) passes true so a provider disabled mid-flight is rejected exactly
    // like a deleted one (#380), while removal passes false because revoking must keep working on a
    // disabled provider (disable-then-clean-up). The map is
    // self-healing (CanonicalLinks lazily creates and stores it), so mutating the returned map persists
    // directly; callers must hold the config lock (Read / Mutate) while touching it. The mode is the typed
    // ProviderMode the controller parsed once at the HTTP boundary (#369), so both dispatch arms are reached
    // only with a validated value; the default throw stays as a belt against an out-of-range enum value.
    private static bool TryGetLinks(PluginConfiguration configuration, ProviderMode mode, string provider, bool requireEnabled, out SerializableDictionary<string, Guid> links)
    {
        switch (mode)
        {
            case ProviderMode.Saml:
                return TryGetLinks(configuration.SamlConfigs, provider, requireEnabled, out links);

            case ProviderMode.Oid:
                return TryGetLinks(configuration.OidConfigs, provider, requireEnabled, out links);

            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown provider mode.");
        }
    }

    // Generic over the provider config type (both maps hold ProviderConfigBase since #204), so the SAML
    // and OpenID arms are one body: a missing provider or a null-valued entry returns false; with
    // requireEnabled a disabled provider also returns false. Reads Enabled only after links != null has
    // proven config non-null.
    private static bool TryGetLinks<T>(SerializableDictionary<string, T> configs, string provider, bool requireEnabled, out SerializableDictionary<string, Guid> links)
        where T : ProviderConfigBase
    {
        var ok = configs.TryGetValue(provider, out var config);
        links = config?.CanonicalLinks;
        return ok && links != null && (!requireEnabled || config.Enabled);
    }

    // Classifies an OpenID subject link's issuer binding against the login's issuer, read under the caller's
    // config lock (#186). SAML (and any non-OID mode) is NotBound — issuer binding is OpenID only. For OID:
    // Absent when the link has no stored issuer yet (legacy/un-stamped, eligible for trust-on-first-use);
    // Match when the stored issuer ordinally equals the login's; Mismatch otherwise. A blank stored value is
    // treated as Absent (never written blank; defensive). The Mismatch arm INCLUDES the case where the login
    // carries no issuer while the link has one, so a token that omits `iss` cannot slip past a stamped
    // binding — fail closed.
    private static IssuerBinding ClassifyIssuer(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey, string issuer)
    {
        if (mode != ProviderMode.Oid)
        {
            return IssuerBinding.NotBound;
        }

        var stored = configuration.OidConfigs.TryGetValue(provider, out var config) && config?.CanonicalLinkIssuers is { } issuers
            && issuers.TryGetValue(canonicalKey, out var storedIssuer)
            ? storedIssuer
            : null;

        if (string.IsNullOrWhiteSpace(stored))
        {
            return IssuerBinding.Absent;
        }

        return string.Equals(stored, issuer, StringComparison.Ordinal) ? IssuerBinding.Match : IssuerBinding.Mismatch;
    }

    // Trust-on-first-use stamp of an OpenID link that has no stored issuer yet (#186), in its own config
    // transaction. OID-only and non-blank-issuer-only. Idempotent: writes only when the link still exists AND
    // its issuer is still absent, so a concurrent login that already stamped is not overwritten. A no-op for
    // SAML or a blank issuer (nothing safe to bind to) — the link stays un-stamped rather than binding to an
    // empty value.
    private void StampIssuer(ProviderMode mode, string provider, string canonicalKey, string issuer)
    {
        if (mode != ProviderMode.Oid || string.IsNullOrWhiteSpace(issuer))
        {
            return;
        }

        _configStore.Mutate(configuration =>
        {
            if (configuration.OidConfigs.TryGetValue(provider, out var config) && config?.CanonicalLinks is { } links
                && links.ContainsKey(canonicalKey)
                && !config.CanonicalLinkIssuers.ContainsKey(canonicalKey))
            {
                config.CanonicalLinkIssuers[canonicalKey] = issuer;
            }
        });
    }

    // Stamps (overwriting) an OpenID link's issuer within the caller's ALREADY-HELD config transaction (#186),
    // called right after a link WRITE (adopt / create / migrate / manual link) so the fresh link carries the
    // issuer it was minted under. Overwrites any stale value — a link just (re)written under this login belongs
    // to this login's issuer. A no-op for SAML or a blank issuer.
    private static void StampIssuerInPlace(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey, string issuer)
    {
        if (mode != ProviderMode.Oid || string.IsNullOrWhiteSpace(issuer))
        {
            return;
        }

        if (configuration.OidConfigs.TryGetValue(provider, out var config) && config is not null)
        {
            config.CanonicalLinkIssuers[canonicalKey] = issuer;
        }
    }

    // Drops an OpenID link's issuer entry within the caller's already-held config transaction (#186), called
    // alongside a link removal so the issuer map does not accumulate orphans. A no-op for SAML.
    private static void RemoveIssuer(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey)
    {
        if (mode == ProviderMode.Oid
            && configuration.OidConfigs.TryGetValue(provider, out var config)
            && config?.CanonicalLinkIssuers is { } issuers)
        {
            issuers.Remove(canonicalKey);
        }
    }

    // The result of the single under-lock candidate read: the subject-keyed link (if live), the legacy
    // username-keyed link (if live), and the subject link's issuer binding against the login (#186) — all
    // resolved in one locked pass so the orchestrator acts on a self-consistent snapshot.
    private readonly record struct ResolutionCandidates(Guid? SubjectLink, Guid? LegacyLink, IssuerBinding SubjectIssuer);
}

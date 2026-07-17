using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Data;
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
    private readonly IUserManager _userManager;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ProviderConfigStore _configStore;
    private readonly ILogger _logger;

    internal CanonicalLinkService(
        IUserManager userManager,
        ICryptoProvider cryptoProvider,
        ProviderConfigStore configStore,
        ILogger logger)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        _configStore = configStore ?? throw new ArgumentNullException(nameof(configStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Resolves the SSO login's stable identity to a Jellyfin user, creating or adopting the account per
    /// the provider's policy, and returns its id. Throws <see cref="AccountLinkForbiddenException"/> when
    /// the login must be refused (no identity resolved, or a pre-existing account may not be adopted).
    /// </summary>
    /// <param name="mode">The protocol mode token, "oid" or "saml".</param>
    /// <param name="provider">The provider the login authenticated against.</param>
    /// <param name="canonicalKey">The stable identity key (OpenID sub / SAML NameID).</param>
    /// <param name="username">The display name the account is provisioned/adopted under.</param>
    /// <param name="allowExistingAccountLink">Whether adopting a pre-existing unlinked account is permitted.</param>
    /// <param name="adoptionGate">
    /// The extra proof a same-named adoption must clear (#218): a privileged target is always refused, and
    /// when the gate requires a verified email the login must carry <c>email_verified == true</c>. Default
    /// (<see cref="AdoptionGate.None"/>) is the SAML/legacy posture: admin refusal only.
    /// </param>
    /// <returns>The resolved Jellyfin user id.</returns>
    internal async Task<Guid> ResolveOrCreateAsync(string mode, string provider, string canonicalKey, string username, bool allowExistingAccountLink, AdoptionGate adoptionGate = default)
    {
        // Defense in depth (#95, #155): a login that resolved no stable identity key (OpenID sub /
        // SAML NameID) or no username must never create, adopt, or look up an account. Both callbacks
        // reject such logins before calling here; this belt keeps the invariant if a caller forgets.
        if (string.IsNullOrWhiteSpace(canonicalKey) || string.IsNullOrWhiteSpace(username))
        {
            throw new AccountLinkForbiddenException("The SSO login did not resolve an identity; refusing to create or link an account.");
        }

        // The link is keyed on the stable identity. A legacy OpenID link (#155) was keyed on the
        // mutable username instead; when no subject-keyed link exists yet but a legacy one resolves,
        // adopt and re-key it, locking it to the subject so a later provider-side rename cannot
        // detach it. Because the legacy key is a name the identity provider controls, following it is
        // name-based account matching, so it honors AllowExistingAccountLink exactly like same-named
        // adoption below (#354): with the flag off, a login whose preferred_username points at another
        // user's entry is refused by the adoption gate instead of being handed that account. Even with
        // the flag on it is followed ONLY while the recorded target still bears the name (#361 below);
        // a target renamed away from it is not handed over on the strength of a stale name key.
        // Only OpenID differs key from name; SAML passes key == name.
        // Both candidates are read in ONE pass under the config lock: with separate reads, a
        // concurrent login's migration could commit between them, so this login would see the subject
        // key before the re-key and the legacy key after it, resolve neither, and bounce a legitimate
        // user off the adoption gate with a spurious 403. A link whose target user was deleted counts
        // as absent (dangling links are dead, not identities).
        var (subjectLink, legacyLink) = _configStore.Read(configuration =>
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
            return (bySubject, byName);
        });

        // The account currently bearing the display name, resolved once (outside the config lock — it is
        // a user-manager read, not a config read). It is both the same-name adoption candidate for the
        // Resolve gate below AND, when it IS the legacy link's target, the proof that following the legacy
        // username key is still true same-name matching rather than handing over an account that was
        // renamed away from this name (#361). A legacy link whose target no longer holds the name is left
        // for the terminal branches to label (a fresh-account orphan, or a reject), never followed.
        var existingAccount = _userManager.GetUserByName(username);
        Guid? existingAccountUserId = existingAccount?.Id;
        bool legacyNameStillHeldByTarget = legacyLink.HasValue && existingAccountUserId == legacyLink;

        var (linkedUserId, migrateLegacy) = AccountLinkResolver.ResolveCanonicalLink(subjectLink, legacyLink, legacyNameStillHeldByTarget, allowExistingAccountLink);
        if (migrateLegacy)
        {
            // The legacy re-key is name-based account matching too (#218): migration fires only when the
            // account currently bearing the name IS the legacy target (legacyNameStillHeldByTarget), so
            // that target is exactly existingAccount. Apply the admin refusal here as well — an attacker
            // presenting a new subject with a victim admin's preferred_username would otherwise re-key the
            // admin's legacy link onto their own subject and take the account over. Admin-only gate
            // (AdoptionGate.None): the verified-email requirement is deliberately not applied to the
            // re-key, which continues a relationship established under the pre-#155 scheme rather than
            // forming a new one. Link an admin account explicitly via the admin endpoint instead.
            if (AdoptionEligibilityResolver.Resolve(existingAccount!.HasPermission(PermissionKind.IsAdministrator), AdoptionGate.None) != AdoptionVerdict.Allow)
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: a legacy username-keyed link points at an administrator account, which is not adopted by name. Link it explicitly via the admin endpoints.",
                    username?.ReplaceLineEndings(string.Empty),
                    mode,
                    provider?.ReplaceLineEndings(string.Empty));
                throw new AccountLinkForbiddenException();
            }

            MigrateCanonicalLinkKey(mode, provider, username, canonicalKey);
            _logger.LogInformation(
                "Migrated {Mode}/{Provider} canonical link from the legacy username key to the stable subject key.",
                mode,
                provider?.ReplaceLineEndings(string.Empty));
        }

        // A legacy link that survives here un-migrated (flag off — or flag on but the name no longer
        // resolves to the recorded target, #354/#361) is not logged at this point: its terminal outcome
        // decides the right message. It splits into a refusal (the name is still taken) or a
        // fresh-account creation (the name was freed by a rename), and only the outcome
        // branch below can label it accurately — the fresh-account case is a SUCCESSFUL login that
        // silently orphans the original account, not a "refused" one, so a single pre-gate line would
        // mislabel exactly the event an operator most needs to see. Each terminal branch emits one
        // line (not deduplicated: a cross-request throttle would need process-wide state on this
        // per-request service, which would leak across tests), so during an upgrade window it is a
        // stream — enough to identify who still needs migrating, scanned expecting volume.

        // Adoption of a pre-existing unlinked account still matches on the display name resolved above.
        var decision = AccountLinkResolver.Resolve(linkedUserId, existingAccountUserId, allowExistingAccountLink);
        switch (decision.Action)
        {
            case AccountLinkAction.UseExistingLink:
                return decision.UserId;

            case AccountLinkAction.AdoptExistingAccount:
            {
                // Same-name adoption trusts the identity provider to make usernames unique and
                // non-reassignable (#218): a new principal asserting an existing user's name is otherwise
                // routed straight to that account. Before writing the link, clear the eligibility gate —
                // an administrator target is never adopted by name (link it explicitly via the admin
                // endpoint), and a provider that requires a verified email must have carried
                // email_verified == true. Fail closed: a refusal writes no link and emits no adoption
                // audit. existingAccount is non-null here (adoption is only chosen when a named account
                // resolved), so the admin read cannot NRE.
                var verdict = AdoptionEligibilityResolver.Resolve(
                    existingAccount!.HasPermission(PermissionKind.IsAdministrator),
                    adoptionGate);
                if (verdict != AdoptionVerdict.Allow)
                {
                    _logger.LogWarning(
                        "SSO login for {Name} via {Mode}/{Provider} refused adoption of a pre-existing account: {Reason}.",
                        username?.ReplaceLineEndings(string.Empty),
                        mode,
                        provider?.ReplaceLineEndings(string.Empty),
                        verdict);
                    throw new AccountLinkForbiddenException();
                }

                // Atomic check-then-link (#133): if a concurrent first-login already linked this
                // identity, that winner is used and no second write or duplicate audit occurs.
                var (adoptedUserId, wrote) = LinkCanonicalIfAbsent(mode, provider, canonicalKey, decision.UserId);
                if (wrote)
                {
                    SsoAudit.AccountAdopted(_logger, string.Equals(mode, "oid", StringComparison.Ordinal) ? "OpenID" : "SAML", provider, username);
                }

                return adoptedUserId;
            }

            case AccountLinkAction.CreateNewAccount:
            {
                if (legacyLink.HasValue)
                {
                    // The dangerous, previously-silent case (#354/#361): a legacy username-keyed link
                    // exists and its target still exists, but no live account bears the name anymore (the
                    // account was renamed on the Jellyfin side), so the legacy link was NOT followed —
                    // whether adoption is off, or on but the name no longer resolves to the recorded target
                    // (#361, the stale-name superset the flag-on arm used to hand over). We are about to
                    // provision a FRESH account under this subject, leaving the original — the one the
                    // legacy key points at — orphaned from this identity. This warning is the single
                    // observable signal of that outcome; recover by linking the original account to this
                    // subject via the admin endpoints. See the upgrade runbook in providers.md.
                    _logger.LogWarning(
                        "SSO login for {Name} via {Mode}/{Provider}: a legacy username-keyed link exists but no live account bears the name (it was renamed on the Jellyfin side), so a fresh account is being provisioned and the original account is now orphaned. Re-link it to this subject via the admin endpoints.",
                        username?.ReplaceLineEndings(string.Empty),
                        mode,
                        provider?.ReplaceLineEndings(string.Empty));
                }

                _logger.LogInformation("SSO user {Name} doesn't exist, creating...", username?.ReplaceLineEndings(string.Empty));
                var user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
                user.AuthenticationProviderId = typeof(SSOController).FullName;
                // https://jonathancrozier.com/blog/how-to-generate-a-cryptographically-secure-random-string-in-dot-net-with-c-sharp
                user.Password = _cryptoProvider.CreatePasswordHash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))).ToString();

                // Atomic check-then-link (#133): if a concurrent first-login for the same identity
                // linked meanwhile, use its account — this freshly created user is left unlinked rather
                // than overwriting the winner's link (a rare, benign orphan, not a duplicate login).
                var (effectiveUserId, _) = LinkCanonicalIfAbsent(mode, provider, canonicalKey, user.Id);
                return effectiveUserId;
            }

            case AccountLinkAction.RejectNameTaken:
                if (legacyLink.HasValue)
                {
                    // Refused, but specifically because a legacy username-keyed link (#354) is pending
                    // and a live account still bears the name — the migratable case, distinct from an
                    // ordinary #95 name collision. One line, so the reject path is not double-logged.
                    _logger.LogWarning(
                        "SSO login for {Name} via {Mode}/{Provider} refused: a legacy username-keyed link is pending but AllowExistingAccountLink is off and a live account still bears the name. Enable AllowExistingAccountLink (a short controlled window) or link the account via the admin endpoints to migrate it.",
                        username?.ReplaceLineEndings(string.Empty),
                        mode,
                        provider?.ReplaceLineEndings(string.Empty));
                }
                else
                {
                    _logger.LogWarning(
                        "SSO login for {Name} via {Mode}/{Provider} refused: a pre-existing unlinked Jellyfin account exists and AllowExistingAccountLink is disabled for this provider.",
                        username?.ReplaceLineEndings(string.Empty),
                        mode,
                        provider?.ReplaceLineEndings(string.Empty));
                }

                throw new AccountLinkForbiddenException();

            default:
                throw new InvalidOperationException($"Unhandled account-link action: {decision.Action}");
        }
    }

    /// <summary>
    /// Creates a manual canonical link (admin/self linking) from a provider-side identity to a Jellyfin
    /// user, under the config lock. HTTP-free: the controller maps the returned result to a response.
    /// </summary>
    /// <param name="mode">The protocol mode token, "oid" or "saml".</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="providerUserId">The provider-side identity key (OpenID sub / SAML NameID).</param>
    /// <param name="jellyfinUserId">The Jellyfin user to link the identity to.</param>
    /// <returns>The write outcome.</returns>
    internal CanonicalLinkWriteResult TryCreateLink(string mode, string provider, string providerUserId, Guid jellyfinUserId)
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
            return CanonicalLinkWriteResult.Created;
        });
    }

    /// <summary>
    /// Removes a manual canonical link, but only when it is registered to the given Jellyfin user, under
    /// the config lock. HTTP-free: the controller maps the returned result to a response. The find,
    /// ownership check, and removal are one read-modify-write so they cannot interleave with a concurrent
    /// write to the same map.
    /// </summary>
    /// <param name="mode">The protocol mode token, "oid" or "saml".</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="canonicalName">The provider-side identity key whose link is removed.</param>
    /// <param name="jellyfinUserId">The Jellyfin user the link must belong to.</param>
    /// <returns>The remove outcome.</returns>
    internal CanonicalLinkRemoveResult TryRemoveLink(string mode, string provider, string canonicalName, Guid jellyfinUserId)
    {
        // Kept as ONE Mutate (find, ownership check, and remove cannot interleave). A no-result outcome
        // still persists the unchanged config. For NotFound / Mismatch that already matched the old
        // controller code (its mutate callback ran to completion and persisted a no-op); for
        // UnknownProvider it is a deliberate small delta — the old code threw KeyNotFoundException out of
        // the callback before the persist, so the unknown-provider DELETE did not write, whereas this
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
                return CanonicalLinkRemoveResult.UnknownProvider;
            }

            if (!links.TryGetValue(canonicalName, out var linkedId))
            {
                return CanonicalLinkRemoveResult.NotFound;
            }

            if (linkedId != jellyfinUserId)
            {
                return CanonicalLinkRemoveResult.Mismatch;
            }

            links.Remove(canonicalName);
            return CanonicalLinkRemoveResult.Removed;
        });
    }

    /// <summary>
    /// Projects, for one protocol, a provider -> [canonical keys linked to this user] map, materialized
    /// under the config lock. Each provider's matches are realized with <c>ToList</c> (#157/F-10) so the
    /// result is a detached snapshot that cannot tear against a concurrent login writing a link during
    /// JSON serialization.
    /// </summary>
    /// <param name="mode">The protocol mode token, "oid" or "saml".</param>
    /// <param name="jellyfinUserId">The Jellyfin user whose links are listed.</param>
    /// <returns>A provider -> link-key-list map.</returns>
    internal SerializableDictionary<string, IEnumerable<string>> LinksByUser(string mode, Guid jellyfinUserId)
    {
        return _configStore.Read(configuration =>
        {
            // Both arms project (name, links) tuples through ProviderConfigBase.CanonicalLinks, so the
            // per-mode twin queries are one shape. A provider stored with a null config object (reachable
            // today via #350's null-body add) yields null links and is skipped rather than dereferenced —
            // same fail-closed treatment TryGetLinks gives it, so the read side cannot NRE into a 500 on
            // a state the write side can produce.
            var providerLinks = string.Equals(mode, "saml", StringComparison.Ordinal)
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
            }

            return removed;
        });
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
    /// <param name="mode">The protocol mode token, "oid" or "saml".</param>
    /// <param name="provider">The provider the login authenticated against.</param>
    /// <param name="canonicalKey">The stable identity key the link is stored under (OpenID sub / SAML NameID).</param>
    /// <param name="userId">The Jellyfin user the login resolved to.</param>
    /// <returns>True only when a live, enabled link for this identity still points at the user.</returns>
    internal bool IsIdentityStillLinked(string mode, string provider, string canonicalKey, Guid userId)
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
    private (Guid EffectiveUserId, bool WroteLink) LinkCanonicalIfAbsent(string mode, string provider, string canonicalKey, Guid candidateUserId)
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
            }

            return (effectiveUserId, wroteLink);
        });
    }

    // Re-keys a canonical link from oldKey to newKey inside the config lock (#155 legacy migration).
    // Idempotent under concurrency: if oldKey is already gone (a concurrent login migrated first) the
    // move is a no-op, and a LIVE newKey entry is never overwritten — only a dangling one (its target
    // user deleted), which would otherwise block the hand-off on every subsequent login.
    private void MigrateCanonicalLinkKey(string mode, string provider, string oldKey, string newKey)
    {
        _configStore.Mutate(configuration =>
        {
            // Migration is a SECOND transaction after the candidate-resolving read. If the provider was
            // deleted or disabled in that window, fail CLOSED: throw rather than no-op, because the
            // caller still holds the legacy user id from the pre-deletion snapshot and would otherwise
            // return UseExistingLink, minting a session for a provider that no longer exists or was just
            // switched off (#373, #380).
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links))
            {
                throw new AccountLinkForbiddenException("The SSO provider is no longer configured or is disabled; refusing to migrate the account link.");
            }

            // A no-op here (unlike the throwing miss above) is the GOOD idempotent case: the provider
            // still exists but oldKey was already re-keyed by a concurrent login, or newKey is live. The
            // never-overwrite-a-live-newKey rule is on the method summary.
            if (links.TryGetValue(oldKey, out var userId)
                && (!links.TryGetValue(newKey, out var existing) || _userManager.GetUserById(existing) == null))
            {
                links.Remove(oldKey);
                links[newKey] = userId;
            }
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
    // directly; callers must hold the config lock (Read / Mutate) while touching it. An unrecognized mode
    // is not an unknown provider but a caller contract violation, so it throws — note the DELETE route
    // forwards mode unvalidated (unlike the AddCanonicalLink dispatch), so that throw is reachable there;
    // #369 tracks parsing mode once at the HTTP boundary into an internal enum.
    private static bool TryGetLinks(PluginConfiguration configuration, string mode, string provider, bool requireEnabled, out SerializableDictionary<string, Guid> links)
    {
        switch (mode.ToLowerInvariant())
        {
            case "saml":
                return TryGetLinks(configuration.SamlConfigs, provider, requireEnabled, out links);

            case "oid":
                return TryGetLinks(configuration.OidConfigs, provider, requireEnabled, out links);

            default:
                throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'");
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
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
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
    /// <returns>The resolved Jellyfin user id.</returns>
    internal async Task<Guid> ResolveOrCreateAsync(string mode, string provider, string canonicalKey, string username, bool allowExistingAccountLink)
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
        // user's entry is refused by the adoption gate instead of being handed that account.
        // Only OpenID differs key from name; SAML passes key == name.
        // Both candidates are read in ONE pass under the config lock: with separate reads, a
        // concurrent login's migration could commit between them, so this login would see the subject
        // key before the re-key and the legacy key after it, resolve neither, and bounce a legitimate
        // user off the adoption gate with a spurious 403. A link whose target user was deleted counts
        // as absent (dangling links are dead, not identities).
        var (subjectLink, legacyLink) = _configStore.Read(configuration =>
        {
            // The login callbacks resolve the provider before calling, so it is normally present. If it
            // was deleted in the race between that lookup and here, fail CLOSED: refuse rather than fall
            // through to the adoption gate, whose create/adopt arms would otherwise mint a session for a
            // provider that no longer exists (a missing provider must never default the login to valid).
            if (!TryGetLinks(configuration, mode, provider, out var links))
            {
                throw new AccountLinkForbiddenException("The SSO provider is no longer configured; refusing to resolve or create an account.");
            }

            Guid? bySubject = links.TryGetValue(canonicalKey, out var s) && _userManager.GetUserById(s) != null
                ? s : null;
            Guid? byName = bySubject is null
                && !string.Equals(canonicalKey, username, StringComparison.Ordinal)
                && links.TryGetValue(username, out var n) && _userManager.GetUserById(n) != null
                ? n : (Guid?)null;
            return (bySubject, byName);
        });

        var (linkedUserId, migrateLegacy) = AccountLinkResolver.ResolveCanonicalLink(subjectLink, legacyLink, allowExistingAccountLink);
        if (migrateLegacy)
        {
            MigrateCanonicalLinkKey(mode, provider, username, canonicalKey);
            _logger.LogInformation(
                "Migrated {Mode}/{Provider} canonical link from the legacy username key to the stable subject key.",
                mode,
                provider?.ReplaceLineEndings(string.Empty));
        }

        // A legacy link that survives here un-migrated (flag off, #354) is not logged at this point:
        // its terminal outcome decides the right message. It splits into a refusal (the name is still
        // taken) or a fresh-account creation (the name was freed by a rename), and only the outcome
        // branch below can label it accurately — the fresh-account case is a SUCCESSFUL login that
        // silently orphans the original account, not a "refused" one, so a single pre-gate line would
        // mislabel exactly the event an operator most needs to see. Each terminal branch emits one
        // line (not deduplicated: a cross-request throttle would need process-wide state on this
        // per-request service, which would leak across tests), so during an upgrade window it is a
        // stream — enough to identify who still needs migrating, scanned expecting volume.

        // Adoption of a pre-existing unlinked account still matches on the display name.
        Guid? existingAccountUserId = _userManager.GetUserByName(username)?.Id;

        var decision = AccountLinkResolver.Resolve(linkedUserId, existingAccountUserId, allowExistingAccountLink);
        switch (decision.Action)
        {
            case AccountLinkAction.UseExistingLink:
                return decision.UserId;

            case AccountLinkAction.AdoptExistingAccount:
            {
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
                    // The dangerous, previously-silent case (#354): a legacy username-keyed link exists,
                    // the flag is off so it was not followed, AND no live account bears the name anymore
                    // (the account was renamed on the Jellyfin side). We are about to provision a FRESH
                    // account under this subject, leaving the original — the one the legacy key points at
                    // — permanently orphaned. This warning is the single observable signal of that
                    // irreversible outcome; recover by linking the original account to this subject via
                    // the admin endpoints, or enable AllowExistingAccountLink before the next login. See
                    // the upgrade runbook in providers.md.
                    _logger.LogWarning(
                        "SSO login for {Name} via {Mode}/{Provider}: a legacy username-keyed link exists but AllowExistingAccountLink is off and no live account bears the name, so a fresh account is being provisioned and the original account is now orphaned. Re-link it to this subject via the admin endpoints (or enable AllowExistingAccountLink before the next login).",
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
            if (!TryGetLinks(configuration, mode, provider, out var links))
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
        // (UnknownProvider / NotFound / Mismatch) still persists the unchanged config, the uniform
        // Mutate behavior every no-op write already has (RemoveUserEverywhere of zero, the
        // LinkCanonicalIfAbsent race loser); the response is identical either way. A read-probe-then-
        // mutate would avoid the write but reintroduce the resolve/act race this deliberately excludes.
        return _configStore.Mutate(configuration =>
        {
            if (!TryGetLinks(configuration, mode, provider, out var links))
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
            var providerList = string.Equals(mode, "saml", StringComparison.Ordinal)
                ? (IEnumerable<KeyValuePair<string, SerializableDictionary<string, Guid>>>)configuration.SamlConfigs.Select(p => new KeyValuePair<string, SerializableDictionary<string, Guid>>(p.Key, p.Value.CanonicalLinks))
                : configuration.OidConfigs.Select(p => new KeyValuePair<string, SerializableDictionary<string, Guid>>(p.Key, p.Value.CanonicalLinks));

            var mappings = new SerializableDictionary<string, IEnumerable<string>>();
            foreach (var provider in providerList)
            {
                mappings[provider.Key] = provider.Value
                    .Where(link => link.Value == jellyfinUserId)
                    .Select(link => link.Key)
                    .ToList();
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
            foreach (var config in configuration.SamlConfigs.Values)
            {
                removed += CanonicalLinkRevoker.RemoveUser(config.CanonicalLinks, userId);
            }

            foreach (var config in configuration.OidConfigs.Values)
            {
                removed += CanonicalLinkRevoker.RemoveUser(config.CanonicalLinks, userId);
            }

            return removed;
        });
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
            // The login path resolved the provider before reaching here. If it was deleted in the race
            // since, fail CLOSED: refuse rather than return a session with no link written. A freshly
            // created user may be left orphaned, the same benign outcome as the #133 race loser.
            if (!TryGetLinks(configuration, mode, provider, out var links))
            {
                throw new AccountLinkForbiddenException("The SSO provider is no longer configured; refusing to link an account.");
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
            // deleted in that window, fail CLOSED: throw rather than no-op, because the caller still
            // holds the legacy user id from the pre-deletion snapshot and would otherwise return
            // UseExistingLink, minting a session for a provider that no longer exists (#373).
            if (!TryGetLinks(configuration, mode, provider, out var links))
            {
                throw new AccountLinkForbiddenException("The SSO provider is no longer configured; refusing to migrate the account link.");
            }

            // A no-op here is the GOOD idempotent case (the provider still exists): oldKey is already
            // gone because a concurrent login migrated first, or newKey is live. Never overwrite a live
            // newKey — only a dangling one (its target user deleted), which would otherwise block the
            // hand-off on every subsequent login.
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
    // and the map when the provider exists; false with a null map when it does not. The map is
    // self-healing (CanonicalLinks lazily creates and stores it), so mutating the returned map persists
    // directly; callers must hold the config lock (Read / Mutate) while touching it. An invalid mode is a
    // programming error (the endpoints dispatch on it) rather than an unknown provider, so it throws.
    private static bool TryGetLinks(PluginConfiguration configuration, string mode, string provider, out SerializableDictionary<string, Guid> links)
    {
        switch (mode.ToLowerInvariant())
        {
            case "saml":
            {
                var ok = configuration.SamlConfigs.TryGetValue(provider, out var config);
                links = config?.CanonicalLinks;
                return ok;
            }

            case "oid":
            {
                var ok = configuration.OidConfigs.TryGetValue(provider, out var config);
                links = config?.CanonicalLinks;
                return ok;
            }

            default:
                throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'");
        }
    }
}

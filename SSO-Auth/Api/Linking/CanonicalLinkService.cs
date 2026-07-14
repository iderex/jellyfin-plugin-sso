using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api;

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
            var links = LinksFor(configuration, mode, provider);
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
        else if (legacyLink.HasValue)
        {
            // The legacy candidate only survives to here un-migrated when the flag is off (#354).
            // After an upgrade from a username-keyed version this breadcrumb separates "migration
            // pending — enable AllowExistingAccountLink" from an ordinary name-taken refusal. It is
            // one line per refused attempt (not deduplicated: a working cross-request throttle would
            // need process-wide state on this per-request service, which would leak across tests), so
            // during the upgrade window it is a stream, not a single alert — enough to identify who
            // still needs migrating, but scan it expecting volume.
            _logger.LogWarning(
                "SSO login for {Name} via {Mode}/{Provider}: a legacy username-keyed link exists but AllowExistingAccountLink is disabled for this provider; the link is not followed or migrated. Enable AllowExistingAccountLink (or link the account via the admin endpoints) to migrate it.",
                username.ReplaceLineEndings(string.Empty),
                mode,
                provider?.ReplaceLineEndings(string.Empty));
        }

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
                _logger.LogInformation("SSO user {Name} doesn't exist, creating...", username.ReplaceLineEndings(string.Empty));
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
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: a pre-existing unlinked Jellyfin account exists and AllowExistingAccountLink is disabled for this provider.",
                    username.ReplaceLineEndings(string.Empty),
                    mode,
                    provider?.ReplaceLineEndings(string.Empty));
                throw new AccountLinkForbiddenException();

            default:
                throw new InvalidOperationException($"Unhandled account-link action: {decision.Action}");
        }
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
            var links = LinksFor(configuration, mode, provider);
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
            var links = LinksFor(configuration, mode, provider);
            if (links.TryGetValue(oldKey, out var userId)
                && (!links.TryGetValue(newKey, out var existing) || _userManager.GetUserById(existing) == null))
            {
                links.Remove(oldKey);
                links[newKey] = userId;
            }
        });
    }

    // The provider's canonical-links map; callers must hold the config lock (Read / Mutate) while
    // touching it. The map is self-healing (CanonicalLinks lazily creates and stores it), so mutating
    // the returned map persists directly. The provider is always present on the paths that reach here
    // (the login callbacks resolved it first); a guarded accessor for the reachable-unknown-provider
    // admin paths, finishing the #241 KeyNotFoundException removal, lands with those endpoints.
    private static SerializableDictionary<string, Guid> LinksFor(PluginConfiguration configuration, string mode, string provider)
    {
        return mode.ToLowerInvariant() switch
        {
            "saml" => configuration.SamlConfigs[provider].CanonicalLinks,
            "oid" => configuration.OidConfigs[provider].CanonicalLinks,
            _ => throw new ArgumentException($"{mode} is not a valid choice between 'saml' and 'oid'"),
        };
    }
}

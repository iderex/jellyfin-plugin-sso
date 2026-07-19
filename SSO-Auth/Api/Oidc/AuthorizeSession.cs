using System;
using Duende.IdentityModel.OidcClient;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The in-flight OpenID authorize state as a closed, immutable sum of two variants: a
/// <see cref="Pending"/> registered at the challenge, atomically swapped for a <see cref="Ready"/> at
/// the callback once the role gate passes (#341). Which variant the store holds IS the "role gate
/// passed" fact — there is no mutable validity flag, and there is no in-place field copy, so a
/// redeemer racing the promotion observes either the whole <see cref="Pending"/> (never redeemable)
/// or the whole <see cref="Ready"/>, never a half-applied field set. The hierarchy is closed by a
/// private constructor: only the two nested variants can derive from it (#318).
/// </summary>
internal abstract class AuthorizeSession
{
    // Private so the sum is closed to exactly the two nested variants below: a nested type can call the
    // enclosing type's private constructor through base(...), but no other type — in this assembly or
    // any other — can introduce a third variant.
    private AuthorizeSession(string token, string provider, bool isLinking, string bindingId, string clientKey, DateTime created)
    {
        Token = token;
        Provider = provider;
        IsLinking = isLinking;
        BindingId = bindingId;
        ClientKey = clientKey;
        Created = created;
    }

    /// <summary>Gets the CSPRNG authorize-state token that keys the entry (the value the callback presents).</summary>
    internal string Token { get; }

    /// <summary>
    /// Gets the provider that minted this state. A state may only be consumed on the same provider's
    /// endpoints, so it cannot be replayed against another provider's login/role gate.
    /// </summary>
    internal string Provider { get; }

    /// <summary>Gets a value indicating whether this flow is a linking request rather than a login.</summary>
    internal bool IsLinking { get; }

    /// <summary>
    /// Gets the browser-binding id (#326): the challenge records a fresh random id here and hands the same
    /// value to the browser as a cookie, so a state started in one browser cannot be completed in another.
    /// </summary>
    internal string BindingId { get; }

    /// <summary>
    /// Gets the normalized client key that reserved this state's per-client budget slot (#327), or null for
    /// an unattributable/exempt source; recorded so the store releases the right client's slot on redeem or prune.
    /// </summary>
    internal string ClientKey { get; }

    /// <summary>Gets when this state was created, used to time it out.</summary>
    internal DateTime Created { get; }

    /// <summary>
    /// The challenge-time variant: it carries everything the callback's token exchange needs (the
    /// OidcClient authorize state, the reused discovery metadata, the RFC 9207 response-iss requirement)
    /// but none of the derived identity or privileges — so holding a <see cref="Pending"/> structurally
    /// cannot mint a session. Immutable: every field is set at construction (#341).
    /// </summary>
    internal sealed class Pending : AuthorizeSession
    {
        internal Pending(
            AuthorizeState oidcState,
            string provider,
            bool isLinking,
            DateTime created,
            string bindingId,
            string clientKey,
            ProviderInformation providerInformation,
            bool responseIssuerRequired)
            : base(oidcState.State, provider, isLinking, bindingId, clientKey, created)
        {
            OidcState = oidcState;
            ProviderInformation = providerInformation;
            ResponseIssuerRequired = responseIssuerRequired;
        }

        /// <summary>Gets the OidcClient authorize state (code_verifier, redirect URI) for the token exchange.</summary>
        internal AuthorizeState OidcState { get; }

        /// <summary>
        /// Gets the challenge's already-validated OpenID discovery metadata to reuse at the callback (#247),
        /// or null when the challenge never captured it (the callback then runs a fresh discovery).
        /// </summary>
        internal ProviderInformation ProviderInformation { get; }

        /// <summary>
        /// Gets a value indicating whether the authorization server advertised the RFC 9207
        /// authorization-response <c>iss</c> parameter, so the callback must require <c>iss</c> (#210).
        /// </summary>
        internal bool ResponseIssuerRequired { get; }
    }

    /// <summary>
    /// The callback-time variant: an immutable snapshot of the redeemed identity and privileges, produced
    /// only from a passed role gate. Its existence in the store is the evidence that the login is valid —
    /// <see cref="OidcStateStore.TryRedeem"/> is the only code that hands one out, and only after the
    /// one-time atomic claim, so code taking a <see cref="Ready"/> cannot run before that claim (#318, #341).
    /// </summary>
    internal sealed class Ready : AuthorizeSession
    {
        internal Ready(Pending pending, OidcAuthorizeStateBuilder.OidcAuthorizeState derived)
            : base(pending.Token, pending.Provider, pending.IsLinking, pending.BindingId, pending.ClientKey, pending.Created)
        {
            // The role gate has passed, so this is exactly the point at which an OpenID login becomes a
            // fully-verified identity (#473): fold the derived result into the one protocol-agnostic
            // VerifiedIdentity the mint path is keyed on. Building it here — inside the variant the store
            // only ever produces for a promoted state and only hands out through the one-time atomic
            // redeem — is what makes this the OpenID construction site the keystone's contract names.
            Identity = VerifiedIdentity.FromOidcRedemption(pending.Provider, derived);
        }

        /// <summary>
        /// Gets the fully-verified identity and privileges of the redeemed OpenID login (#473). This is
        /// the sole payload of a <see cref="Ready"/>: holding one is the evidence the login passed the role
        /// gate, and it is what <see cref="OidcStateStore.TryRedeem"/> feeds into the shared mint path.
        /// </summary>
        internal VerifiedIdentity Identity { get; }
    }
}

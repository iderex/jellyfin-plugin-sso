using Duende.IdentityModel.OidcClient;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Evidence that the OpenID callback's state token was found current for its provider —
/// <see cref="OidcStateStore.PeekCurrent"/> is the only production constructor. Distinct from
/// <see cref="RedeemedState"/> by design: holding a peek structurally cannot mint a session (#318).
/// </summary>
internal sealed class PendingState
{
    private readonly TimedAuthorizeState _entry;

    internal PendingState(TimedAuthorizeState entry) => _entry = entry;

    /// <summary>Gets the OidcClient authorize state (code_verifier, redirect URI) for the token exchange.</summary>
    internal AuthorizeState OidcState => _entry.State;

    /// <summary>
    /// Gets the challenge's already-validated OpenID discovery metadata to reuse at the callback (#247),
    /// or null when the state predates the capture (the callback then does a fresh discovery).
    /// </summary>
    internal ProviderInformation ProviderInformation => _entry.ProviderInformation;

    /// <summary>Gets a value indicating whether this flow is a linking request rather than a login.</summary>
    internal bool IsLinking => _entry.IsLinking;

    /// <summary>
    /// Applies the verified login's derived values (username, validity, admin, Live TV, folders,
    /// avatar) to the stored state, whose derivation fields are still at their defaults at this
    /// point — the only production write of <see cref="TimedAuthorizeState.Valid"/>, and only from
    /// the builder's role-gate result. This is today's in-place pending-to-ready promotion on the
    /// shared stored instance; the atomic variant swap is the AuthorizeSession follow-up (#318).
    /// </summary>
    /// <param name="derived">The role-gate result to copy onto the stored state.</param>
    internal void Complete(OidcAuthorizeStateBuilder.OidcAuthorizeState derived)
    {
        _entry.Username = derived.Username;
        _entry.Subject = derived.Subject;
        _entry.Valid = derived.Valid;
        _entry.Admin = derived.Admin;
        _entry.EnableLiveTv = derived.EnableLiveTv;
        _entry.EnableLiveTvManagement = derived.EnableLiveTvManagement;
        _entry.Folders = derived.Folders;
        _entry.AvatarURL = derived.AvatarUrl;
    }
}

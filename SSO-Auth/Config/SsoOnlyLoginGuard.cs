using System;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Why a break-glass admin does (or does not) satisfy the survivor guard. A reason CODE, never a username
/// or roster — the public refusal message is deliberately singular and non-enumerating (T-I1), so these
/// verdicts exist only for the unit tests and the audit trail.
/// </summary>
internal enum SsoOnlyGuardVerdict
{
    /// <summary>The designated account is an enabled administrator with a working password login — activation is safe.</summary>
    Allow,

    /// <summary>No break-glass admin was designated (blank username).</summary>
    NoBreakGlassDesignated,

    /// <summary>The designated username resolves to no account.</summary>
    BreakGlassNotFound,

    /// <summary>The designated account is not an administrator (the exemption cannot grant admin).</summary>
    BreakGlassNotAdministrator,

    /// <summary>The designated administrator is disabled, so it cannot log in.</summary>
    BreakGlassDisabled,

    /// <summary>The designated administrator has no usable password login path (wrong provider routing or no password).</summary>
    BreakGlassNoPasswordLogin,
}

/// <summary>
/// The resolved login state of a candidate break-glass administrator, snapshotted from
/// <c>IUserManager</c> so the guard predicate stays pure and unit-testable (the controller resolves the
/// account and fills this in; the guard never touches Jellyfin services). Every field must hold for the
/// account to be a valid break-glass admin — the single always-available password door SSO-only leaves
/// open (SSO-ONLY-LOGIN-DESIGN.md §3 option A).
/// </summary>
/// <param name="Exists">Whether an account with the designated username exists at all.</param>
/// <param name="IsAdministrator">Whether that account holds <c>PermissionKind.IsAdministrator</c> (the exemption may only spare an EXISTING admin, never grant admin — T-E1).</param>
/// <param name="IsEnabled">Whether the account is enabled (not <c>PermissionKind.IsDisabled</c>).</param>
/// <param name="HasUsablePasswordLogin">Whether the account currently routes to Jellyfin's password provider AND has a non-empty stored password — i.e. it can actually log in without SSO.</param>
internal readonly record struct BreakGlassAdminState(bool Exists, bool IsAdministrator, bool IsEnabled, bool HasUsablePasswordLogin);

/// <summary>
/// The fail-closed activation interlock for SSO-only login (#165), in the style of
/// <see cref="ProviderConfigValidator"/>: it refuses to let <c>DisablePasswordLogin</c> be turned on unless
/// a working non-SSO administrator login path is provable — canonically a designated, enabled
/// administrator account that still has a password (the break-glass admin). Pure and side-effect-free: the
/// caller resolves the account state into a <see cref="BreakGlassAdminState"/> and this decides. The
/// success criterion the whole feature rests on is that no reachable configuration can leave zero working
/// admin logins (SSO-ONLY-LOGIN-DESIGN.md §3).
/// </summary>
internal static class SsoOnlyLoginGuard
{
    /// <summary>
    /// The single, actionable, non-enumerating refusal message every rejected activation surfaces (T-I1):
    /// it names the reason and the fix without leaking which accounts are admins or their login state.
    /// </summary>
    internal const string PublicRefusalMessage =
        "Cannot enable SSO-only login: no administrator would keep a working password login path. Designate an existing, enabled administrator account that still has a password as the break-glass admin first.";

    /// <summary>
    /// Classifies whether the resolved break-glass admin satisfies the survivor guard. Fail-closed by
    /// construction: every missing condition (no designation, no such account, not an admin, disabled, no
    /// usable password) is its own refusal verdict; only a fully-qualified break-glass admin returns
    /// <see cref="SsoOnlyGuardVerdict.Allow"/>. An SSO link is deliberately NOT accepted as the survivor —
    /// its usability depends on the IdP being up, which is exactly what fails in the lockout scenario
    /// (SSO-ONLY-LOGIN-DESIGN.md §3, T-D3).
    /// </summary>
    /// <param name="breakGlassUsername">The designated break-glass admin username (may be blank).</param>
    /// <param name="breakGlass">The resolved login state of that account.</param>
    /// <returns>The guard verdict.</returns>
    internal static SsoOnlyGuardVerdict Evaluate(string breakGlassUsername, BreakGlassAdminState breakGlass)
    {
        if (string.IsNullOrWhiteSpace(breakGlassUsername))
        {
            return SsoOnlyGuardVerdict.NoBreakGlassDesignated;
        }

        if (!breakGlass.Exists)
        {
            return SsoOnlyGuardVerdict.BreakGlassNotFound;
        }

        if (!breakGlass.IsAdministrator)
        {
            return SsoOnlyGuardVerdict.BreakGlassNotAdministrator;
        }

        if (!breakGlass.IsEnabled)
        {
            return SsoOnlyGuardVerdict.BreakGlassDisabled;
        }

        if (!breakGlass.HasUsablePasswordLogin)
        {
            return SsoOnlyGuardVerdict.BreakGlassNoPasswordLogin;
        }

        return SsoOnlyGuardVerdict.Allow;
    }

    /// <summary>
    /// Throws a fail-closed, non-enumerating <see cref="ArgumentException"/> (mirroring
    /// <see cref="ProviderConfigValidator"/>) when the resolved break-glass admin does not satisfy the
    /// guard, so an unsafe activation is rejected before anything is persisted. A no-op when the account
    /// qualifies.
    /// </summary>
    /// <param name="breakGlassUsername">The designated break-glass admin username.</param>
    /// <param name="breakGlass">The resolved login state of that account.</param>
    /// <exception cref="ArgumentException">The activation would strand the last admin.</exception>
    internal static void AssertCanActivate(string breakGlassUsername, BreakGlassAdminState breakGlass)
    {
        if (Evaluate(breakGlassUsername, breakGlass) != SsoOnlyGuardVerdict.Allow)
        {
            throw new ArgumentException(PublicRefusalMessage, nameof(breakGlassUsername));
        }
    }

    /// <summary>
    /// Whether SSO-only enforcement applies to the account with the given username: the mode is on and the
    /// account is NOT the designated break-glass admin. The single predicate the activation sweep, the
    /// login-path re-assertion, and the disable-side skip all share, so "the break-glass admin is never
    /// repointed" is defined once. Username comparison is ordinal-ignore-case to match Jellyfin's
    /// case-insensitive account names.
    /// </summary>
    /// <param name="configuration">The live plugin configuration.</param>
    /// <param name="username">The account username under consideration.</param>
    /// <returns>True when the account must be kept off the password provider.</returns>
    internal static bool IsEnforcedNonExempt(PluginConfiguration configuration, string username)
        => configuration is { DisablePasswordLogin: true }
           && !IsBreakGlass(configuration, username);

    /// <summary>
    /// Whether the given username is the designated break-glass admin (the exempt account). Ordinal-ignore-case.
    /// </summary>
    /// <param name="configuration">The live plugin configuration.</param>
    /// <param name="username">The account username under consideration.</param>
    /// <returns>True when the account is the exempt break-glass admin.</returns>
    internal static bool IsBreakGlass(PluginConfiguration configuration, string username)
        => !string.IsNullOrWhiteSpace(configuration?.BreakGlassAdminUsername)
           && string.Equals(configuration!.BreakGlassAdminUsername, username, StringComparison.OrdinalIgnoreCase);
}

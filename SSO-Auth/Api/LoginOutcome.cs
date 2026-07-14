using MediaBrowser.Controller.Authentication;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The closed set of results a login flow can produce (#318). There is deliberately no Error case:
/// anything unexpected propagates as an exception and surfaces as a genuine 500, so a client-caused
/// condition structurally cannot become a 500. The hierarchy is closed within the assembly by
/// convention: the internal type cannot be named outside it, and while an in-assembly subtype can
/// still derive through the compiler-synthesized record copy constructor, the mapper throws on any
/// unknown subtype, so a foreign case fails closed. <see cref="LoginStatusMapper"/> is the single place outcomes become HTTP
/// responses. A throttled case joins this sum with the rate-limit filter step — the Retry-After
/// header needs response access a pure mapper does not have, and the 429 is byte-identical today.
/// </summary>
internal abstract record LoginOutcome
{
    private LoginOutcome()
    {
    }

    /// <summary>A minted session; the mapper returns it as the 200 JSON body unchanged.</summary>
    /// <param name="Session">The authentication result the client consumes.</param>
    internal sealed record Success(AuthenticationResult Session) : LoginOutcome;

    /// <summary>A client-caused rejection with a categorized, deliberately uninformative public reason.</summary>
    /// <param name="Reason">The public rejection category the mapper translates.</param>
    internal sealed record Rejected(PublicReason Reason) : LoginOutcome;

    /// <summary>
    /// A policy denial (role allow-list, unresolved identity). Deliberately carries no reason at all:
    /// every denial maps to the one uniform 401 body, so a cause cannot leak even by construction.
    /// </summary>
    internal sealed record Denied : LoginOutcome;
}

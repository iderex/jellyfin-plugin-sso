#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api.Shared;

/// <summary>
/// The endpoint-class bucket keys the per-client rate-limit gate keys on (#694). <see cref="SsoRateLimitGate.Check"/>
/// folds the class into the limiter key as <c>class + ":" + clientKey</c>, so each value here names one
/// independent budget: the anonymous login stages (<see cref="Challenge"/>/<see cref="Callback"/>/<see cref="Auth"/>),
/// the elevation-gated Test-connection probe (<see cref="Test"/>), the anonymous SP-metadata read
/// (<see cref="Metadata"/>), the admin SSO-revoke (<see cref="Unregister"/>, #516), and the authenticated
/// link/unlink write surface (<see cref="Link"/>, #382). These are named constants rather than bare string
/// literals at the call sites precisely because the value is LOAD-BEARING on the limiter grouping: a typo in a
/// literal ("challange") compiles cleanly and silently mints a separate, empty bucket, weakening the rate limit
/// undetectably. Referencing a member instead makes a typo a compile error, and the
/// <c>RateLimitEndpointClass_UsesTypedConstants_NotLiterals</c> conformance test forbids a raw literal from
/// creeping back in. The values are the exact lowercase strings the wire keys have always carried, so this is a
/// readability/safety change with no behavioural or persisted-state effect.
/// </summary>
internal static class SsoRateLimitClass
{
    /// <summary>The anonymous login-challenge stage that begins an OpenID/SAML flow.</summary>
    internal const string Challenge = "challenge";

    /// <summary>The anonymous callback stage where the identity provider returns the login result.</summary>
    internal const string Callback = "callback";

    /// <summary>The anonymous authentication stage that mints the Jellyfin session.</summary>
    internal const string Auth = "auth";

    /// <summary>The elevation-gated Test-connection provider probe.</summary>
    internal const string Test = "test";

    /// <summary>The anonymous service-provider SAML metadata read.</summary>
    internal const string Metadata = "metadata";

    /// <summary>The admin SSO-revoke (unregister) surface (#516).</summary>
    internal const string Unregister = "unregister";

    /// <summary>The authenticated account link/unlink write surface (#382).</summary>
    internal const string Link = "link";
}

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
    internal const string Challenge = "challenge";
    internal const string Callback = "callback";
    internal const string Auth = "auth";
    internal const string Test = "test";
    internal const string Metadata = "metadata";
    internal const string Unregister = "unregister";
    internal const string Link = "link";
}

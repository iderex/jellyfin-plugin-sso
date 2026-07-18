using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("SSO-Auth.Tests")]

// The out-of-band fuzz harness (SSO-Auth.Fuzz, #402) drives the internal untrusted-input parse entry
// points — SamlResponseLoader, PkceDiscovery, OidcResponseIssuer — directly, the same way the test
// project does. It is a separate, non-shipping project kept out of the normal build/test path.
[assembly: InternalsVisibleTo("SSO-Auth.Fuzz")]

// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("SSO-Auth.Tests")]

// The out-of-band fuzz harness (SSO-Auth.Fuzz, #402) drives the internal untrusted-input parse entry
// points — SamlResponseLoader, PkceDiscovery, OidcResponseIssuer — directly, the same way the test
// project does. It is a separate, non-shipping project kept out of the normal build/test path.
[assembly: InternalsVisibleTo("SSO-Auth.Fuzz")]

// The VSTest twin of the test project (SSO-Auth.Tests.Stryker, #899) compiles the SAME test sources
// for the Stryker mutation run only — Stryker's runner speaks VSTest and cannot drive the MTP-v2
// test project. Non-shipping, outside the normal build/test path; delete with the twin when Stryker
// gains MTP v2 support.
[assembly: InternalsVisibleTo("SSO-Auth.Tests.Stryker")]

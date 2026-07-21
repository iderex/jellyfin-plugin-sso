// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlAssertionValidator.TryProduceVerifiedIdentity"/> that pin the single-evaluation
/// role threading (#479): the flow service evaluates the assertion's Role attribute ONCE for the login
/// allow-list and threads that list in here, so the privilege derivation must consume the roles it is
/// PASSED rather than re-reading the assertion — the property the dedup relies on.
/// </summary>
public class SamlAssertionValidatorTests
{
    private static SamlResponse SignedResponse(string role)
    {
        var fixture = SamlTestFactory.Create(nameId: "alice", role: role);
        return new SamlResponse(fixture.CertificateBase64, fixture.EncodeResponse());
    }

    [Fact]
    public void TryProduceVerifiedIdentity_DerivesPrivilegesFromThreadedRoles_NotFromAssertion()
    {
        // Replay is a process-wide static; reset so a prior test's consumed assertion id cannot interfere.
        SamlAssertionValidator.ResetReplaysForTests();
        var validator = new SamlAssertionValidator(Substitute.For<ILogger>());

        // The assertion carries a NON-admin role, but the caller threads in a role list that DOES grant admin
        // (the single evaluation the flow service already performed, #479). If this method reused the threaded
        // list, the derived identity is an admin; if it re-read the assertion, it would not be. Asserting admin
        // pins that the passed roles — not a second read of the assertion — drive the derivation.
        var response = SignedResponse("plain-users");
        var config = new SamlConfig { AdminRoles = new[] { "admins" } };

        var produced = validator.TryProduceVerifiedIdentity(
            config,
            "adfs",
            response,
            new List<string> { "admins" },
            out var identity,
            out var rejection);

        Assert.True(produced);
        Assert.Null(rejection);
        Assert.NotNull(identity);
        Assert.True(identity.Admin);
    }

    [Fact]
    public void TryValidate_ParsesButFailsValidation_ReturnsFalseAndNullsOutTheResponse()
    {
        SamlAssertionValidator.ResetReplaysForTests();
        var validator = new SamlAssertionValidator(Substitute.For<ILogger>());

        // A well-formed, parseable response whose signature does NOT verify against the configured (foreign)
        // certificate: TryParse succeeds, so this exercises the parse-ok / validation-fail branch — the one
        // that disposes the parsed response and sets the out parameter to null (#674 and the documented
        // "otherwise null" out contract). Nothing else calls TryValidate directly, so without this test that
        // dispose-and-null branch is exercised by nothing and deleting it would be undetectable.
        // DoNotValidateAudience isolates the failure to the signature check.
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var config = new SamlConfig
        {
            SamlCertificate = SamlFixture.ForeignCertificateBase64(),
            DoNotValidateAudience = true,
        };

        var result = validator.TryValidate(config, "adfs", "https://jf.example", fixture.EncodeResponse(), out var samlResponse);

        Assert.False(result);
        Assert.Null(samlResponse);
    }

    [Fact]
    public void TryValidate_ParsesAndValidates_ReturnsTrueWithNonNullResponse()
    {
        SamlAssertionValidator.ResetReplaysForTests();
        var validator = new SamlAssertionValidator(Substitute.For<ILogger>());

        // The mirror of the fail path: a correctly-signed response returns true with a non-null out response,
        // so a mutant that always nulls the out (or always returns false) is caught.
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var config = new SamlConfig
        {
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
        };

        var result = validator.TryValidate(config, "adfs", "https://jf.example", fixture.EncodeResponse(), out var samlResponse);

        Assert.True(result);
        Assert.NotNull(samlResponse);
        samlResponse.Dispose();
    }
}

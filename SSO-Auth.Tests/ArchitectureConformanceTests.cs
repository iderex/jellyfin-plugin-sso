using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Jellyfin.Plugin.SSO_Auth;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Architecture-conformance fitness functions for the target architecture planned in #318. These run as
/// part of the ordinary test suite, so every PR is checked — a change that drifts from the agreed
/// structure fails CI. The rules encode structural invariants that hold TODAY and are part of the target;
/// as each migration step lands a new structural property, add the rule that locks it in here so it
/// cannot regress. Keep rules type-level (reflection over the production assembly); call-level invariants
/// stay guarded by CodeQL/CodeRabbit and the pinning tests.
/// </summary>
public class ArchitectureConformanceTests
{
    // Suffixes that mark a pure, single-responsibility helper in the target layering (a "gate", store, or
    // mapper). By the "one unified OO architecture" + "default internal" principles these are internal
    // implementation detail, never part of the plugin's public surface.
    private static readonly string[] HelperSuffixes =
    {
        "Validator", "Cache", "Builder", "Mapper", "Policy", "Probe", "Store", "Revoker", "Extractor",
    };

    private static IEnumerable<Type> PluginTypes =>
        typeof(SSOPlugin).Assembly
            .GetTypes()
            .Where(t => t.IsClass && !IsCompilerGenerated(t));

    [Fact]
    public void SingleResponsibilityHelpers_AreInternal_NotPartOfThePublicSurface()
    {
        var leaked = PluginTypes
            .Where(t => HelperSuffixes.Any(s => t.Name.EndsWith(s, StringComparison.Ordinal)))
            .Where(t => t.IsPublic || t.IsNestedPublic)
            .Select(t => t.FullName)
            .ToList();

        Assert.True(leaked.Count == 0, "These helper types must be internal (target: default-internal, thin public surface): " + string.Join(", ", leaked));
    }

    [Fact]
    public void SingleResponsibilityHelpers_AreSealedOrStatic_NotAnInheritanceBase()
    {
        // A pure helper is a leaf: `static` (abstract+sealed in IL) or `sealed`. An open helper base is a
        // divergent one-off pattern the unified architecture rules out.
        var open = PluginTypes
            .Where(t => HelperSuffixes.Any(s => t.Name.EndsWith(s, StringComparison.Ordinal)))
            .Where(t => !t.IsSealed && !t.IsAbstract)
            .Select(t => t.FullName)
            .ToList();

        Assert.True(open.Count == 0, "These helper types must be sealed or static (a pure helper is a leaf, not an inheritance base): " + string.Join(", ", open));
    }

    [Fact]
    public void Controllers_DeriveFromControllerBase()
    {
        var stray = PluginTypes
            .Where(t => t.Name.EndsWith("Controller", StringComparison.Ordinal))
            .Where(t => !typeof(ControllerBase).IsAssignableFrom(t))
            .Select(t => t.FullName)
            .ToList();

        Assert.True(stray.Count == 0, "Types named *Controller must derive from ControllerBase: " + string.Join(", ", stray));
    }

    [Fact]
    public void EverythingLivesUnderThePluginRootNamespace()
    {
        // The whole plugin stays under one root namespace; the migration reorganises the sub-namespaces
        // (Http/Flows/Oidc/Saml/Config/Shared/…) but never leaks a type outside the root.
        var outside = PluginTypes
            .Where(t => t.Namespace is not null)
            .Where(t => !t.Namespace!.StartsWith("Jellyfin.Plugin.SSO_Auth", StringComparison.Ordinal))
            .Select(t => t.FullName)
            .ToList();

        Assert.True(outside.Count == 0, "All plugin types must live under the Jellyfin.Plugin.SSO_Auth root namespace: " + string.Join(", ", outside));
    }

    private static bool IsCompilerGenerated(Type t) =>
        t.Name.Contains('<', StringComparison.Ordinal)
        || t.GetCustomAttribute<System.Runtime.CompilerServices.CompilerGeneratedAttribute>() is not null;
}

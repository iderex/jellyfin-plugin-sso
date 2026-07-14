using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Architecture-conformance fitness functions for the target architecture planned in #318. These run as
/// part of the ordinary test suite, so every PR is checked — a change that drifts from the agreed
/// structure fails CI. The rules encode structural invariants that hold today and are part of the target;
/// as each migration step lands a new structural property, add the rule that locks it in here so it
/// cannot regress. Rules are type-level (reflection over the production assembly); call-level invariants
/// stay guarded by CodeQL/CodeRabbit and the pinning tests.
/// </summary>
public class ArchitectureConformanceTests
{
    private const string Root = "Jellyfin.Plugin.SSO_Auth";

    // Suffixes that mark a pure, single-responsibility helper in the target layering (a "gate", store, or
    // mapper). By the "one unified OO architecture" + "default internal" principles these are internal
    // implementation detail, never part of the plugin's public surface.
    private static readonly string[] HelperSuffixes =
    {
        "Validator", "Cache", "Builder", "Mapper", "Policy", "Probe", "Store", "Revoker", "Extractor", "Gate", "State",
    };

    // Every production type, compiler-generated ones excluded — the base sequence for structural rules
    // that must cover interfaces/enums/structs/delegates too (e.g. the namespace boundary).
    private static IEnumerable<Type> AllPluginTypes =>
        typeof(SSOPlugin).Assembly.GetTypes().Where(t => !IsCompilerGenerated(t));

    // The class subset, for rules that only make sense on classes (helper shape, controller base type).
    private static IEnumerable<Type> PluginClasses => AllPluginTypes.Where(t => t.IsClass);

    private static bool IsHelper(Type t) =>
        HelperSuffixes.Any(s => SimpleName(t).EndsWith(s, StringComparison.Ordinal));

    [Fact]
    public void SingleResponsibilityHelpers_AreInternal_NotPartOfThePublicSurface()
    {
        // Any externally-visible accessibility leaks the helper: public, or a nested member reachable by a
        // consumer or a derived type (protected / protected-internal count as leaks too).
        var leaked = PluginClasses
            .Where(IsHelper)
            .Where(t => t.IsPublic || t.IsNestedPublic || t.IsNestedFamily || t.IsNestedFamORAssem)
            .Select(t => t.FullName)
            .ToList();

        Assert.True(leaked.Count == 0, "These helper types must be internal (target: default-internal, thin public surface): " + string.Join(", ", leaked));
    }

    [Fact]
    public void SingleResponsibilityHelpers_AreSealedOrStatic_NotAnInheritanceBase()
    {
        // A pure helper is a leaf: `static` (abstract+sealed in IL) or `sealed`. Anything not sealed — an
        // ordinary class OR an abstract base — is an open inheritance point the unified architecture rules
        // out. (A static class is sealed, so it passes.)
        var open = PluginClasses
            .Where(IsHelper)
            .Where(t => !t.IsSealed)
            .Select(t => t.FullName)
            .ToList();

        Assert.True(open.Count == 0, "These helper types must be sealed or static (a pure helper is a leaf, not an inheritance base): " + string.Join(", ", open));
    }

    [Fact]
    public void Controllers_DeriveFromControllerBase()
    {
        var stray = PluginClasses
            .Where(t => SimpleName(t).EndsWith("Controller", StringComparison.Ordinal))
            .Where(t => !typeof(ControllerBase).IsAssignableFrom(t))
            .Select(t => t.FullName)
            .ToList();

        Assert.True(stray.Count == 0, "Types named *Controller must derive from ControllerBase: " + string.Join(", ", stray));
    }

    [Fact]
    public void EverythingLivesUnderThePluginRootNamespace()
    {
        // The whole plugin stays under one root namespace; the migration reorganises the sub-namespaces
        // (Http/Flows/Oidc/Saml/Config/Shared/…) but never leaks a type outside the root. Covers ALL types
        // (interfaces/enums/structs/delegates too), rejects the global namespace, and matches the root
        // exactly or as a "Root."-prefixed descendant — so a sibling like "…SSO_AuthEvil" does not pass.
        var outside = AllPluginTypes
            .Where(t => !t.IsNested) // a nested type inherits its declaring type's namespace; check the outers
            .Where(t => t.Namespace is not { } ns || !(ns == Root || ns.StartsWith(Root + ".", StringComparison.Ordinal)))
            .Select(t => t.FullName ?? t.Name)
            .ToList();

        Assert.True(outside.Count == 0, "All plugin types must live under the " + Root + " root namespace: " + string.Join(", ", outside));
    }

    [Fact]
    public void MutableKeyedState_LivesOnlyInsideStoreLikeTypes()
    {
        // Locked in by the OidcStateStore consolidation (#318): a raw dictionary holding runtime state
        // outside a *Store/*Cache/*Limiter type is how the pre-consolidation controller accumulated its
        // scattered cap/lifetime/sweep conventions. Two documented exemptions:
        // - SSOController.PkceSupportCache: the PKCE-discovery cache still lives on the controller and
        //   moves into its own probe type in a later #318 step; naming the exact field keeps anything
        //   new from hiding behind the exemption.
        // - ProviderConfigBase._canonicalLinks: the persisted account-link map — serialized plugin
        //   configuration mutated only under the config lock, so a runtime store type would be the
        //   wrong home; it is config state, not in-flight state.
        var storeLike = new[] { "Store", "Cache", "Limiter" };
        var exemptions = new[] { "SSOController.PkceSupportCache", "ProviderConfigBase._canonicalLinks" };

        var offenders = PluginClasses
            .Where(t => !storeLike.Any(s => SimpleName(t).EndsWith(s, StringComparison.Ordinal)))
            .SelectMany(t => t.GetFields(BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            .Where(f => !f.Name.Contains('<', StringComparison.Ordinal)) // compiler-generated backing fields
            .Where(f => IsDictionaryLike(f.FieldType))
            .Select(f => $"{SimpleName(f.DeclaringType!)}.{f.Name}") // DeclaringType is never null for a type's own fields
            .Where(n => !exemptions.Contains(n))
            .ToList();

        Assert.True(offenders.Count == 0, "Raw dictionary state must live inside a *Store/*Cache/*Limiter type (or carry a documented exemption here): " + string.Join(", ", offenders));
    }

    [Fact]
    public void SSOPlugin_DeclaresNoConfigurationLogicBeyondTheStoreFacade()
    {
        // Locked in by the ProviderConfigStore extraction (#318): SSOPlugin is bootstrap + page
        // manifests + a thin facade, and every configuration read/write/validation/preservation rule
        // lives in Config/ (ProviderConfigStore, ProviderConfigValidator, ServerManagedFields). Any
        // declared method or field whose signature mentions a configuration type must be one of the
        // named facade members that delegate to the store. PersistBase is allow-listed by name: it is
        // the private bridge handing base.UpdateConfiguration to the store, not config logic of its own.
        // Compiler-generated members (the ctor's `() => Configuration` lambda, backing fields) are
        // artifacts of the allowed wiring, not declared members — same exclusion as the keyed-state rule.
        var facade = new[] { "ReadConfiguration", "MutateConfiguration", "UpdateConfiguration", "PersistBase" };
        const BindingFlags declared = BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;

        var offenders = typeof(SSOPlugin).GetMethods(declared)
            .Where(m => !facade.Contains(m.Name) && !m.Name.Contains('<', StringComparison.Ordinal))
            .Where(m => m.GetParameters().Select(p => p.ParameterType).Append(m.ReturnType).Any(MentionsConfiguration))
            .Select(m => m.Name)
            .Concat(typeof(SSOPlugin).GetFields(declared)
                .Where(f => !f.Name.Contains('<', StringComparison.Ordinal))
                .Where(f => MentionsConfiguration(f.FieldType))
                .Select(f => f.Name))
            .ToList();

        Assert.True(offenders.Count == 0, "SSOPlugin members touching configuration types must stay limited to the delegating facade (config logic lives in Config/): " + string.Join(", ", offenders));
    }

    // A configuration type for the facade rule: the plugin configuration itself or any provider config
    // (OidConfig/SamlConfig derive from ProviderConfigBase), including one buried in a generic
    // (e.g. Func<PluginConfiguration, T>) or array signature.
    private static bool MentionsConfiguration(Type t) =>
        typeof(BasePluginConfiguration).IsAssignableFrom(t)
        || typeof(ProviderConfigBase).IsAssignableFrom(t)
        || (t.HasElementType && MentionsConfiguration(t.GetElementType()!))
        || (t.IsGenericType && t.GetGenericArguments().Any(MentionsConfiguration));

    // Catches concrete dictionaries (they implement non-generic IDictionary) AND fields declared as the
    // generic IDictionary<,> interface, which does not inherit the non-generic one — otherwise an
    // interface-typed field would slip past the mutable-keyed-state rule.
    private static bool IsDictionaryLike(Type t) =>
        typeof(System.Collections.IDictionary).IsAssignableFrom(t)
        || (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(IDictionary<,>))
        || t.GetInterfaces().Any(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IDictionary<,>));

    // The reflection Name of a generic type carries a `1 arity suffix (e.g. "Cache`1"); strip it so suffix
    // matching sees the source name.
    private static string SimpleName(Type t)
    {
        var name = t.Name;
        var tick = name.IndexOf('`', StringComparison.Ordinal);
        return tick < 0 ? name : name[..tick];
    }

    private static bool IsCompilerGenerated(Type t) =>
        t.Name.Contains('<', StringComparison.Ordinal)
        || t.GetCustomAttribute<System.Runtime.CompilerServices.CompilerGeneratedAttribute>() is not null;
}

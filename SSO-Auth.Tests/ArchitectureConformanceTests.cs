using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
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
/// cannot regress. Most rules are type-level (reflection over the production assembly); call-level
/// invariants otherwise stay guarded by CodeQL/CodeRabbit and the pinning tests. Two call-level
/// properties are locked in as source scans — the CONTROLLER touches no provider link map directly
/// (<see cref="Controller_NeverTouchesProviderLinkMaps"/>) and no raw socket/DNS surface
/// (<see cref="Controller_NeverTouchesRawSocketsOrDns"/>) — because the #372 extraction confines
/// link-map access to CanonicalLinkService (the login/admin workflow) and ServerManagedFields.Preserve
/// (the #157 server-managed re-injection the config tier owns), a boundary worth failing CI on, not just
/// review; #383 retired the controller's last two inline re-injection sites into that shared Preserve, so
/// the scan is now a plain zero-occurrence invariant on the controller.
/// </summary>
public class ArchitectureConformanceTests
{
    private const string Root = "Jellyfin.Plugin.SSO_Auth";

    // Suffixes that mark a pure, single-responsibility helper in the target layering (a "gate", store, or
    // mapper). By the "one unified OO architecture" + "default internal" principles these are internal
    // implementation detail, never part of the plugin's public surface.
    private static readonly string[] HelperSuffixes =
    {
        "Validator", "Cache", "Builder", "Mapper", "Policy", "Probe", "Store", "Revoker", "Extractor", "Gate", "State", "Resolver",
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
    public void FlowServices_AreInternalAndSealed()
    {
        // The flow tier (#318): a *Service is a stateful collaborator (holds IUserManager, the config
        // store, …) that orchestrates pure helpers — distinct from the leaf *Helper suffixes above, so
        // it gets its own rule rather than joining HelperSuffixes. It is still internal-by-default and a
        // sealed leaf, never an inheritance base or part of the public surface.
        var stray = PluginClasses
            .Where(t => SimpleName(t).EndsWith("Service", StringComparison.Ordinal))
            .Where(t => t.IsPublic || t.IsNestedPublic || t.IsNestedFamily || t.IsNestedFamORAssem || !t.IsSealed)
            .Select(t => t.FullName)
            .ToList();

        Assert.True(stray.Count == 0, "Flow services (*Service) must be internal and sealed collaborators: " + string.Join(", ", stray));
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
    public void Controller_NeverTouchesProviderLinkMaps()
    {
        // Locked in by the link/unlink admin-surface extraction (#372) and completed by #383: the two
        // legitimate homes for provider-CanonicalLinks access are CanonicalLinkService (the login/admin
        // link workflow, under the config lock) and ServerManagedFields.Preserve (the #157 re-injection
        // the config tier owns) — and the controller's two former inline re-injection statements now route
        // through that shared Preserve, so the CONTROLLER has ZERO direct CanonicalLinks access and the
        // earlier re-injection exemption is retired. This is a call-level property, so it is a source scan
        // rather than a reflection rule (the one exception to the "call-level invariants stay with
        // CodeQL/CodeRabbit" note in the class summary); a missing source file fails the test loudly.
        var controllerSource = File.ReadAllLines(Path.Combine(RepoRoot(), "SSO-Auth", "Api", "SSOController.cs"));
        var linkMapLines = controllerSource
            .Select((line, index) => (Text: line.Trim(), Number: index + 1))
            .Where(l => l.Text.Contains(".CanonicalLinks", StringComparison.Ordinal))
            .Select(l => $"line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            linkMapLines.Count == 0,
            "SSOController must not access a provider CanonicalLinks map directly; route link-map access through CanonicalLinkService and server-managed re-injection through ServerManagedFields.Preserve. Found: " + string.Join(" | ", linkMapLines));
    }

    [Fact]
    public void Controller_NeverTouchesRawSocketsOrDns()
    {
        // Locked in by the AvatarService extraction (#375): the raw-socket/DNS surface lives only in the
        // avatar tier (AvatarService, AvatarUrlValidator) and SsoRateLimiter — the controller orchestrates
        // flows over injected collaborators and never opens a network primitive itself. Same plain source
        // scan as the link-map rule above. Marker choice: any Socket/NetworkStream/SocketsHttpHandler use
        // needs the System.Net.Sockets namespace in the file (using directive, alias, or full
        // qualification), so that one marker subsumes the type names; "NetworkStream" is the
        // belt-and-braces type-name catch on top; "Dns." catches System.Net.Dns call sites (which need no
        // Sockets using) and "System.Net.Dns" the static-import form. Bare "Socket"/"Dns" are deliberately
        // NOT markers — they would false-positive on prose in comments.
        var markers = new[] { "System.Net.Sockets", "NetworkStream", "Dns.", "System.Net.Dns" };
        var controllerSource = File.ReadAllLines(Path.Combine(RepoRoot(), "SSO-Auth", "Api", "SSOController.cs"));
        var socketLines = controllerSource
            .Select((line, index) => (Text: line.Trim(), Number: index + 1))
            .Where(l => markers.Any(m => l.Text.Contains(m, StringComparison.Ordinal)))
            .Select(l => $"line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            socketLines.Count == 0,
            "SSOController must not touch the raw socket/DNS surface (System.Net.Sockets, Socket, NetworkStream, Dns); outbound network primitives belong to AvatarService/AvatarUrlValidator and SsoRateLimiter. Found: " + string.Join(" | ", socketLines));
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
            .Concat(typeof(SSOPlugin).GetConstructors(declared)
                .Where(c => c.GetParameters().Select(p => p.ParameterType).Any(MentionsConfiguration))
                .Select(c => ".ctor"))
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
        || t.GetCustomAttribute<CompilerGeneratedAttribute>() is not null;

    // The repository root, derived from this test file's compile-time path (<root>/SSO-Auth.Tests/<file>).
    // CallerFilePath is baked in at build, and CI builds on the same checkout it tests, so the source tree
    // is present for the source-scan rule above.
    private static string RepoRoot([CallerFilePath] string thisFilePath = "") =>
        Directory.GetParent(Path.GetDirectoryName(thisFilePath)!)!.FullName;
}

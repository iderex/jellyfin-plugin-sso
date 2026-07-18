using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
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
/// invariants otherwise stay guarded by CodeQL and the pinning tests. Two call-level
/// properties are locked in as source scans — the CONTROLLER touches no provider link map directly
/// (<see cref="Controller_NeverTouchesProviderLinkMaps"/>) and no raw socket/DNS surface
/// (<see cref="Controller_NeverTouchesRawSocketsOrDns"/>) — because the #372 extraction confines
/// link-map access to CanonicalLinkService (the login/admin workflow) and ServerManagedFields.Preserve
/// (the #157 server-managed re-injection the config tier owns), a boundary worth failing CI on, not just
/// review; #383 retired the controller's last two inline re-injection sites into that shared Preserve, so
/// the scan is now a plain zero-occurrence invariant on the controller. Both source scans discover EVERY
/// controller source file from reflection (<see cref="ControllerSourceFiles"/>) rather than one hardcoded
/// path, so the planned #318 controller split — into partial-class files or several controllers — cannot
/// hide an endpoint from them, and each is sentinel-guarded against a vacuous pass: the file set must be
/// non-empty, and the link-map scan pins its target property by reflection so a rename fails loudly (#388).
/// The socket/DNS scan's markers are BCL identifiers rather than a token this codebase owns, so its
/// sentinel instead pins the marker SET against the surface's legitimate home — AvatarService,
/// AvatarUrlValidator, SsoRateLimiter — asserting at least one marker still matches real usage there,
/// so a marker set that stops matching anything real fails loudly too (#444).
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

    // The login-path caches that converged on the shared bounding pattern — a hard global cap plus TWO
    // distinct IntervalGates: "_pruneGate" (throttled expired-entry sweep, #452) and "_capWarnGate"
    // (throttled cap-refusal capacity warning, #246/#327/#470). ONE canonical list, consumed by both the
    // prune-gate rule and the cap-warn rule below, so a cache can never fall out of one rule's list but not
    // the other's (which is exactly how SamlOutcomeStore was missed on first draft). A new cap-bounded
    // login-path cache is added here once, and both fitness functions guard it.
    private static readonly Type[] LoginPathCapWarnCaches =
    {
        typeof(SamlReplayCache), typeof(SamlRequestCache), typeof(OidcStateStore), typeof(SamlOutcomeStore),
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
        // scattered cap/lifetime/sweep conventions. The former SSOController.DiscoveryFactsCache moved into a
        // *Cache type in #449 and was then removed entirely in #450 (discovery is now read once per challenge
        // and fed to the login, with nothing cached), so no discovery-facts dictionary remains to exempt.
        // Two documented exemptions remain, both persisted account-link config state:
        // - ProviderConfigBase._canonicalLinks: the persisted account-link map — serialized plugin
        //   configuration mutated only under the config lock, so a runtime store type would be the
        //   wrong home; it is config state, not in-flight state.
        // - OidConfig._canonicalLinkIssuers: the per-link issuer binding (#186), the exact parallel of
        //   _canonicalLinks — serialized config mutated only under the config lock, same rationale.
        var storeLike = new[] { "Store", "Cache", "Limiter" };
        var exemptions = new[] { "ProviderConfigBase._canonicalLinks", "OidConfig._canonicalLinkIssuers" };

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
    public void LoginPathCaches_ThrottleTheirExpiredEntrySweepThroughIntervalGate()
    {
        // Locked in by #452: the login-path caches converged on one bounding pattern — an
        // IntervalGate-throttled expired-entry sweep plus a hard global cap — so none can regress to the
        // unthrottled full-dictionary sweep (or the unbounded set) SamlReplayCache carried before #452.
        // Each named cache must declare the PRUNE gate specifically (an IntervalGate field named
        // "_pruneGate"), not merely some IntervalGate: the siblings also carry a "_capWarnGate", so keying
        // on the field type alone would miss a sibling that dropped its prune gate but kept cap-warn.
        // SamlRequestCache and OidcStateStore already had it (#246, #327); SamlReplayCache adopted it (#452).
        // The cache set is the shared LoginPathCapWarnCaches list, so this rule and the cap-warn rule below
        // can never disagree on which caches are login-path caches.
        const string pruneGateField = "_pruneGate";
        var missing = LoginPathCapWarnCaches
            .Where(t => !t.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.DeclaredOnly)
                .Any(f => f.FieldType == typeof(IntervalGate) && f.Name == pruneGateField))
            .Select(SimpleName)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Every login-path cache must throttle its expired-entry sweep through an IntervalGate field (#452): " + string.Join(", ", missing));
    }

    [Fact]
    public void LoginPathCaches_ThrottleTheirCapacityWarningThroughItsOwnIntervalGate()
    {
        // Locked in by #470: every login-path cache that refuses fail-closed at its hard cap surfaces that
        // refusal to the caller through a SEPARATE cap-warn IntervalGate ("_capWarnGate"), distinct from the
        // prune gate ("_pruneGate"), so a full cache is observable to operators yet a flood of refusals
        // cannot amplify into log volume (CWE-400). SamlRequestCache, OidcStateStore and SamlOutcomeStore
        // already carried it (#246, #327, #251); SamlReplayCache adopted it here (#470). Require BOTH gates as
        // distinct named fields so a later refactor cannot collapse the cap-warn signal onto the prune gate
        // (which would re-couple the two intervals) or drop it and regress a cache to a silent cap refusal.
        // The cache set is the shared LoginPathCapWarnCaches list, so it can never drift from the prune-gate
        // rule above.
        var missing = LoginPathCapWarnCaches
            .Where(t =>
            {
                var gates = t.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.DeclaredOnly)
                    .Where(f => f.FieldType == typeof(IntervalGate))
                    .Select(f => f.Name)
                    .ToList();
                return !gates.Contains("_pruneGate") || !gates.Contains("_capWarnGate");
            })
            .Select(SimpleName)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Every login-path cache must carry BOTH a _pruneGate and a distinct _capWarnGate IntervalGate (#470): " + string.Join(", ", missing));
    }

    [Fact]
    public void CanonicalLinkService_ThrottlesTheLegacyLinkWarningThroughAStaticIntervalGate()
    {
        // Locked in by #362 (CWE-400, log-volume): the terminal pending-legacy-link warnings live in a
        // service the controller constructs PER REQUEST, so the once-per-interval throttle must be a
        // PROCESS-WIDE (static) IntervalGate — an instance field would reset every login and throttle
        // nothing, letting a hot login loop for a not-yet-migrated user flood the log. Pin the static gate
        // so a later refactor cannot silently demote it to an instance field (which compiles and passes the
        // unit tests, because those inject a fresh gate) and reopen the flood.
        var staticGate = typeof(CanonicalLinkService)
            .GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Any(f => f.FieldType == typeof(IntervalGate));

        Assert.True(
            staticGate,
            "CanonicalLinkService must throttle its pending-legacy-link warning through a static IntervalGate (#362), because the service is constructed per request and an instance gate would throttle nothing.");
    }

    [Fact]
    public void AuthorizeStates_AreImmutableVariants()
    {
        // Locked in by #341: the in-flight OpenID authorize state is a CLOSED, IMMUTABLE sum — an
        // AuthorizeSession base with exactly the Pending and Ready variants, swapped atomically in the
        // store rather than promoted in place. Immutable variants are what make the swap torn-read-free: a
        // redeemer racing the promotion observes either the whole Pending (not redeemable) or the whole
        // Ready, never a half-applied field set. A settable property or writable instance field on the base
        // or a variant would reopen the in-place-promotion window #341 closed, so pin it structurally.
        var baseType = typeof(AuthorizeSession);
        var variants = new[] { typeof(AuthorizeSession.Pending), typeof(AuthorizeSession.Ready) };

        // Closed sum: the base is abstract, every AuthorizeSession subtype in the assembly is one of the
        // two known variants, and each variant is a sealed leaf — no third variant, no open inheritance
        // point.
        Assert.True(baseType.IsAbstract, "AuthorizeSession must be an abstract base (the root of the closed sum).");
        var subtypes = AllPluginTypes.Where(t => t != baseType && baseType.IsAssignableFrom(t)).ToList();
        Assert.Equal(variants.Length, subtypes.Count);
        Assert.All(variants, v => Assert.Contains(v, subtypes));
        Assert.All(variants, v => Assert.True(v.IsSealed, $"{SimpleName(v)} must be a sealed variant of the closed sum."));

        // Immutable: no settable property and no writable instance field on the base or either variant.
        // Get-only auto-properties compile to readonly (initonly) backing fields, so they pass; a
        // `{ get; set; }` / `{ get; private set; }` or a plain writable field would be flagged.
        const BindingFlags members = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
        var mutable = new[] { baseType }.Concat(variants)
            .SelectMany(t => t.GetProperties(members)
                .Where(p => p.SetMethod is not null)
                .Select(p => $"{SimpleName(t)}.{p.Name} (settable property)")
                .Concat(t.GetFields(members)
                    .Where(f => !f.IsInitOnly && !f.IsLiteral && !f.Name.Contains('<', StringComparison.Ordinal))
                    .Select(f => $"{SimpleName(t)}.{f.Name} (writable field)")))
            .ToList();

        Assert.True(
            mutable.Count == 0,
            "AuthorizeSession and its variants must be immutable (no settable property or writable instance field) so the store's Pending -> Ready swap stays torn-read-free (#341): " + string.Join(", ", mutable));
    }

    [Fact]
    public void SamlLoginOutcome_IsImmutable()
    {
        // Locked in by the SAML one-time outcome token (#251): the login outcome stored between the ACS
        // callback and the mint leg is redeemed by an atomic remove of the WHOLE record, so a redeemer never
        // observes a torn outcome. A settable property or writable instance field would reopen an in-place
        // mutation window on a value that IS the proof the assertion passed every gate, so pin it structurally
        // exactly as AuthorizeSession's variants are (#341). A get-only auto-property / positional record
        // parameter compiles to a readonly (initonly) backing field and passes; a `{ get; set; }` or a plain
        // writable field would be flagged.
        var outcome = typeof(SamlLoginOutcome);
        Assert.True(outcome.IsSealed, "SamlLoginOutcome must be a sealed leaf.");

        const BindingFlags members = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
        var mutable = outcome.GetProperties(members)
            .Where(p => p.SetMethod is not null && !IsInitOnlySetter(p.SetMethod))
            .Select(p => $"{SimpleName(outcome)}.{p.Name} (settable property)")
            .Concat(outcome.GetFields(members)
                .Where(f => !f.IsInitOnly && !f.IsLiteral && !f.Name.Contains('<', StringComparison.Ordinal))
                .Select(f => $"{SimpleName(outcome)}.{f.Name} (writable field)"))
            .ToList();

        Assert.True(
            mutable.Count == 0,
            "SamlLoginOutcome must be immutable (no settable property or writable instance field) so the store's one-time redeem stays torn-read-free (#251): " + string.Join(", ", mutable));
    }

    // A record's positional properties expose an `init` setter (SetMethod is non-null) but are immutable
    // after construction; treat an init-only setter as read-only so a record's own positional members are
    // not mis-flagged as mutable. An init-only setter carries the IsExternalInit modreq on its return type.
    private static bool IsInitOnlySetter(MethodInfo setter) =>
        setter.ReturnParameter.GetRequiredCustomModifiers().Any(m => m.FullName == "System.Runtime.CompilerServices.IsExternalInit");

    [Fact]
    public void VerifiedIdentity_IsConstructedOnlyByProtocolValidators()
    {
        // Locked in by #473: VerifiedIdentity is the keystone the session-minting path is keyed on, and it
        // is unforgeable — its constructor is PRIVATE, so the only way to obtain one is a named factory that
        // stands for "this protocol's validation has completed". Two properties are pinned:
        //
        // 1. Reflection: NO declared instance constructor is reachable from outside the type — none is
        //    public, internal, or protected-internal. A sealed record's own compiler-generated copy
        //    constructor is emitted PRIVATE (protected only for unsealed records), so it too is excluded by
        //    this filter; the accessibility test is written to also exclude a plain `protected` ctor, which
        //    is unreachable on a sealed type anyway (no derived type could invoke it). The C# compiler
        //    guarantees such a constructor cannot be invoked outside the declaring type, so this alone
        //    proves `new VerifiedIdentity(...)` can appear only inside VerifiedIdentity.cs (the two
        //    factories) — no third construction path can compile. (An empty `with { }` on an existing
        //    instance clones a valid identity verbatim; every property is get-only, so it can neither
        //    mutate nor forge one.) A future `public`/`internal` ctor added to the type would reopen that
        //    hole and fail HERE.
        // 2. Source scan: each factory is INVOKED only from its protocol's validator. FromOidcRedemption
        //    belongs to the OpenID redeem path — built inside AuthorizeSession.Ready, which the store hands
        //    out only through the one-time atomic redeem — and FromValidatedSaml only at the SAML
        //    session-minting endpoint after full response validation. A call from anywhere else (a link
        //    endpoint, a new controller action) would mean an identity minted from something other than a
        //    completed validation, so it fails the scan.
        var ctors = typeof(VerifiedIdentity)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
        Assert.True(ctors.Length > 0, "VerifiedIdentity must declare an instance constructor to pin (it was removed or the type was renamed).");
        var reachable = ctors
            .Where(c => c.IsPublic || c.IsAssembly || c.IsFamilyOrAssembly)
            .Select(c => c.ToString())
            .ToList();
        Assert.True(
            reachable.Count == 0,
            "VerifiedIdentity's constructor(s) must not be reachable from outside the type (no public/internal/protected-internal ctor) so it is constructible only through its validation factories (#473): " + string.Join(", ", reachable));

        // Sentinel + call-site pins. The factory NAMES are the contract; require both to exist (a rename
        // must consciously update this rule), then confine each factory's invocation to the file(s) that own
        // its protocol's validation. AuthorizeSession is where the OpenID identity is built (from the
        // role-gate result); the SAML factory is invoked from the dedicated SamlAssertionValidator, the
        // single home the SAML inbound validation moved into (#496) — downstream of every gate, so the
        // "constructed only after complete validation" invariant is local to the validator.
        const string oidcFactory = "FromOidcRedemption";
        const string samlFactory = "FromValidatedSaml";
        var factoryMethods = typeof(VerifiedIdentity)
            .GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
            .Where(m => m.ReturnType == typeof(VerifiedIdentity))
            .Select(m => m.Name)
            .ToHashSet(StringComparer.Ordinal);
        Assert.True(
            factoryMethods.Contains(oidcFactory) && factoryMethods.Contains(samlFactory),
            $"VerifiedIdentity must expose the two named validation factories ({oidcFactory}, {samlFactory}); one was renamed, so update this rule and the source-scan allow-list with it (#473).");

        var oidcHome = SourceFilesDeclaring(new[] { typeof(AuthorizeSession) });
        var samlHome = SourceFilesDeclaring(new[] { typeof(SamlAssertionValidator) });
        AssertFactoryInvocationsConfinedTo("VerifiedIdentity." + oidcFactory + "(", oidcHome, "the OpenID redeem path (AuthorizeSession.Ready)");
        AssertFactoryInvocationsConfinedTo("VerifiedIdentity." + samlFactory + "(", samlHome, "the SAML assertion validator (SamlAssertionValidator)");
    }

    // Fails if the given factory-invocation token appears in any SSO-Auth source file outside the allowed
    // homes. Shared by the two #473 call-site pins; the allowed set is matched by absolute path so a file
    // rename that the reflection-driven home discovery already tracks flows through unchanged. This is a
    // qualified-call substring scan (belt-and-braces): the AIRTIGHT construction lock is the private-ctor
    // reflection assertion above — nothing outside VerifiedIdentity.cs can construct one at all, so a call
    // that this scan's substring might miss (a `using static` unqualified spelling, a line-split call) still
    // cannot forge an identity; this scan adds the sharper "constructed only by the RIGHT validator" signal
    // on top, keying on the qualified spelling the codebase actually uses.
    private static void AssertFactoryInvocationsConfinedTo(string invocationToken, IEnumerable<string> allowedFiles, string homeDescription)
    {
        var allowed = allowedFiles.Select(Path.GetFullPath).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var strays = Directory
            .EnumerateFiles(Path.Combine(RepoRoot(), "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Where(path => !allowed.Contains(Path.GetFullPath(path)))
            .Where(path => File.ReadAllText(path).Contains(invocationToken, StringComparison.Ordinal))
            .Select(Path.GetFileName)
            .ToList();

        Assert.True(
            strays.Count == 0,
            $"{invocationToken}...) may be invoked only from {homeDescription}; found outside it in: " + string.Join(", ", strays));
    }

    [Fact]
    public void Controller_NeverTouchesProviderLinkMaps()
    {
        // Locked in by the link/unlink admin-surface extraction (#372) and completed by #383: the two
        // legitimate homes for provider-CanonicalLinks access are CanonicalLinkService (the login/admin
        // link workflow, under the config lock) and ServerManagedFields.Preserve (the #157 re-injection
        // the config tier owns) — and the controller's two former inline re-injection statements now route
        // through that shared Preserve, so a CONTROLLER has ZERO direct CanonicalLinks access. This is a
        // call-level property, so it is a source scan rather than a reflection rule (the one exception to
        // the "call-level invariants stay with CodeQL" note in the class summary).
        //
        // Sentinel against a vacuous pass (#388): a zero-occurrence scan only means something while its
        // target token still names a link map. A property rename (CanonicalLinks -> anything) would make
        // the scan match nothing and pass for the wrong reason, so pin each property by reflection — a
        // rename fails HERE and forces a conscious update of the roster (and the scanned token with it).
        // BOTH server-managed link maps are guarded: the account-link map (ProviderConfigBase.CanonicalLinks,
        // #157) and its per-link issuer binding (OidConfig.CanonicalLinkIssuers, #186). Both are owned by
        // CanonicalLinkService and ServerManagedFields.Preserve; a controller must touch neither directly.
        var linkMapProperties = new[]
        {
            (Declaring: typeof(ProviderConfigBase), Name: "CanonicalLinks"),
            (Declaring: typeof(OidConfig), Name: "CanonicalLinkIssuers"),
        };
        foreach (var (declaring, name) in linkMapProperties)
        {
            Assert.True(
                declaring.GetProperty(name, BindingFlags.Public | BindingFlags.Instance) is not null,
                $"{declaring.Name}.{name} was renamed or removed; point this rule at the new provider link-map property so the scan keeps guarding it (#388).");
        }

        // The two tokens are disjoint substrings (".CanonicalLinkIssuers" does not contain ".CanonicalLinks"
        // — the char after "Link" is "I", not "s"), so scanning for both cannot cross-match.
        var tokens = linkMapProperties.Select(p => "." + p.Name).ToList();
        var linkMapLines = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => tokens.Any(t => l.Text.Contains(t, StringComparison.Ordinal)))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            linkMapLines.Count == 0,
            "A controller must not access a provider link map (CanonicalLinks / CanonicalLinkIssuers) directly; route link-map access through CanonicalLinkService and server-managed re-injection through ServerManagedFields.Preserve. Found: " + string.Join(" | ", linkMapLines));
    }

    [Fact]
    public void Controller_NeverTouchesRawSocketsOrDns()
    {
        // Locked in by the AvatarService extraction (#375): the raw-socket/DNS surface lives only in the
        // avatar tier (AvatarService, AvatarUrlValidator) and SsoRateLimiter — the controller orchestrates
        // flows over injected collaborators and never opens a network primitive itself. Same source scan as
        // the link-map rule above, over every controller source file (#388). Marker choice: any
        // Socket/NetworkStream use needs the System.Net.Sockets namespace in the file (using directive,
        // alias, or full qualification), so that one marker subsumes those type names; "NetworkStream" is
        // the belt-and-braces type-name catch on top; "SocketsHttpHandler" lives in System.Net.Http, which
        // the controller legitimately imports, so the namespace marker cannot cover it and it gets its own;
        // "Dns." catches System.Net.Dns call sites (which need no Sockets using) and "System.Net.Dns" the
        // static-import form. Bare "Socket"/"Dns" are deliberately NOT markers — they would false-positive
        // on prose in comments.
        var markers = new[] { "System.Net.Sockets", "SocketsHttpHandler", "NetworkStream", "Dns.", "System.Net.Dns" };
        var socketLines = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => markers.Any(m => l.Text.Contains(m, StringComparison.Ordinal)))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            socketLines.Count == 0,
            "A controller must not touch the raw socket/DNS surface (System.Net.Sockets, Socket, NetworkStream, Dns); outbound network primitives belong to AvatarService/AvatarUrlValidator and SsoRateLimiter. Found: " + string.Join(" | ", socketLines));

        // Sentinel against a vacuous pass (#444): unlike the link-map rule above, these markers are BCL
        // identifiers, not a token this codebase owns, so there is no single property to pin by
        // reflection. Instead pin the marker SET against reality: the raw socket/DNS surface's one
        // legitimate home is AvatarService/AvatarUrlValidator/SsoRateLimiter (#375), so at least one
        // marker must still match a real line there today. If a refactor ever changed how that tier
        // references sockets/DNS (a wrapping abstraction, a different BCL spelling) so that NONE of the
        // markers matched it any more, the zero-occurrence scan above would keep "passing" for the wrong
        // reason — this is the assertion that would actually catch it. Deliberately "at least one", not
        // "every" marker: "System.Net.Dns" is a defensive marker for the fully-qualified/static-import
        // spelling, which this codebase does not use anywhere today (Dns.GetHostAddressesAsync resolves
        // through the "using System.Net;" form instead, caught by the "Dns." marker) — that marker having
        // no live match is expected, not a liveness failure.
        var homeTypes = new[] { typeof(AvatarService), typeof(AvatarUrlValidator), typeof(SsoRateLimiter) };
        var homeFiles = SourceFilesDeclaring(homeTypes);
        Assert.True(
            homeFiles.Count == homeTypes.Length,
            "The raw socket/DNS surface's legitimate home (AvatarService/AvatarUrlValidator/SsoRateLimiter) was renamed or moved; point Controller_NeverTouchesRawSocketsOrDns's liveness check at its new location (#444).");

        var homeLines = homeFiles.SelectMany(File.ReadAllLines).ToList();
        Assert.True(
            markers.Any(m => homeLines.Any(l => l.Contains(m, StringComparison.Ordinal))),
            "None of the socket/DNS markers match any line in their legitimate home (AvatarService/AvatarUrlValidator/SsoRateLimiter); the zero-occurrence controller scan above would pass vacuously — update the markers to track how the socket/DNS surface is actually referenced (#444).");
    }

    [Fact]
    public void AvatarService_HoldsAStaticSharedHttpClient()
    {
        // Locked in by the per-login churn trim (#248): the controller builds a fresh AvatarService per
        // request, so the outbound HTTP stack must be a STATIC shared client — one connection pool for the
        // whole process — not a per-instance client that would open a new pool (a full TCP+TLS handshake)
        // on every login. The reference field the constructor reads (_httpClient) points at this shared
        // client in production; the reference-equality across two production instances is proven behaviorally
        // in AvatarServiceTests, and this rule locks in that the shared field it points at exists at all.
        var staticClient = typeof(AvatarService)
            .GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
            .Where(f => !f.Name.Contains('<', StringComparison.Ordinal))
            .Any(f => typeof(System.Net.Http.HttpClient).IsAssignableFrom(f.FieldType));

        Assert.True(staticClient, "AvatarService must hold a static HttpClient so the outbound stack is reused across the controller's per-request instances rather than rebuilt per login (#248).");
    }

    [Fact]
    public void SessionMinter_RechecksRevocationImmediatelyBeforeTheMint()
    {
        // Locked in by the in-flight revocation gate (#232): MintAsync must evaluate the caller-supplied
        // revocation predicate (identityStillLinked) as the last gate before it authenticates the session,
        // so a refactor cannot silently drop it or reorder it after the mint and reopen the TOCTOU between
        // link-resolution (under the config lock) and AuthenticateDirect (outside it). Call-level property,
        // so it is a source scan like the controller rules above. The invocation "identityStillLinked()"
        // is distinct from the parameter declaration/param-doc (no parentheses), so it matches only a gate.
        // The FINAL gate is what closes the race, so this pins the LAST invocation before the mint (an
        // earlier pre-mutation gate must not satisfy the rule) AND that no user-mutating side effect sits
        // between that final gate and AuthenticateDirect — otherwise a revocation during that work would go
        // unre-checked.
        var minterSource = File.ReadAllLines(Path.Combine(RepoRoot(), "SSO-Auth", "Api", "SessionMinter.cs"));
        var mintLine = Array.FindIndex(minterSource, l => l.Contains("AuthenticateDirect(", StringComparison.Ordinal));
        Assert.True(mintLine >= 0, "SessionMinter.MintAsync must call AuthenticateDirect to mint the session.");

        var finalGate = Array.FindLastIndex(minterSource, mintLine - 1, l => l.Contains("identityStillLinked()", StringComparison.Ordinal));
        Assert.True(finalGate >= 0, "SessionMinter.MintAsync must invoke the identityStillLinked revocation re-check before AuthenticateDirect (#232).");

        var mutationMarkers = new[] { "UpdateUserAsync", "SetPermission", "SetPreference", "TrySetAsync", "AuthenticationProviderId =" };
        var interveningMutation = minterSource
            .Skip(finalGate + 1)
            .Take(mintLine - finalGate - 1)
            .Any(l => mutationMarkers.Any(m => l.Contains(m, StringComparison.Ordinal)));
        Assert.False(
            interveningMutation,
            "No user-mutating side effect may sit between the final #232 revocation re-check and AuthenticateDirect — the re-check must be the last gate before the mint.");
    }

    [Fact]
    public void Controller_DelegatesLoginCompletionToTheFlowService()
    {
        // Locked in by the login-completion extraction (#160, #318 step 11): the one shared completion tail —
        // resolve/adopt the link, build the SessionParameters, mint the session under the revocation gate,
        // audit, map to a LoginOutcome — moved wholesale into LoginCompletionService. The controller's two
        // callbacks now hand a VerifiedIdentity to that service and return its result, so a CONTROLLER neither
        // builds SessionParameters nor mints a session itself. Call-level property, so it is a source scan
        // like the other controller rules above.
        //
        // The scanned tokens are derived from the moved types via nameof, so a rename of SessionParameters or
        // SessionMinter.MintAsync fails to COMPILE this rule (the strongest pin) rather than passing
        // vacuously. Constructing the minter to inject it (new SessionMinter(...)) is wiring, not the tail, so
        // it is deliberately not a scanned token — only building the parameters and minting are.
        var paramsToken = "new " + nameof(SessionParameters);
        var mintToken = nameof(SessionMinter.MintAsync) + "(";

        var controllerHits = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => l.Text.Contains(paramsToken, StringComparison.Ordinal) || l.Text.Contains(mintToken, StringComparison.Ordinal))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            controllerHits.Count == 0,
            "A controller must not build SessionParameters or mint a session directly; the shared login-completion tail lives in LoginCompletionService (#160). Found: " + string.Join(" | ", controllerHits));

        // Liveness against a vacuous pass: the tail must actually live in the flow service — a move, not a
        // silent removal — so LoginCompletionService's own source must contain both moved tokens.
        var completionSource = string.Join(
            "\n",
            SourceFilesDeclaring(new[] { typeof(LoginCompletionService) }).Select(File.ReadAllText));
        Assert.True(
            completionSource.Contains(paramsToken, StringComparison.Ordinal) && completionSource.Contains(mintToken, StringComparison.Ordinal),
            "LoginCompletionService must own the login-completion tail (build SessionParameters and mint the session); otherwise the controller scan passes vacuously (#160).");
    }

    [Fact]
    public void Controller_DelegatesOidcFlowToTheFlowService()
    {
        // Locked in by the OpenID flow extraction (#160, #318 step 12): the OpenID challenge and redirect
        // callback bodies, together with the OpenID-specific process-wide state (the in-flight authorize
        // store) and the discovery read, moved into OidcLoginService. The controller's OpenID endpoints now
        // apply the shared rate-limit gate and hand the request to that service, so a CONTROLLER neither
        // holds the OIDC authorize store / discovery read nor drives the OidcClient challenge/callback
        // protocol itself. Call-level property, so it is a source scan like the other controller rules above.
        //
        // The store and reader tokens are nameof-derived, so a rename of either type fails to COMPILE this
        // rule rather than passing vacuously; the two protocol tokens are the OidcClient methods the
        // challenge (PrepareLoginAsync) and callback (ProcessResponseAsync) drive. The shared per-client rate limiter
        // is deliberately NOT a marker — it fronts BOTH protocols, so rather than living on either flow
        // service it lives in the shared SsoRateLimitGate (#160), pinned off the controller by
        // Controller_HoldsNoMutableStaticState.
        var storeToken = nameof(OidcStateStore);
        var readerToken = nameof(OidcDiscoveryReader);
        var markers = new[] { storeToken, readerToken, "PrepareLoginAsync", "ProcessResponseAsync" };

        var controllerHits = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => markers.Any(m => l.Text.Contains(m, StringComparison.Ordinal)))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            controllerHits.Count == 0,
            "A controller must not hold the OpenID authorize/discovery caches or drive the OidcClient challenge/callback protocol; the OpenID flow lives in OidcLoginService (#160). Found: " + string.Join(" | ", controllerHits));

        // Liveness against a vacuous pass: the OpenID flow must actually live in OidcLoginService — a move,
        // not a silent removal — so the flow service's own source must contain every moved token.
        var oidcSource = string.Join(
            "\n",
            SourceFilesDeclaring(new[] { typeof(OidcLoginService) }).Select(File.ReadAllText));
        Assert.True(
            markers.All(m => oidcSource.Contains(m, StringComparison.Ordinal)),
            "OidcLoginService must own the OpenID challenge/callback flow, its authorize store, and the discovery read; otherwise the controller scan passes vacuously (#160).");
    }

    [Fact]
    public void Controller_DelegatesSamlFlowToTheFlowService()
    {
        // Locked in by the SAML flow extraction (#160, #318 step 13), the mirror of the OpenID rule above:
        // the SAML challenge, assertion-consumer callback, session-minting authenticate and manual-link
        // bodies, together with the SAML-specific process-wide state (the replay cache and the
        // outstanding-AuthnRequest cache), moved into SamlLoginService. The controller's SAML endpoints now
        // apply the shared rate-limit gate and hand the request to that service, so a CONTROLLER neither
        // holds those SAML caches nor drives the SAML challenge/validation protocol itself. Call-level
        // property, so it is a source scan like the other controller rules above.
        //
        // The two cache tokens are nameof-derived, so a rename of either type fails to COMPILE this rule
        // rather than passing vacuously; the two protocol tokens are the outgoing-request builder
        // (SamlAuthnRequest, which the challenge constructs and signs) and the response validator
        // (ValidateSaml). The shared per-client rate limiter is deliberately NOT a marker — it fronts BOTH
        // protocols, so it lives in the shared SsoRateLimitGate (#160), pinned off the controller by
        // Controller_HoldsNoMutableStaticState, exactly as in the OpenID rule.
        var replayToken = nameof(SamlReplayCache);
        var requestToken = nameof(SamlRequestCache);
        var markers = new[] { replayToken, requestToken, "SamlAuthnRequest", "ValidateSaml" };

        var controllerHits = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => markers.Any(m => l.Text.Contains(m, StringComparison.Ordinal)))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            controllerHits.Count == 0,
            "A controller must not hold the SAML replay/request caches or drive the SAML challenge/validation protocol; the SAML flow lives in SamlLoginService and SamlAssertionValidator (#160, #496). Found: " + string.Join(" | ", controllerHits));

        // Liveness against a vacuous pass: the SAML flow must actually live in the SAML flow tier — a move,
        // not a silent removal — so its own source must contain every moved token. The tier is now two types:
        // SamlLoginService owns the challenge/callback orchestration and the outstanding-request cache
        // (SamlRequestCache, SamlAuthnRequest), and the dedicated SamlAssertionValidator owns the inbound
        // validation and the replay cache (SamlReplayCache, ValidateSaml) it moved into (#496) — so scan both.
        var samlSource = string.Join(
            "\n",
            SourceFilesDeclaring(new[] { typeof(SamlLoginService), typeof(SamlAssertionValidator) }).Select(File.ReadAllText));
        Assert.True(
            markers.All(m => samlSource.Contains(m, StringComparison.Ordinal)),
            "The SAML flow tier (SamlLoginService + SamlAssertionValidator) must own the SAML challenge/callback/authenticate/link flow, its replay/request caches, and the inbound validation; otherwise the controller scan passes vacuously (#160, #496).");
    }

    [Fact]
    public void SharedFlowResponses_OwnTheAuthPageErrorAndLinkWriteResults()
    {
        // Locked in by the shared-helper consolidation (#160, #500): the three HTTP result shapes both flow
        // services need — the security-headered intermediate auth page (the CSP build), the plain-text flow
        // error, and the manual-link write mapping — were duplicated (the controller's HtmlAuthPage +
        // ReturnError, and the OpenID service's PlainTextError twin). They now live once in FlowResponses,
        // which both flow services call, so a CONTROLLER neither builds the CSP auth page nor sets its
        // defensive headers itself. Call-level property, so it is a source scan like the other controller
        // rules above. Markers are the emission tokens: the CSP builder (AuthPageCsp.Build) and the two
        // clickjacking/sniffing headers the auth page sets.
        var markers = new[] { "AuthPageCsp.Build", "X-Frame-Options", "X-Content-Type-Options" };
        var offenders = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => markers.Any(m => l.Text.Contains(m, StringComparison.Ordinal)))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A controller must not build the CSP auth page or set its defensive headers directly; the shared flow-result shapes live in FlowResponses (#160). Found: " + string.Join(" | ", offenders));

        // Liveness against a vacuous pass: the auth page must actually live in FlowResponses — a move, not a
        // silent removal — so its own source must build the CSP and set the frame-options header.
        var sharedSource = string.Join(
            "\n",
            Directory.EnumerateFiles(Path.Combine(RepoRoot(), "SSO-Auth", "Api", "Shared"), "*.cs", SearchOption.AllDirectories)
                .Select(File.ReadAllText));
        Assert.True(
            sharedSource.Contains("AuthPageCsp.Build", StringComparison.Ordinal) && sharedSource.Contains("X-Frame-Options", StringComparison.Ordinal),
            "FlowResponses must own the CSP auth-page render (AuthPageCsp.Build + the defensive headers); otherwise the controller scan passes vacuously (#160).");
    }

    [Fact]
    public void RateLimiting_FlowsThroughLoginOutcome()
    {
        // Locked in by #474: the rate-limit rejection was the last login-path error that bypassed the single
        // mapper. It now flows as LoginOutcome.Throttled through LoginStatusMapper, which is the ONE place the
        // 429 status and its Retry-After header are emitted — so a CONTROLLER neither returns a bare rate-limit
        // ContentResult nor sets Retry-After itself. Call-level property, so it is a source scan like the other
        // controller rules above. Markers are the emission tokens, not prose: the 429 status constant, the
        // typed IHeaderDictionary accessor (".RetryAfter" — the leading dot excludes the "retryAfterSeconds"
        // local the controller still passes into the outcome), and the raw header-name literal.
        var markers = new[] { "Status429TooManyRequests", ".RetryAfter", "Retry-After" };
        var offenders = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => markers.Any(m => l.Text.Contains(m, StringComparison.Ordinal)))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A controller must not emit a rate-limit 429 or set Retry-After directly; route the rejection through LoginOutcome.Throttled and LoginStatusMapper (#474). Found: " + string.Join(" | ", offenders));

        // Liveness against a vacuous pass: the 429 + Retry-After must actually live in the mapper — a move,
        // not a silent removal — so LoginStatusMapper's own source must emit both.
        var mapperSource = string.Join(
            "\n",
            SourceFilesDeclaring(new[] { typeof(LoginStatusMapper) }).Select(File.ReadAllText));
        Assert.True(
            mapperSource.Contains("Status429TooManyRequests", StringComparison.Ordinal) && mapperSource.Contains("RetryAfter", StringComparison.Ordinal),
            "LoginStatusMapper must own the rate-limit 429 and its Retry-After header; otherwise the controller scan passes vacuously (#474).");
    }

    [Fact]
    public void Controller_HoldsNoMutableStaticState()
    {
        // Locked in by the rate-limit-gate extraction (#160, #318): after the OpenID (#500), SAML (#501) and
        // rate-limit (#160) moves, the controller is a stateless request dispatcher — every process-wide
        // store, cache and limiter lives in a flow service or the Shared tier. So a controller holds NO
        // mutable process-wide state as a static field. The former SsoRateLimiter static (the last such on
        // SSOController) moved into SsoRateLimitGate; a new cache/limiter/counter/dictionary dropped back
        // onto ANY controller — the exact regression this rule guards — fails HERE.
        //
        // "Mutable state" is what is forbidden, not every static: a compile-time constant (a const, which is
        // IsLiteral) and an immutable static readonly VALUE (e.g. SSOViewsController's version-derived asset
        // ETag, an EntityTagHeaderValue computed once at load) are fine — they never accumulate runtime
        // state. So a static field is an offender only when it is genuinely mutable: a WRITABLE static (not
        // readonly, so it can be reassigned at runtime), OR a static readonly reference to a state CONTAINER
        // — a *Store/*Cache/*Limiter type, or a raw dictionary — which is readonly-by-reference but mutates
        // internally (exactly the shape SsoRateLimiter had on the controller). Compiler-generated backing
        // fields ('<'-named) are excluded, the same exclusion the other reflection rules use.
        var stateSuffixes = new[] { "Store", "Cache", "Limiter" };
        bool IsStateContainer(Type t) =>
            IsDictionaryLike(t)
            || (t.Assembly == typeof(SSOPlugin).Assembly && stateSuffixes.Any(s => SimpleName(t).EndsWith(s, StringComparison.Ordinal)));

        const BindingFlags statics = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
        var controllers = PluginClasses.Where(t => typeof(ControllerBase).IsAssignableFrom(t)).ToList();

        // Sentinel against a vacuous pass: a controller must be found, or a rename/rebase that lost the
        // ControllerBase base would pass this rule for the wrong reason (as ControllerSourceFiles guards the
        // source-scan rules).
        Assert.True(
            controllers.Count > 0,
            "No controller type was found to check for mutable static state; a controller was renamed or lost its ControllerBase base — update Controller_HoldsNoMutableStaticState.");

        var offenders = controllers
            .SelectMany(t => t.GetFields(statics)
                .Where(f => !f.Name.Contains('<', StringComparison.Ordinal))
                .Where(f => !f.IsLiteral)
                .Where(f => !f.IsInitOnly || IsStateContainer(f.FieldType))
                .Select(f => $"{SimpleName(t)}.{f.Name} ({SimpleName(f.FieldType)})"))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A controller must hold no mutable static state (a writable static, or a static readonly *Store/*Cache/*Limiter or dictionary); every process-wide store/cache/limiter belongs in a flow service or a Shared gate (#160, #318). Found: " + string.Join(", ", offenders));

        // Liveness against a vacuous pass: the rate limiter must actually live in its new home — a move, not
        // a silent removal — so SsoRateLimitGate must own the process-wide SsoRateLimiter instance the
        // controller no longer holds, and it is a state container the offender scan above would catch on a
        // controller (so the rule is proven non-vacuous on the very type that motivated it).
        var gateOwnsLimiter = typeof(SsoRateLimitGate)
            .GetFields(statics)
            .Any(f => f.FieldType == typeof(SsoRateLimiter));
        Assert.True(
            gateOwnsLimiter && IsStateContainer(typeof(SsoRateLimiter)),
            "SsoRateLimitGate must own the process-wide SsoRateLimiter (a state container) that moved off the controller; otherwise the controller scan passes vacuously (#160).");
    }

    [Fact]
    public void LegacyLinkMigration_ReturnsTheAuthoritativeMapping_NotAVoidReKey()
    {
        // Locked in by #363: the #155 legacy-link re-key runs as a SECOND lock acquisition after the
        // candidate-resolving read, so a concurrent login could migrate the same identity between the two.
        // The fix folds the re-key and the re-resolution into one config transaction that RETURNS the
        // authoritative user id, and the caller binds the login to that returned id rather than the
        // pre-migration snapshot. Structurally that means the migration helper must be a value-returning
        // mutation (Guid?), never a fire-and-forget void re-key whose result the caller ignores — a
        // revert to void would silently reopen the window. Reflection over the service's own private
        // methods pins it: any migration helper (name contains "Migrate") must return Guid?.
        var migrationHelpers = typeof(CanonicalLinkService)
            .GetMethods(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
            .Where(m => m.Name.Contains("Migrate", StringComparison.Ordinal))
            .ToList();

        // Sentinel against a vacuous pass: a rename that drops "Migrate" from the helper's name would make
        // the scan match nothing and pass for the wrong reason, so require at least one to exist and force
        // a conscious update of this rule if the naming changes.
        Assert.True(
            migrationHelpers.Count > 0,
            "No legacy-link migration helper (a private method whose name contains \"Migrate\") was found on CanonicalLinkService; it was renamed, so point this rule at the new name so the return-type invariant keeps guarding #363.");

        var voidReKeys = migrationHelpers
            .Where(m => m.ReturnType != typeof(Guid?))
            .Select(m => $"{m.Name} -> {m.ReturnType.Name}")
            .ToList();
        Assert.True(
            voidReKeys.Count == 0,
            "The legacy-link migration must return the authoritative mapping (Guid?) so the login binds to the post-migration state, not a pre-migration snapshot (#363); these do not: " + string.Join(", ", voidReKeys));
    }

    [Fact]
    public void ProviderMode_IsThreadedTyped_NotAsARawStringToken()
    {
        // Locked in by #369: the route's {mode} token is parsed ONCE at the controller boundary into the
        // ProviderMode enum, and the typed value is threaded inward — so no linking-tier method re-accepts
        // the raw string to re-parse or re-compare it (the two former divergent dispatches, a
        // culture-sensitive ToLower() switch and an invariant-lowercase one, that had to agree). Pin it
        // structurally on the two types the token flows through:
        //
        // 1. CanonicalLinkService — the linking workflow: NO method (public or private) may take a parameter
        //    named "mode" typed as string; it must be the ProviderMode enum. A revert to a string mode
        //    parameter (reopening the re-parse-inward hole) fails HERE.
        // 2. VerifiedIdentity.LinkMode — the identity the login path carries: must expose the protocol as the
        //    typed ProviderMode, not a "oid"/"saml" string the mint path would have to re-compare.
        const BindingFlags anyMethod = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
        var methods = typeof(CanonicalLinkService).GetMethods(anyMethod);

        var stringModeParams = methods
            .SelectMany(m => m.GetParameters().Select(p => (Method: m.Name, Param: p)))
            .Where(x => x.Param.Name == "mode" && x.Param.ParameterType == typeof(string))
            .Select(x => $"{x.Method}(string mode)")
            .ToList();
        Assert.True(
            stringModeParams.Count == 0,
            "CanonicalLinkService must take the parsed ProviderMode, never a raw string mode token, so the {mode} route string is parsed once at the boundary and threaded typed inward (#369): " + string.Join(", ", stringModeParams));

        // Sentinel against a vacuous pass: a ProviderMode-typed mode parameter must actually exist on the
        // surface, so a rename that dropped the parameter entirely does not pass for the wrong reason.
        var typedModeExists = methods
            .SelectMany(m => m.GetParameters())
            .Any(p => p.Name == "mode" && p.ParameterType == typeof(ProviderMode));
        Assert.True(
            typedModeExists,
            "No ProviderMode-typed \"mode\" parameter was found on CanonicalLinkService; the linking surface was renamed, so point this rule at the new shape so the typed-mode invariant keeps guarding #369.");

        var linkMode = typeof(VerifiedIdentity).GetProperty("LinkMode", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.True(linkMode is not null, "VerifiedIdentity.LinkMode was renamed or removed; point this rule at the new property so the typed-mode invariant keeps guarding #369.");
        Assert.True(
            linkMode!.PropertyType == typeof(ProviderMode),
            "VerifiedIdentity.LinkMode must be the typed ProviderMode, not a raw \"oid\"/\"saml\" string the mint path would re-compare (#369).");
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

    [Fact]
    public void ProviderFormFieldIds_MatchOidConfigProperties()
    {
        // The provider settings form's save contract (#365), locked in as a fitness function. config.js
        // saveProvider persists each marked input as current_config[element.id] = value, so every input
        // bearing a persisting behavior-marker class MUST have an id equal to a real OidConfig property —
        // otherwise it renders but silently never saves, because the server drops JSON members that are not
        // OidConfig properties. The five marker classes mirror config.js listArgumentsByType
        // (sso-text/sso-line-list/sso-toggle) plus the two populate-helper widgets (sso-folder-list =
        // EnabledFolders, sso-role-map = FolderRoleMapping). The provider-name input is deliberately
        // unmarked — its value is the OidConfigs dictionary key, not a property — so it is not scanned.
        // Matching is token-exact (so sso-role-map does not swallow sso-role-mapping-container), and the
        // scan is scoped to #sso-new-oidc-provider so a future SAML form (whose fields map to SamlConfig)
        // would not be checked against OidConfig. The forward check (every marked id is a real property) is
        // paired below with a reverse pin (every security-critical property is still a marked field), so
        // neither a mistyped id nor a dropped marker class can silently break a security setting's save.
        var markerClasses = new[] { "sso-text", "sso-line-list", "sso-toggle", "sso-folder-list", "sso-role-map" };

        var form = OidcProviderFormMarkup(
            File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Config", "configPage.html")));

        var oidConfigProperties = typeof(OidConfig)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .ToHashSet(StringComparer.Ordinal);

        var matchedIds = new HashSet<string>(StringComparer.Ordinal);
        var offenders = new List<string>();
        foreach (Match tag in Regex.Matches(form, "<[a-zA-Z][^>]*>", RegexOptions.Singleline))
        {
            var classAttr = Regex.Match(tag.Value, "class=\"([^\"]*)\"", RegexOptions.Singleline);
            if (!classAttr.Success)
            {
                continue;
            }

            var classes = classAttr.Groups[1].Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (!classes.Any(c => markerClasses.Contains(c, StringComparer.Ordinal)))
            {
                continue;
            }

            // (?<![-\w]) so an attribute whose name merely ends in "id" (a future data-id, gridid, …) is
            // not misread as the element id; an id attribute is preceded by whitespace or the tag open.
            var idMatch = Regex.Match(tag.Value, "(?<![-\\w])id=\"([^\"]*)\"", RegexOptions.Singleline);
            var id = idMatch.Success ? idMatch.Groups[1].Value : "(no id)";
            matchedIds.Add(id);
            if (!oidConfigProperties.Contains(id))
            {
                offenders.Add($"{id} (classes: {classAttr.Groups[1].Value.Trim()})");
            }
        }

        // Guard against a vacuous pass (a broken regex or a renamed form marker silently matching nothing):
        // one sentinel id per marker class must have been scanned, proving the parser reached the form and
        // every marker class is live.
        var sentinels = new[] { "OidEndpoint", "Roles", "Enabled", "EnabledFolders", "FolderRoleMapping" };
        var missingSentinels = sentinels.Where(s => !matchedIds.Contains(s)).ToList();
        Assert.True(
            missingSentinels.Count == 0,
            "The provider-form scan did not reach expected fields (broken parse or renamed marker class?); missing sentinels: " + string.Join(", ", missingSentinels));

        // Reverse direction: the forward check catches a mistyped id, but dropping a marker class entirely
        // — the exact operation this contract change performs on the provider-name field — would silently
        // stop a field persisting while leaving the forward check green. For a security setting that is
        // fail-open (the server keeps the stored value; the admin can no longer harden it), so pin the
        // security-critical settings: each MUST remain a marked, correctly-typed persisting field. Extend
        // this roster in the same PR that surfaces a new security toggle in the admin form; a deliberately
        // XML-only toggle is not a form field and so stays out of this roster until it is surfaced (as
        // RequireVerifiedEmailForAdoption was, #484/#488, and RequireVerifiedEmailForLogin was, #524).
        var securityCritical = new[]
        {
            "EnableAuthorization", "OidSecret", "DisableHttps", "DisablePushedAuthorization",
            "DoNotValidateEndpoints", "DoNotValidateIssuerName", "DoNotValidateResponseIssuer",
            "DoNotLoadProfile", "RequirePkce", "AllowExistingAccountLink",
            "RequireVerifiedEmailForAdoption", "RequireVerifiedEmailForLogin",
        };
        var unsaved = securityCritical.Where(p => !matchedIds.Contains(p)).ToList();
        Assert.True(
            unsaved.Count == 0,
            "These security-critical settings must remain persisting provider-form fields (a marked input whose id equals the OidConfig property); missing or unmarked: " + string.Join(", ", unsaved));

        Assert.True(
            offenders.Count == 0,
            "Every persisting provider-form field (sso-text/sso-line-list/sso-toggle/sso-folder-list/sso-role-map) must have an id equal to an OidConfig property; these do not: " + string.Join(" | ", offenders));
    }

    // The markup of the #sso-new-oidc-provider settings form (from the opening tag's id attribute to its
    // closing </form>). Forms are not nested here, so the first </form> after the id marker closes it; the
    // preceding #sso-load-config form is left out because its </form> sits before the marker.
    private static string OidcProviderFormMarkup(string html)
    {
        const string marker = "id=\"sso-new-oidc-provider\"";
        var start = html.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "The #sso-new-oidc-provider form was not found in configPage.html.");
        var end = html.IndexOf("</form>", start, StringComparison.Ordinal);
        Assert.True(end > start, "The #sso-new-oidc-provider form has no closing </form> tag.");
        return html[start..end];
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

    // Every source file that declares a controller type, discovered from reflection so the controller
    // source scans follow the planned #318 controller split automatically (#388): reflection names the
    // controller TYPES (deriving from ControllerBase); the files are those declaring them — a partial-class
    // split declares one type across several files, a multi-controller split adds more types, and both are
    // found. Matching the declaration in the file body, not the file name, also survives a controller file
    // rename. The set must be non-empty: a scan reading no file would pass every controller rule vacuously,
    // so a controller reflection can no longer find (removed base type, moved out of the source tree) fails
    // loudly here rather than turning the rules into silent no-ops.
    private static IReadOnlyList<string> ControllerSourceFiles()
    {
        var controllerTypes = PluginClasses.Where(t => typeof(ControllerBase).IsAssignableFrom(t));
        var files = SourceFilesDeclaring(controllerTypes);

        Assert.True(
            files.Count > 0,
            "No controller source file was found to scan; a controller was renamed, moved out of SSO-Auth, or lost its ControllerBase base, so the controller source scans would pass vacuously — update ControllerSourceFiles (#388).");
        return files;
    }

    // Every source file that declares any of the given types, matched by class declaration in the file
    // body (not the file name), so a file rename still resolves via the type's own name. Shared by
    // ControllerSourceFiles above and the raw socket/DNS liveness check (#444) — both need "which files
    // declare these types", just for a different type set.
    private static IReadOnlyList<string> SourceFilesDeclaring(IEnumerable<Type> types)
    {
        var declarations = types
            .Select(t => new Regex($@"\bclass\s+{Regex.Escape(SimpleName(t))}\b"))
            .ToList();

        return Directory
            .EnumerateFiles(Path.Combine(RepoRoot(), "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Where(path => declarations.Any(d => d.IsMatch(File.ReadAllText(path))))
            .ToList();
    }

    // obj/bin hold generated and compiled output; the source scans read hand-written source only.
    private static bool IsBuildOutput(string path) =>
        path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        || path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal);

    // The repository root, derived from this test file's compile-time path (<root>/SSO-Auth.Tests/<file>).
    // CallerFilePath is baked in at build, and CI builds on the same checkout it tests, so the source tree
    // is present for the source-scan rule above.
    private static string RepoRoot([CallerFilePath] string thisFilePath = "") =>
        Directory.GetParent(Path.GetDirectoryName(thisFilePath)!)!.FullName;
}

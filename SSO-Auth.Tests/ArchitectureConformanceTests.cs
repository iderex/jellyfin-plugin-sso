// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.SSO_Auth.Api.Routing;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
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

    // Module-boundary fitness function of the #777 folder migration: each extracted module may import ONLY the
    // Api modules explicitly allowed for it (a leaf allows none), pinning the module dependency DAG. Enforced at
    // the IMPORT level, which also catches method-body coupling (reflection over signatures would miss a
    // body-only call): using a type from another Api module requires importing its namespace. Importing NON-Api
    // namespaces (e.g. the Config persistence model or the still-unmigrated flat Api core) stays allowed, and a
    // file never imports its own module namespace. As each module lands (#777) it registers a case here with its
    // allowed dependencies; together the cases lock in the DAG and forbid a cycle.
    [Theory]
    [InlineData("Net")] // leaf — networking / URL / SSRF primitives: IpAddressClassifier, CanonicalBaseUrl, SsoHttp
    [InlineData("Secrets")] // leaf — secrets at rest: SecretStore, SecretEnvelope, ConfigSecretProtection
    [InlineData("Audit")] // leaf — append-only audit logging: SsoAudit
    [InlineData("Avatar", "Net", "RateLimit")] // avatar fetch — validates targets through the Net SSRF classifier, per-user store locks via KeyedLockStore (RateLimit)
    [InlineData("RateLimit", "Net")] // login throttling — keys buckets by the Net client-IP classifier
    [InlineData("Authz")] // leaf — role→permission mapping: PermissionGrant, PermissionRolePolicy, RolePrivilegeMapper
    [InlineData("Routing")] // leaf — the plugin's route-shape contract: RouteSuffix ({protocol}/{path-kind}/{provider} reader), ChallengePath (new/legacy classifier)
    [InlineData("Crypto")] // leaf — the shared asymmetric signing-key strength policy (min RSA bits / approved EC curves), referenced by both protocol paths so they cannot drift (#733)
    [InlineData("LoginButtons")] // leaf — login-page button rendering (#722): pure injector/builder over the config + a branding-sync hosted service; imports no other Api module
    [InlineData("Logout")] // leaf — Single Logout session-state store (#727): pure bounded operations over the config's LogoutSessions map; imports no other Api module


    [InlineData("Provider", "Net", "RateLimit")] // provider config/test/naming — validates URLs (Net) and keys throttles (RateLimit)
    [InlineData("Linking", "Audit", "Provider", "RateLimit")] // account linking — audits writes, validates providers, throttles
    [InlineData("Saml", "Authz", "Crypto", "Identity", "RateLimit", "Session")] // SAML core/validators — mints the keystone (Identity), returns login outcomes (Session), maps roles (Authz), throttles (RateLimit), enforces the signing-key floor (Crypto)
    [InlineData("Oidc", "Authz", "Avatar", "Crypto", "Identity", "Logout", "Net", "Provider", "RateLimit", "Routing")] // OIDC flow — mints the keystone (Identity), orchestrates roles, avatar, net, provider, throttle; reads its callback path through the Routing suffix reader; enforces the signing-key floor (Crypto); carries the captured logout context (Logout, #727)
    [InlineData("Identity", "Authz", "Provider")] // the identity keystone — grants (Authz) + link mode (Provider); decoupled from the protocols by #790
    [InlineData("Session", "Authz", "Avatar", "Linking")] // session mint + login outcomes — applies grants (Authz), sets avatars (Avatar), reconciles links (Linking)
    [InlineData("Shared", "Avatar", "Linking", "RateLimit", "Routing", "Session")] // shared served-page / flow-response + rate-limit-gate helpers — depend downward on the session/linking/avatar/throttle/route tiers, never on a protocol or the boundary
    [InlineData("Flows", "Audit", "Identity", "Linking", "Logout", "Net", "Oidc", "Provider", "RateLimit", "Saml", "Session", "Shared")] // per-protocol login orchestration — drives both protocol modules (Oidc/Saml) and the downstream mint/link/session tiers; persists the captured logout state at the mint (Logout, #727); nothing above the boundary imports it
    [InlineData("Http", "Audit", "Avatar", "Flows", "Linking", "Logout", "Net", "Oidc", "Provider", "Saml", "Session", "Shared")] // the web boundary (SSOController + request helpers + the admin test-connection probe): the composition top of the DAG — it fronts every flow, so its import list is deliberately wide (incl. the RP-initiated logout store, #727); nothing imports it back (#790/#807)
    public void ApiModule_ImportsOnlyItsAllowedApiModules(string module, params string[] allowed)
    {
        var moduleDir = Path.Combine(RepoRoot(), "SSO-Auth", "Api", module);
        var permitted = new HashSet<string>(allowed) { module };
        var offenders = Directory.EnumerateFiles(moduleDir, "*.cs")
            .SelectMany(file => File.ReadLines(file)
                .Select(line => Regex.Match(line, @"^\s*using\s+Jellyfin\.Plugin\.SSO_Auth\.Api\.(?<mod>[A-Za-z0-9_]+)\s*;"))
                .Where(m => m.Success && !permitted.Contains(m.Groups["mod"].Value))
                .Select(m => Path.GetFileName(file) + ": " + m.Value.Trim()))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"The {module} module may import only [{string.Join(", ", allowed)}] among Api modules; these imports break that: " + string.Join(" | ", offenders));
    }

    [Fact]
    public void FlatApi_HoldsNoSourceFiles_EveryApiTypeLivesInAModule()
    {
        // The kernel dissolution is complete and locked (#790/#807): there is NO code directly in
        // SSO-Auth/Api/ — every type lives in a named module subfolder (Net, Secrets, …, Http). The former
        // flat "kernel" that once held the controller, the URL builders, the keystone and the served-page
        // types was a deliberate, transitional bucket; it is now empty and must stay empty, so a new type is
        // forced into a module (or a new one) at creation and can never re-accumulate a flat pile.
        var apiRoot = Path.Combine(RepoRoot(), "SSO-Auth", "Api");
        var flatFiles = Directory.EnumerateFiles(apiRoot, "*.cs", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileName)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            flatFiles.Count == 0,
            "SSO-Auth/Api/ must hold no source files directly — every Api type belongs in a module subfolder (#790/#807). Found in the flat Api root: " + string.Join(", ", flatFiles));
    }

    [Fact]
    public void ModuleTests_MirrorTheSourceModuleFolders()
    {
        // #791: a test that covers a type in Api/<Module>/ lives under SSO-Auth.Tests/<Module>/, so a test is
        // as easy to place and find as the code it covers, and the test tree cannot drift back into a flat
        // pile. Governs the per-source-module tests (found by the <Type> -> <Type>Tests.cs naming); the
        // SSOController split tests (SSOController*Tests, which sit under Http/ next to the controller source),
        // the Config, and the shared-infrastructure tests are organised in their own folders (Config, _Support,
        // …) and have no exact <Type>Tests.cs source match, so they are out of scope here. A type with no
        // matching test file is simply skipped.
        var apiRoot = Path.Combine(RepoRoot(), "SSO-Auth", "Api");
        var testsRoot = Path.Combine(RepoRoot(), "SSO-Auth.Tests");
        var testFiles = Directory.EnumerateFiles(testsRoot, "*Tests.cs", SearchOption.AllDirectories)
            .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !p.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .ToList();

        var offenders = new List<string>();
        foreach (var src in Directory.EnumerateFiles(apiRoot, "*.cs", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(apiRoot, src);
            var separator = relative.IndexOf(Path.DirectorySeparatorChar);
            if (separator < 0)
            {
                continue; // a flat Api/ kernel file — not module-scoped
            }

            var module = relative[..separator];
            var expectedDir = Path.Combine(testsRoot, module) + Path.DirectorySeparatorChar;
            var testName = Path.GetFileNameWithoutExtension(src) + "Tests.cs";
            var test = testFiles.FirstOrDefault(p => string.Equals(Path.GetFileName(p), testName, StringComparison.Ordinal));
            if (test is not null && !test.StartsWith(expectedDir, StringComparison.Ordinal))
            {
                offenders.Add($"{testName} (covers Api/{module}) is at {Path.GetRelativePath(testsRoot, test)} — expected under {module}/");
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Each module's tests must mirror its source folder under SSO-Auth.Tests/<Module>/ (#791): " + string.Join(" | ", offenders));
    }

    [Fact]
    public void SourceModuleNamespaces_MirrorTheirFolder()
    {
        // #873: every type in Api/<Module>/ declares namespace <Root>.Api.<Module>, so the namespace and the
        // folder can never drift apart. RequestHelpers once sat physically in Api/Http/ under the stale
        // namespace ...Helpers and no fitness function caught it until #867 moved it; this locks the invariant
        // in as an executable guard. Files directly in the flat Api/ root are out of scope — FlatApi_HoldsNoSourceFiles
        // keeps that empty.
        var apiRoot = Path.Combine(RepoRoot(), "SSO-Auth", "Api");
        var offenders = new List<string>();
        foreach (var src in Directory.EnumerateFiles(apiRoot, "*.cs", SearchOption.AllDirectories))
        {
            if (src.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || src.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            {
                continue;
            }

            var relative = Path.GetRelativePath(apiRoot, src);
            var separator = relative.IndexOf(Path.DirectorySeparatorChar);
            if (separator < 0)
            {
                continue; // a flat Api/ file — not module-scoped
            }

            var module = relative[..separator];
            var expected = $"{Root}.Api.{module}";
            var declared = File.ReadLines(src)
                .Select(line => line.Trim())
                .FirstOrDefault(line => line.StartsWith("namespace ", StringComparison.Ordinal))
                ?.Substring("namespace ".Length)
                .TrimEnd(';', ' ', '{');
            if (!string.Equals(declared, expected, StringComparison.Ordinal))
            {
                offenders.Add($"Api/{relative} declares '{declared ?? "(no namespace)"}' — expected '{expected}'");
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Every type in Api/<Module>/ must declare namespace <Root>.Api.<Module> so the namespace and folder cannot drift (#873): " + string.Join(" | ", offenders));
    }

    [Fact]
    public void InternalDocumentationGate_StaysEnforced()
    {
        // #864/#873 — guard for the guard. The internal-surface XML-doc completeness gate rests on two
        // switches that a single quiet edit could disable: SA1600 must stay at warning-or-error in
        // .editorconfig (CI's warnaserror turns it into a build failure), and stylecop.json must keep
        // documentInternalElements=true (without it SA1600 checks only the public surface). Neither is
        // exercised by any other test, so pin both here — a revert to none, suggestion, silent, or
        // documentInternalElements=false fails this test rather than silently reopening the internal API to
        // undocumented members.
        var editorConfig = File.ReadAllText(Path.Combine(RepoRoot(), ".editorconfig"));
        var severity = editorConfig
            .Split('\n')
            .Select(line => line.Trim())
            .FirstOrDefault(line => line.StartsWith("dotnet_diagnostic.SA1600.severity", StringComparison.Ordinal));
        Assert.True(
            severity is not null && (severity.EndsWith("= warning", StringComparison.Ordinal) || severity.EndsWith("= error", StringComparison.Ordinal)),
            $"SA1600 must stay enforced (warning or error) so the #864 internal-doc gate cannot be silently switched off — found: '{severity ?? "(missing)"}'.");

        var styleCop = File.ReadAllText(Path.Combine(RepoRoot(), "stylecop.json"));
        Assert.Contains("\"documentInternalElements\": true", styleCop, StringComparison.Ordinal);
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
        // - PluginConfiguration._logoutSessions: the persisted Single Logout session map (#727) — serialized
        //   config mutated only under the config lock via SessionLogoutStore, so it is config state, not
        //   in-flight state; the store type (SessionLogoutStore) holds the bounding logic, not the field.
        var storeLike = new[] { "Store", "Cache", "Limiter" };
        var exemptions = new[] { "ProviderConfigBase._canonicalLinks", "OidConfig._canonicalLinkIssuers", "PluginConfiguration._logoutSessions" };

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
        // 2. Source scan: each factory is INVOKED only from its protocol's validator. FromValidatedOidc
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
        const string oidcFactory = "FromValidatedOidc";
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
        var minterSource = File.ReadAllLines(Path.Combine(RepoRoot(), "SSO-Auth", "Api", "Session", "SessionMinter.cs"));
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
    public void IsDisabledIsWrittenOnlyOnTheNewAccountProvisioningArm()
    {
        // Locked in by #737. IsDisabled is a lockout vector: the plugin deliberately never disabled an
        // account until the pending-approval provisioning feature, and it is barred from SSO role mapping
        // (PermissionRolePolicy) so no login can disable an EXISTING account. The one sanctioned write —
        // provisioning a BRAND-NEW account inert for admin approval — must stay confined to
        // CanonicalLinkService (the single create seam). A source scan pins that: any future
        // SetPermission(PermissionKind.IsDisabled, ...) elsewhere (a mint path, a role mapper, a controller)
        // would reopen the "an SSO login disabled my account" surface and fails here instead of shipping.
        var apiRoot = Path.Combine(RepoRoot(), "SSO-Auth", "Api");
        var offenders = new List<string>();
        foreach (var src in Directory.EnumerateFiles(apiRoot, "*.cs", SearchOption.AllDirectories))
        {
            var lines = File.ReadAllLines(src);
            for (var i = 0; i < lines.Length; i++)
            {
                if (lines[i].Contains("SetPermission(PermissionKind.IsDisabled", StringComparison.Ordinal)
                    && !src.EndsWith(Path.Combine("Linking", "CanonicalLinkService.cs"), StringComparison.Ordinal))
                {
                    offenders.Add($"{Path.GetFileName(src)}:{i + 1}");
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            "IsDisabled may be written only on CanonicalLinkService's new-account provisioning arm (#737). Writing it elsewhere can disable an existing account via SSO — a lockout vector. Offending sites: " + string.Join(", ", offenders));
    }

    [Fact]
    public void OidcRedirectUriField_IsReadOnlyAndUnmarked_AndDerivesFromTheSameBaseTheLoginUses()
    {
        // #724: the config page shows the exact redirect_uri the login uses so an admin registers it verbatim
        // (a mismatch is the most common OIDC setup failure). Structural properties a JS runtime test cannot
        // pin (no JS harness exists), locked as a source scan:
        //  - the field is READ-ONLY and carries NO sso-* marker class, so it never becomes a persisting field
        //    (it is not an OidConfig property; ProviderFormFieldIds_MatchOidConfigProperties stays green);
        //  - its value is set via .value, never innerHTML (#221);
        //  - it derives from the Base URL Override (the same canonical base the server's OidcRedirectUriBuilder
        //    uses) plus the fixed /sso/OID/redirect/ path — deriving from anything else would display a URI the
        //    login does not actually send;
        //  - the copy confirmation is announced through an aria-live region (not colour-only).
        var html = File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "configPage.html"));
        var js = File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "config.js"));

        var field = Regex.Match(html, "<input\\b[^>]*id=\"OidRedirectUri\"[^>]*>", RegexOptions.Singleline);
        Assert.True(field.Success, "The read-only #OidRedirectUri field must exist in configPage.html (#724).");
        Assert.Contains("readonly", field.Value, StringComparison.Ordinal);
        Assert.DoesNotMatch(new Regex("class=\"[^\"]*sso-(text|line-list|toggle|folder-list|role-map)"), field.Value);

        // The copy confirmation is a live region, not a colour-only signal.
        Assert.Matches(new Regex("id=\"OidRedirectUri-copied\"[^>]*aria-live", RegexOptions.Singleline), html);

        // config.js derives from the base-URL override + the fixed server path, and writes via .value.
        Assert.Contains("/sso/OID/redirect/", js, StringComparison.Ordinal);
        Assert.Matches(new Regex("computeRedirectUri[\\s\\S]{0,500}BaseUrlOverride", RegexOptions.Singleline), js);
        // It normalizes the base through the URL parser so the shown value matches the server's System.Uri
        // canonicalization (lowercased scheme/host, default port elided) — deriving from the raw override
        // string would display a URI the login does not send (a redirect_uri mismatch). Pinned on the exact
        // origin+pathname derivation, which is unique to computeRedirectUri.
        Assert.Contains("new URL(raw)", js, StringComparison.Ordinal);
        Assert.Matches(new Regex("\\.origin\\s*\\+\\s*[A-Za-z_$][\\w$]*\\.pathname", RegexOptions.Singleline), js);
        Assert.Matches(new Regex("#OidRedirectUri\"\\)[\\s\\S]{0,200}\\.value\\s*=", RegexOptions.Singleline), js);
        Assert.DoesNotMatch(new Regex("OidRedirectUri[\\s\\S]{0,200}innerHTML", RegexOptions.Singleline), js);
    }

    [Fact]
    public void OidcStepUpGate_ReadsAcrFromTheSignatureVerifiedIdToken_NotTheUserInfoMergedPrincipal()
    {
        // Locked in by #757. With LoadProfile on (the default), OidcClient merges the UNSIGNED UserInfo
        // response into result.User, so the step-up / MFA gate MUST read the acr from the raw, signature-
        // verified id_token (result.IdentityToken via OidcIdTokenAcr), never from result.User — otherwise a
        // UserInfo-supplied acr could satisfy a step-up requirement the session never actually met. This is a
        // call-site property invisible to a unit test (the gate would still pass its behavioural tests reading
        // from either source when they happen to agree), so it is pinned as a source scan: a refactor that
        // sources the acr from the merged principal reopens the gap and fails here.
        var source = File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Api", "Flows", "OidcLoginService.cs"));

        Assert.Contains("OidcIdTokenAcr.Read(result.IdentityToken)", source, StringComparison.Ordinal);
        Assert.DoesNotMatch(new Regex("result\\.User\\.Claims[^;]*\"acr\"", RegexOptions.Singleline), source);
    }

    [Fact]
    public void OidcAuthorizeState_IsKeyedOnUtc_NotMachineLocalTime()
    {
        // Locked in by #676: the in-flight OpenID authorize-state store keys its lifetime/expiry on the
        // instant the challenge stamps (the Pending's Created) and the callback/redeem legs compare against
        // (PruneExpired / PeekCurrent / TryRedeem). That instant MUST be UTC (DateTime.UtcNow), never
        // machine-LOCAL wall-clock (DateTime.Now): on a DST transition or a clock step local time jumps, so
        // a machine-local basis can expire a valid authorize state early — or shift its window — and
        // spuriously fail an otherwise-valid login. The SAML flow already keeps a UTC basis; this pins the
        // OpenID side to the same one. Call-level property, so it is a source scan like the controller /
        // SessionMinter rules above — the store TAKES `now` as a parameter, so the clock choice lives
        // entirely at these call sites and is invisible to a store-level unit test (which injects its own
        // clock and so passes with EITHER basis). The production code passes the clock inline at each site.
        //
        // Deliberately NOT in scope: the _newPathPersistGate.TryEnter(DateTime.Now) throttle in the same
        // file (and its SAML twin) — a best-effort config-persist throttle, not the authorize-state
        // lifetime; its clock jitter is harmless and it stays symmetric with the SAML side. The markers
        // below are scoped to the store's clock-bearing calls, so that line is out of scope by construction.
        var oidcSource = SourceFilesDeclaring(new[] { typeof(OidcLoginService) });
        Assert.True(
            oidcSource.Count == 1,
            "OidcLoginService's source file was not found (renamed/moved); point OidcAuthorizeState_IsKeyedOnUtc_NotMachineLocalTime at its new location so the UTC-basis scan keeps guarding #676.");

        var lines = File.ReadAllLines(oidcSource[0]);
        var storeClockMarkers = new[]
        {
            "StateStore.PruneExpired(", "StateStore.PeekCurrent(", "StateStore.TryRedeem(", "new AuthorizeSession.Pending(",
        };

        foreach (var marker in storeClockMarkers)
        {
            var markerLines = lines
                .Select((line, index) => (Text: line.Trim(), Number: index + 1))
                .Where(l => l.Text.Contains(marker, StringComparison.Ordinal))
                .ToList();

            // Liveness against a vacuous pass: the store's clock-bearing call site must still exist, or the
            // scan guards nothing — a rename/restructure of the flow fails HERE and forces a conscious
            // update of this rule (as the other source scans' sentinels do). "DateTime.Now" is not a
            // substring of "DateTime.UtcNow", so a correct UtcNow site never trips the machine-local check.
            Assert.True(
                markerLines.Count > 0,
                $"The OIDC authorize-state call site \"{marker}\" was not found in OidcLoginService; it was renamed or restructured, so update OidcAuthorizeState_IsKeyedOnUtc_NotMachineLocalTime so the UTC-basis scan keeps guarding #676.");

            var offenders = markerLines
                .Where(l => l.Text.Contains("DateTime.Now", StringComparison.Ordinal) || !l.Text.Contains("DateTime.UtcNow", StringComparison.Ordinal))
                .Select(l => $"line {l.Number}: {l.Text}")
                .ToList();
            Assert.True(
                offenders.Count == 0,
                $"Every OIDC authorize-state \"{marker}\" call must key on DateTime.UtcNow, never machine-local DateTime.Now, so a DST transition or clock step cannot expire a valid login early (#676). Found: " + string.Join(" | ", offenders));
        }
    }

    [Fact]
    public void SsoManagedProviderId_IsPinnedAndUsedByBothStampAndDetector()
    {
        // SECURITY / PERSISTENCE pin (#837). This exact string is written to User.AuthenticationProviderId
        // and persisted in Jellyfin's user database: every SSO-managed account provisioned by any version
        // carries it, the stamp (CanonicalLinkService) writes it, and the SSO-only detector
        // (SsoAuthenticationProviders.IsSsoProvider) compares against it. It MUST NEVER change — a different
        // value silently stops recognizing every existing SSO account — and it MUST stay decoupled from
        // typeof(SSOController).FullName so a future move of that type (e.g. into an Api.Http module, #807)
        // cannot orphan those accounts. The value equals the controller's historical full type name; that is
        // a coincidence of history, not a live coupling.
        Assert.Equal("Jellyfin.Plugin.SSO_Auth.Api.SSOController", SsoManagedProviderId.Value);

        // The detector resolves to the same pinned value, so the stamp and the detector can never disagree.
        Assert.Equal(SsoManagedProviderId.Value, SsoAuthenticationProviders.SsoProviderId);

        // The stamp uses the pin, and neither the stamp nor the detector recomputes the id from the
        // controller type. Source scans, so a regression to type-coupling fails here even if today's value
        // still happens to match.
        var stampSource = string.Join("\n", SourceFilesDeclaring(new[] { typeof(CanonicalLinkService) }).Select(File.ReadAllText));
        var detectorSource = string.Join("\n", SourceFilesDeclaring(new[] { typeof(SsoAuthenticationProviders) }).Select(File.ReadAllText));
        Assert.Contains("SsoManagedProviderId.Value", stampSource, StringComparison.Ordinal);
        Assert.DoesNotContain("typeof(SSOController)", stampSource, StringComparison.Ordinal);
        Assert.DoesNotContain("typeof(SSOController)", detectorSource, StringComparison.Ordinal);
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
    public void FlowServices_DoNotDuplicateChallengeNewPathResolution()
    {
        // Locked in by #670: the near-identical ResolveChallengeNewPath resolver — and its
        // _newPathPersistGate persist-throttle — that OidcLoginService and SamlLoginService each carried
        // (~40 lines apiece, differing only in which provider map the Mutate delegate re-resolved against)
        // are now ONE generic helper in ChallengeNewPathResolver (Api/Shared), with a single shared gate. Pin
        // by reflection that NEITHER flow service re-declares its own copy of either member, so the
        // duplication (and a second, divergent throttle) cannot silently reappear.
        const BindingFlags all = BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
        var flowServices = new[] { typeof(OidcLoginService), typeof(SamlLoginService) };

        var offenders = flowServices
            .SelectMany(t => t.GetMethods(all)
                .Where(m => m.Name == "ResolveChallengeNewPath")
                .Select(m => $"{SimpleName(t)}.{m.Name} (method)")
                .Concat(t.GetFields(all)
                    .Where(f => f.Name == "_newPathPersistGate")
                    .Select(f => $"{SimpleName(t)}.{f.Name} (field)")))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Neither flow service may declare its own ResolveChallengeNewPath method or _newPathPersistGate field; the single generic resolver and its one shared throttle live in ChallengeNewPathResolver (Api/Shared) (#670). Found: " + string.Join(", ", offenders));

        // Liveness against a vacuous pass: the shared resolver must actually own both — a move, not a silent
        // removal — so ChallengeNewPathResolver must declare the resolver method and the single gate field.
        var resolver = typeof(ChallengeNewPathResolver);
        Assert.True(
            resolver.GetMethods(all).Any(m => m.Name == "ResolveChallengeNewPath"),
            "ChallengeNewPathResolver must own the ResolveChallengeNewPath resolver; otherwise the flow-service scan passes vacuously (#670).");
        Assert.True(
            resolver.GetFields(all).Any(f => f.Name == "_newPathPersistGate" && f.FieldType == typeof(IntervalGate)),
            "ChallengeNewPathResolver must own the single _newPathPersistGate IntervalGate; otherwise the flow-service scan passes vacuously (#670).");
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
    public void RateLimitEndpointClass_UsesTypedConstants_NotLiterals()
    {
        // Locked in by #694: the per-client rate-limit bucket key is built as `class + ":" + clientKey` in
        // SsoRateLimitGate.Check, so the endpoint-class string IS the limiter grouping. Passed as a bare
        // literal at each call site, a single typo ("challange") compiles cleanly and silently mints a
        // separate, empty bucket — weakening the rate limit undetectably, with nothing to fail. Every call
        // site now references a SsoRateLimitClass member instead, so a typo is a compile error; this rule
        // forbids a raw literal from creeping back in. Call-level property, so it is a source scan like the
        // other controller rules above. The scan covers BOTH the controller's RateLimitCheck wrapper and any
        // direct SsoRateLimitGate.Check invocation (belt-and-braces: a future controller could call the gate
        // straight, bypassing the wrapper), and flags a string-literal FIRST argument to either — never the
        // typed SsoRateLimitClass member reference.
        var literalCall = new Regex("(?:RateLimitCheck|SsoRateLimitGate\\.Check)\\(\\s*\"");
        var offenders = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => literalCall.IsMatch(l.Text))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A rate-limited endpoint must pass its endpoint class as a SsoRateLimitClass member, never a raw string literal — a literal typo silently mints a separate empty limiter bucket (#694). Found: " + string.Join(" | ", offenders));

        // Sentinel against a vacuous pass: the scan only means something while the typed call sites exist. A
        // rename of the wrapper or a restructure that dropped every RateLimitCheck call would make the
        // offender scan match nothing and pass for the wrong reason, so pin the count of typed call sites. All
        // rate-limited endpoints route through the RateLimitCheck(SsoRateLimitClass.X) wrapper today; extend
        // this expected count in the same PR that adds or removes a rate-limited endpoint (as the provider-form
        // roster rules do), so a change to the limiter surface is a conscious update here rather than a silent
        // drift the offender scan cannot see.
        const int expectedTypedCallSites = 13;
        var typedCall = new Regex("RateLimitCheck\\(\\s*SsoRateLimitClass\\.");
        var typedCallSites = ControllerSourceFiles()
            .Sum(path => typedCall.Matches(File.ReadAllText(path)).Count);

        Assert.True(
            typedCallSites == expectedTypedCallSites,
            $"Expected {expectedTypedCallSites} typed RateLimitCheck(SsoRateLimitClass.X) call sites (#694); found {typedCallSites}. A rate-limited endpoint was added or removed — update this sentinel in the same PR so the literal scan cannot pass vacuously.");
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
    public void RawServedLinkingPage_ContainsNoDashboardLocalizationPlaceholders()
    {
        // The self-service linking page is served raw by SSOViewsController.GetView (route
        // /SSOViews/linking) — no Jellyfin dashboard, so no localization pass runs. A ${...} token the
        // dashboard would substitute therefore leaks to the end user verbatim (the ${Help} button label
        // was the live case, #666). Scan the raw-served page for such placeholders, ignoring inline
        // <script> blocks where ${...} is a legitimate JS template-literal interpolation, not a
        // dashboard token.
        var html = File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "linking.html"));
        var withoutScripts = Regex.Replace(html, "<script.*?</script>", string.Empty, RegexOptions.Singleline | RegexOptions.IgnoreCase);

        var placeholders = Regex.Matches(withoutScripts, "\\$\\{[^}]*\\}", RegexOptions.Singleline)
            .Select(m => m.Value)
            .ToList();

        Assert.True(
            placeholders.Count == 0,
            "The raw-served linking page must not carry dashboard ${...} localization placeholders (they are not substituted off the dashboard, #666); found: " + string.Join(", ", placeholders));
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
            File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "configPage.html")));

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
            "RequireAcr", "AcrValues",
        };
        var unsaved = securityCritical.Where(p => !matchedIds.Contains(p)).ToList();
        Assert.True(
            unsaved.Count == 0,
            "These security-critical settings must remain persisting provider-form fields (a marked input whose id equals the OidConfig property); missing or unmarked: " + string.Join(", ", unsaved));

        Assert.True(
            offenders.Count == 0,
            "Every persisting provider-form field (sso-text/sso-line-list/sso-toggle/sso-folder-list/sso-role-map) must have an id equal to an OidConfig property; these do not: " + string.Join(" | ", offenders));
    }

    [Fact]
    public void ProviderForm_RendersEveryPersistingFieldId()
    {
        // The full save-contract roster, pinned after the #365 provider-workspace redesign reordered and
        // regrouped the form into native accordion sections. ProviderFormFieldIds_MatchOidConfigProperties
        // guards the FORWARD direction (no stray marked id) and a reverse pin for the security-critical
        // SUBSET; this test is the exhaustive reverse pin: every persisting field must still render as a
        // marked input with its exact id, so a field silently dropped or unmarked during a future re-layout —
        // which would stop it persisting — fails here rather than shipping as silent data loss. The
        // provider-name KEY input (OidProviderName) is deliberately unmarked (it supplies the OidConfigs
        // dictionary key, not an OidConfig property) and is asserted present separately.
        //
        // The roster is compared as a SET IN BOTH DIRECTIONS (#934). A subset assertion silently tolerated a
        // newly added field that nobody listed here — which is exactly how DisableAvatarFromPictureClaim
        // (#723) and RoleClaimIsObjectMap escaped it — so a new form field now fails this test until it is
        // rostered, instead of shipping outside the guard.
        var markerClasses = new[] { "sso-text", "sso-line-list", "sso-toggle", "sso-folder-list", "sso-role-map" };
        var form = OidcProviderFormMarkup(
            File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "configPage.html")));

        var markedIds = new HashSet<string>(StringComparer.Ordinal);
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

            var idMatch = Regex.Match(tag.Value, "(?<![-\\w])id=\"([^\"]*)\"", RegexOptions.Singleline);
            if (idMatch.Success)
            {
                markedIds.Add(idMatch.Groups[1].Value);
            }
        }

        var expected = new[]
        {
            "OidEndpoint", "OidClientId", "OidSecret", "OidScopes", "Enabled",
            "EnableAuthorization", "DefaultUsernameClaim", "DefaultProvider", "AvatarUrlFormat", "DisableAvatarFromPictureClaim",
            "RoleClaim", "RoleClaimIsObjectMap",
            "Roles", "AdminRoles", "EnableAllFolders", "EnabledFolders", "EnableFolderRoles", "FolderRoleMapping",
            "EnableLiveTvRoles", "LiveTvRoles", "LiveTvManagementRoles", "EnableLiveTv", "EnableLiveTvManagement",
            "DoNotLoadProfile", "SchemeOverride", "PortOverride", "BaseUrlOverride",
            "RequirePkce", "AllowExistingAccountLink", "ProvisionNewUsersDisabled", "RequireVerifiedEmailForAdoption", "RequireVerifiedEmailForLogin",
            "AcrValues", "Prompt", "MaxAge", "RequireAcr",
            "DisableHttps", "DisablePushedAuthorization", "DoNotValidateEndpoints", "DoNotValidateIssuerName", "DoNotValidateResponseIssuer",
            "HideLoginButton", "LoginButtonText", "PostLogoutRedirectUri",
        };

        Assert.Equal(44, expected.Length);
        var missing = expected.Where(id => !markedIds.Contains(id)).ToList();
        Assert.True(
            missing.Count == 0,
            "These persisting provider-form fields are missing their marked input in configPage.html (a re-layout dropped or unmarked them, so they would stop persisting): " + string.Join(", ", missing));

        // The other direction: a marked input nobody rostered is a field that shipped outside this guard.
        var unrostered = markedIds.Where(id => !expected.Contains(id, StringComparer.Ordinal)).OrderBy(id => id, StringComparer.Ordinal).ToList();
        Assert.True(
            unrostered.Count == 0,
            "These provider-form fields render a marked input but are not in this test's roster, so they are outside the persistence guard — add them to `expected` and bump its count: " + string.Join(", ", unrostered));

        // The provider-name KEY input must still be present (unmarked by design).
        Assert.Contains("id=\"OidProviderName\"", form, StringComparison.Ordinal);
    }

    [Fact]
    public void ProviderFormFieldIds_MatchSamlConfigProperties()
    {
        // The SAML provider form's save contract (#725), locked in as the SamlConfig-side twin of
        // ProviderFormFieldIds_MatchOidConfigProperties. config.js saveSamlProvider persists each marked
        // input as current_config[samlPropOf(element.id)] = value, where samlPropOf strips the mandatory
        // "saml-" id prefix (the prefix keeps every SAML field id unique in a document the OpenID form already
        // populated). So every input bearing a persisting marker class MUST (a) have a "saml-"-prefixed id and
        // (b) once stripped, equal a real SamlConfig property — otherwise it renders but silently never saves,
        // because the server drops JSON members that are not SamlConfig properties. The scan is scoped to
        // #sso-new-saml-provider so it is checked against SamlConfig, never OidConfig. Paired below with a
        // reverse security-critical pin so neither a mistyped id nor a dropped marker class can silently break
        // a SAML security setting's save.
        var markerClasses = new[] { "sso-text", "sso-line-list", "sso-toggle", "sso-folder-list", "sso-role-map" };

        var form = SamlProviderFormMarkup(
            File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "configPage.html")));

        var samlConfigProperties = typeof(SamlConfig)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .ToHashSet(StringComparer.Ordinal);

        // matchedProps holds the STRIPPED property names (samlPropOf) so the sentinel/security pins below read
        // as plain SamlConfig property names, mirroring the OpenID test.
        var matchedProps = new HashSet<string>(StringComparer.Ordinal);
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

            var idMatch = Regex.Match(tag.Value, "(?<![-\\w])id=\"([^\"]*)\"", RegexOptions.Singleline);
            var id = idMatch.Success ? idMatch.Groups[1].Value : "(no id)";

            // The prefix itself is part of the contract: a marked SAML field without it would collide with the
            // OpenID field of the same name AND be mis-saved, so flag it rather than silently stripping nothing.
            if (!id.StartsWith("saml-", StringComparison.Ordinal))
            {
                offenders.Add($"{id} (missing the required saml- id prefix; classes: {classAttr.Groups[1].Value.Trim()})");
                continue;
            }

            var prop = id.Substring("saml-".Length);
            matchedProps.Add(prop);
            if (!samlConfigProperties.Contains(prop))
            {
                offenders.Add($"{id} -> {prop} (classes: {classAttr.Groups[1].Value.Trim()})");
            }
        }

        // Guard against a vacuous pass: one sentinel per marker class must have been scanned.
        var sentinels = new[] { "SamlEndpoint", "Roles", "Enabled", "EnabledFolders", "FolderRoleMapping" };
        var missingSentinels = sentinels.Where(s => !matchedProps.Contains(s)).ToList();
        Assert.True(
            missingSentinels.Count == 0,
            "The SAML provider-form scan did not reach expected fields (broken parse or renamed marker class?); missing sentinels: " + string.Join(", ", missingSentinels));

        // Reverse direction: pin the SAML security-critical settings — each MUST remain a marked, correctly
        // "saml-"-prefixed persisting field, so dropping its marker class (fail-open: the server keeps the
        // stored value and the admin can no longer change it in the form) fails here. DoNotValidateAudience is
        // the SAML insecure toggle; ValidateRecipient/ValidateInResponseTo/SignAuthnRequests are the opt-in
        // hardening toggles; the signing keys are the write-only secrets; AllowExistingAccountLink and
        // ProvisionNewUsersDisabled govern account adoption/provisioning. Extend in the same PR that surfaces a
        // new SAML security setting.
        var securityCritical = new[]
        {
            "EnableAuthorization", "DoNotValidateAudience", "ValidateRecipient", "ValidateInResponseTo",
            "SignAuthnRequests", "SamlSigningKeyPfx", "SamlRolloverSigningKeyPfx",
            "AllowExistingAccountLink", "ProvisionNewUsersDisabled",
        };
        var unsaved = securityCritical.Where(p => !matchedProps.Contains(p)).ToList();
        Assert.True(
            unsaved.Count == 0,
            "These SAML security-critical settings must remain persisting provider-form fields (a marked input whose id is \"saml-\" + the SamlConfig property); missing or unmarked: " + string.Join(", ", unsaved));

        Assert.True(
            offenders.Count == 0,
            "Every persisting SAML provider-form field (sso-text/sso-line-list/sso-toggle/sso-folder-list/sso-role-map) must have an id equal to \"saml-\" + a SamlConfig property; these do not: " + string.Join(" | ", offenders));
    }

    [Fact]
    public void SamlProviderForm_RendersEveryPersistingFieldId()
    {
        // The exhaustive reverse pin for the SAML save contract (#725), the twin of
        // ProviderForm_RendersEveryPersistingFieldId: every one of the 32 persisting SAML fields must render
        // as a marked input with its exact "saml-"-prefixed id, so a field silently dropped or unmarked during
        // a future re-layout — which would stop it persisting — fails here rather than shipping as silent data
        // loss. The provider-name KEY input (saml-provider-name) is deliberately unmarked (it supplies the
        // SamlConfigs dictionary key, not a SamlConfig property) and is asserted present separately.
        var markerClasses = new[] { "sso-text", "sso-line-list", "sso-toggle", "sso-folder-list", "sso-role-map" };
        var form = SamlProviderFormMarkup(
            File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "configPage.html")));

        var markedProps = new HashSet<string>(StringComparer.Ordinal);
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

            var idMatch = Regex.Match(tag.Value, "(?<![-\\w])id=\"([^\"]*)\"", RegexOptions.Singleline);
            if (idMatch.Success && idMatch.Groups[1].Value.StartsWith("saml-", StringComparison.Ordinal))
            {
                markedProps.Add(idMatch.Groups[1].Value.Substring("saml-".Length));
            }
        }

        var expected = new[]
        {
            "SamlEndpoint", "SamlSloEndpoint", "SamlClientId", "SamlCertificate", "SamlSecondaryCertificate", "SamlAudience",
            "DoNotValidateAudience", "ValidateRecipient", "ValidateInResponseTo", "SignAuthnRequests",
            "SamlSigningKeyPfx", "SamlRolloverSigningKeyPfx",
            "Enabled", "EnableAuthorization", "DefaultProvider", "AllowExistingAccountLink", "ProvisionNewUsersDisabled",
            "Roles", "AdminRoles", "EnableAllFolders", "EnabledFolders", "EnableFolderRoles", "FolderRoleMapping",
            "EnableLiveTvRoles", "LiveTvRoles", "LiveTvManagementRoles", "EnableLiveTv", "EnableLiveTvManagement",
            "SchemeOverride", "PortOverride", "BaseUrlOverride",
            "HideLoginButton", "LoginButtonText",
        };

        Assert.Equal(33, expected.Length);
        var missing = expected.Where(p => !markedProps.Contains(p)).ToList();
        Assert.True(
            missing.Count == 0,
            "These persisting SAML provider-form fields are missing their marked \"saml-\"-prefixed input in configPage.html (a re-layout dropped or unmarked them, so they would stop persisting): " + string.Join(", ", missing));

        // The provider-name KEY input must still be present (unmarked by design).
        Assert.Contains("id=\"saml-provider-name\"", form, StringComparison.Ordinal);
    }

    [Fact]
    public void OpenSamlProvider_ResetsEditorBeforeLoadingTheProvider()
    {
        // #689/#725 (provider-switch state bleed) for the SAML editor: the SAML editor is a single reused
        // form, so opening a provider must start from a clean slate or a field the target provider does not
        // set keeps the PREVIOUS provider's value and a later save silently persists it. No JS runtime harness
        // exists, so this pins the ordering statically: within openSamlProvider, resetSamlEditor(page) must run
        // BEFORE loadSamlProvider(page, provider_name), the same clean-slate-first order OpenProvider enforces.
        var js = File.ReadAllText(
            Path.Combine(RepoRoot(), "SSO-Auth", "Web", "config.js"));

        var open = js.IndexOf("openSamlProvider:", StringComparison.Ordinal);
        Assert.True(open >= 0, "openSamlProvider was not found in config.js.");

        var nextMethod = js.IndexOf("addSamlProvider:", open, StringComparison.Ordinal);
        Assert.True(nextMethod > open, "addSamlProvider (the method after openSamlProvider) was not found in config.js.");
        var body = js[open..nextMethod];

        var reset = body.IndexOf("resetSamlEditor(page)", StringComparison.Ordinal);
        var load = body.IndexOf("loadSamlProvider(page, provider_name)", StringComparison.Ordinal);
        Assert.True(reset >= 0, "openSamlProvider must call resetSamlEditor(page) to clear the previous provider's state before loading.");
        Assert.True(load >= 0, "openSamlProvider must call loadSamlProvider(page, provider_name).");
        Assert.True(
            reset < load,
            "openSamlProvider must call resetSamlEditor(page) BEFORE loadSamlProvider(page, provider_name); otherwise the previous provider's unset fields bleed into the loaded provider and can be silently saved (#689/#725).");
    }

    [Fact]
    public void ProviderPresets_OidcFieldsAndTogglesAreRenderedMarkedFields()
    {
        // #726 provider templates: applying a preset writes into the editor field whose id equals the
        // preset's `fields` key (and pre-checks the toggle whose id equals the toggle name). If a key does
        // not match a marked field in the OpenID form, the apply silently no-ops (a broken preset) — and the
        // separate save-contract test already guarantees every marked field id is a real OidConfig property,
        // so this pins the composition: every OIDC preset field/toggle targets a real persisting field, so
        // applying a preset always respects the save contract.
        var js = File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "config.js"));
        var (fieldKeys, toggles) = ParsePresetCatalog(js, "OIDC_PRESETS");
        Assert.True(fieldKeys.Count > 0, "OIDC_PRESETS parsed to zero field keys — broken parse or empty catalog.");

        var markedIds = MarkedFieldIds(OidcProviderFormMarkup(
            File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "configPage.html"))));

        var missing = fieldKeys.Concat(toggles).Where(k => !markedIds.Contains(k)).ToList();
        Assert.True(
            missing.Count == 0,
            "These OIDC preset field/toggle keys do not match a marked field id in #sso-new-oidc-provider (a preset would silently fill nothing): " + string.Join(", ", missing));
    }

    [Fact]
    public void ProviderPresets_SamlFieldsAndTogglesAreRenderedMarkedFields()
    {
        // The SAML counterpart: a SAML preset's field/toggle key K targets the id "saml-"+K, so each must
        // exist as a marked field in #sso-new-saml-provider.
        var js = File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "config.js"));
        var (fieldKeys, toggles) = ParsePresetCatalog(js, "SAML_PRESETS");
        Assert.True(fieldKeys.Count > 0, "SAML_PRESETS parsed to zero field keys — broken parse or empty catalog.");

        var markedIds = MarkedFieldIds(SamlProviderFormMarkup(
            File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "configPage.html"))));

        var missing = fieldKeys.Concat(toggles).Where(k => !markedIds.Contains("saml-" + k)).ToList();
        Assert.True(
            missing.Count == 0,
            "These SAML preset field/toggle keys do not match a marked \"saml-\"+key field id in #sso-new-saml-provider: " + string.Join(", ", missing));
    }

    [Fact]
    public void ProviderPresets_NeverFillSecrets()
    {
        // A preset pre-fills only NON-secret fields (#726 acceptance). Pin it: no preset's `fields` may carry
        // a write-only secret property, so a template can never place a secret value in the form (or, worse,
        // a plausible-looking wrong one the admin trusts).
        var js = File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "config.js"));
        var secrets = new[] { "OidSecret", "SamlSigningKeyPfx", "SamlRolloverSigningKeyPfx" };

        foreach (var catalog in new[] { "OIDC_PRESETS", "SAML_PRESETS" })
        {
            var (fieldKeys, _) = ParsePresetCatalog(js, catalog);
            var offending = fieldKeys.Where(k => secrets.Contains(k, StringComparer.Ordinal)).ToList();
            Assert.True(
                offending.Count == 0,
                $"{catalog} must never pre-fill a secret field; found: " + string.Join(", ", offending));
        }
    }

    [Fact]
    public void ProviderPresets_OnlyPreCheckKnownCompatToggles()
    {
        // A preset may pre-check ONLY a known compatibility/insecure toggle, never a fail-closed hardening
        // toggle (#726): silently enabling a hardening toggle could lock out a not-yet-ready IdP, and
        // enabling an unrelated toggle is a downgrade the admin did not choose. Pin both directions: every
        // preset toggle is in the protocol's managed-toggle allow-list, and every allow-list entry is a real
        // config property that is NOT one of the hardening toggles.
        var js = File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "config.js"));

        var oidcProps = typeof(OidConfig).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        var samlProps = typeof(SamlConfig).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name).ToHashSet(StringComparer.Ordinal);

        var hardening = new[]
        {
            "RequirePkce", "RequireVerifiedEmailForAdoption", "RequireVerifiedEmailForLogin", "RequireAcr",
            "ValidateRecipient", "ValidateInResponseTo", "SignAuthnRequests",
        };

        var oidcManaged = ParseJsStringArrayConst(js, "OIDC_PRESET_MANAGED_TOGGLES");
        var samlManaged = ParseJsStringArrayConst(js, "SAML_PRESET_MANAGED_TOGGLES");

        // Allow-list entries are real properties and are not hardening toggles.
        foreach (var (managed, props, name) in new[]
        {
            (oidcManaged, oidcProps, "OIDC_PRESET_MANAGED_TOGGLES"),
            (samlManaged, samlProps, "SAML_PRESET_MANAGED_TOGGLES"),
        })
        {
            var notProp = managed.Where(t => !props.Contains(t)).ToList();
            Assert.True(notProp.Count == 0, $"{name} contains non-properties: " + string.Join(", ", notProp));
            var isHardening = managed.Where(t => hardening.Contains(t, StringComparer.Ordinal)).ToList();
            Assert.True(isHardening.Count == 0, $"{name} must not include a hardening toggle: " + string.Join(", ", isHardening));
        }

        // Every preset toggle is within its protocol's allow-list.
        var oidcToggles = ParsePresetCatalog(js, "OIDC_PRESETS").toggles;
        var samlToggles = ParsePresetCatalog(js, "SAML_PRESETS").toggles;
        var oidcStray = oidcToggles.Where(t => !oidcManaged.Contains(t)).ToList();
        var samlStray = samlToggles.Where(t => !samlManaged.Contains(t)).ToList();
        Assert.True(oidcStray.Count == 0, "OIDC presets pre-check a toggle outside the allow-list: " + string.Join(", ", oidcStray));
        Assert.True(samlStray.Count == 0, "SAML presets pre-check a toggle outside the allow-list: " + string.Join(", ", samlStray));
    }

    [Fact]
    public void ProviderPresets_OidcPresetsShareTheSameFieldKeySet()
    {
        // #726 idempotency invariant: applyOidcPreset overwrites only the fields the newly chosen preset
        // sets (after clearing the managed toggles), so if two presets set DIFFERENT field-key sets,
        // switching from a richer to a poorer one would leave a stale value behind — e.g. a preset that
        // dropped RoleClaim would keep the previous provider's claim path. Every OIDC preset must therefore
        // set EXACTLY the same four fields; this locks that in so a future preset cannot silently reintroduce
        // the state-bleed (a review follow-up on #726).
        var js = File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Web", "config.js"));
        var start = js.IndexOf("const OIDC_PRESETS = {", StringComparison.Ordinal);
        Assert.True(start >= 0, "OIDC_PRESETS was not found in config.js.");
        var end = js.IndexOf("};", start, StringComparison.Ordinal);
        Assert.True(end > start, "OIDC_PRESETS has no closing }};.");
        var region = js[start..end];

        var required = new[] { "OidEndpoint", "OidScopes", "RoleClaim", "DefaultUsernameClaim" };
        var blocks = Regex.Matches(region, @"fields:\s*\{([^}]*)\}", RegexOptions.Singleline)
            .Select(m => m.Groups[1].Value)
            .ToList();
        Assert.True(
            blocks.Count >= 9,
            $"Expected at least 9 OIDC preset field blocks, found {blocks.Count} — broken parse or shrunken catalog.");

        foreach (var block in blocks)
        {
            var keys = Regex.Matches(block, "(\\w+)\\s*:\\s*\"")
                .Select(m => m.Groups[1].Value)
                .ToHashSet(StringComparer.Ordinal);
            var missing = required.Where(r => !keys.Contains(r)).ToList();
            var extra = keys.Where(k => !required.Contains(k)).ToList();
            Assert.True(
                missing.Count == 0,
                "An OIDC preset omits a shared field key (switching templates would leave a stale value): " + string.Join(", ", missing));
            Assert.True(
                extra.Count == 0,
                "An OIDC preset sets a field key outside the shared set (breaks idempotent switching): " + string.Join(", ", extra));
        }
    }

    [Fact]
    public void OpenProvider_ResetsEditorBeforeLoadingTheProvider()
    {
        // #689 (provider-switch state bleed): the editor is a single reused form, so opening a provider must
        // start from a clean slate or a text/array field the target provider does not set keeps the
        // PREVIOUS provider's value and a later save silently persists it (e.g. repointing the #186-sensitive
        // OidEndpoint with no admin edit). No JS runtime harness exists (the config.js checks are static text
        // parsers), so this pins the ordering invariant statically: within openProvider, resetEditor(page)
        // must run BEFORE loadProvider(page, provider_name) — the same clean-slate-first order addProvider
        // already uses. loadProvider then fills the target's real values on top of the reset baseline.
        var js = File.ReadAllText(
            Path.Combine(RepoRoot(), "SSO-Auth", "Web", "config.js"));

        var open = js.IndexOf("openProvider:", StringComparison.Ordinal);
        Assert.True(open >= 0, "openProvider was not found in config.js.");

        // Scope to the openProvider method body (up to the next method, addProvider) so resetEditor/
        // loadProvider references elsewhere in the file cannot satisfy the check.
        var nextMethod = js.IndexOf("addProvider:", open, StringComparison.Ordinal);
        Assert.True(nextMethod > open, "addProvider (the method after openProvider) was not found in config.js.");
        var body = js[open..nextMethod];

        var reset = body.IndexOf("resetEditor(page)", StringComparison.Ordinal);
        var load = body.IndexOf("loadProvider(page, provider_name)", StringComparison.Ordinal);
        Assert.True(reset >= 0, "openProvider must call resetEditor(page) to clear the previous provider's state before loading.");
        Assert.True(load >= 0, "openProvider must call loadProvider(page, provider_name).");
        Assert.True(
            reset < load,
            "openProvider must call resetEditor(page) BEFORE loadProvider(page, provider_name); otherwise the previous provider's unset fields bleed into the loaded provider and can be silently saved (#689).");
    }

    [Fact]
    public void SyncDependentFields_ExpandsEnclosingSecuritySectionOnTheOrOfInsecureOrSensitive()
    {
        // #689 (active downgrade hidden behind a collapsed accordion): the insecure toggles live behind a
        // "Show insecure options" list that is itself inside the "Security & hardening" emby-collapse, which
        // is authored collapsed. Expanding only the inner list left an active DisableHttps /
        // AllowExistingAccountLink invisible. syncDependentFields must expand the ENCLOSING accordion section
        // (by its stable id) when any insecure OR sensitive toggle is active. No JS runtime harness exists,
        // so this pins statically both the target (the section id in the markup and the call) AND the
        // condition shape: the expand is driven by the OR of the two sets, so a `||`->`&&` mutant — which
        // would stop a sensitive-only (AllowExistingAccountLink) provider from expanding — fails here.
        var html = File.ReadAllText(
            Path.Combine(RepoRoot(), "SSO-Auth", "Web", "configPage.html"));
        var js = File.ReadAllText(
            Path.Combine(RepoRoot(), "SSO-Auth", "Web", "config.js"));

        // The enclosing accordion is the emby-collapse carrying the stable id, and it is the security section.
        Assert.Matches(
            new Regex("<div\\b[^>]*is=\"emby-collapse\"[^>]*id=\"sso-security-section\"[^>]*title=\"Security & hardening\"", RegexOptions.Singleline),
            html);

        // Scope to the syncDependentFields method body (up to the next method) so the reference is inside it.
        var sync = js.IndexOf("syncDependentFields:", StringComparison.Ordinal);
        Assert.True(sync >= 0, "syncDependentFields was not found in config.js.");
        var nextMethod = js.IndexOf("setInsecureOptionsExpanded:", sync, StringComparison.Ordinal);
        Assert.True(nextMethod > sync, "The method after syncDependentFields was not found in config.js.");
        var body = js[sync..nextMethod];

        // anyInsecure is derived from the insecure set.
        Assert.Matches(
            new Regex(@"anyInsecure\s*=\s*ssoConfigurationPage\.insecureFieldIds\.some\(", RegexOptions.Singleline),
            body);

        // The combined condition is the OR (never AND) of anyInsecure and the sensitive set — the disjunction
        // a `||`->`&&` mutant would break. Both sets must feed it, not just appear somewhere in the body.
        Assert.Matches(
            new Regex(@"anySensitive\s*=\s*anyInsecure\s*\|\|\s*ssoConfigurationPage\.sensitiveFieldIds\.some\(", RegexOptions.Singleline),
            body);

        // The inner insecure-options list is gated on anyInsecure; the ENCLOSING section on the combined
        // anySensitive — so the section expands for a sensitive-only provider too.
        Assert.Matches(
            new Regex(@"if\s*\(\s*anyInsecure\s*\)\s*\{\s*ssoConfigurationPage\.setInsecureOptionsExpanded\(\s*page,\s*true", RegexOptions.Singleline),
            body);
        Assert.Matches(
            new Regex("if\\s*\\(\\s*anySensitive\\s*\\)\\s*\\{\\s*ssoConfigurationPage\\.setSectionExpanded\\(\\s*page,\\s*\"sso-security-section\"", RegexOptions.Singleline),
            body);

        // The flag / auto-expand trigger set must contain only settings whose ENABLED state is a downgrade or
        // an attack-surface widening: the five insecure toggles and AllowExistingAccountLink. It must NOT
        // contain the fail-closed hardening toggles (RequireVerifiedEmailForAdoption/ForLogin, RequirePkce),
        // which are OFF by default and whose ON state is MORE secure — flagging those is backwards (#689
        // re-review). Scoped to the two array literals so a stray mention elsewhere cannot mask a regression.
        var insecureSet = ArrayLiteralAfter(js, "insecureFieldIds:");
        var sensitiveSet = ArrayLiteralAfter(js, "sensitiveFieldIds:");
        var trigger = insecureSet + " " + sensitiveSet;
        foreach (var id in new[]
        {
            "DisableHttps", "DisablePushedAuthorization", "DoNotValidateEndpoints",
            "DoNotValidateIssuerName", "DoNotValidateResponseIssuer", "AllowExistingAccountLink",
        })
        {
            Assert.Contains("\"" + id + "\"", trigger, StringComparison.Ordinal);
        }

        foreach (var hardening in new[]
        {
            "RequireVerifiedEmailForAdoption", "RequireVerifiedEmailForLogin", "RequirePkce", "RequireAcr",
        })
        {
            Assert.DoesNotContain(hardening, trigger, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ResetEditor_ClearsEveryConditionallyLoadedFieldCategory()
    {
        // #689 (provider-switch state bleed): loadProvider fills the text, line-list, folder-list and
        // role-map categories ONLY under `if (provider[id])`, so the clean slate that prevents a previous
        // provider's value bleeding through has to come from resetEditor unconditionally clearing every one
        // of those categories (plus the checkboxes). No JS runtime harness exists to assert the live DOM is
        // zeroed, so this statically pins that the resetEditor body contains the clear for each category — a
        // mutant deleting any one category's reset (which would let that category bleed) fails here. Scoped
        // to the resetEditor body so a clear living in some other method cannot satisfy the check.
        var js = File.ReadAllText(
            Path.Combine(RepoRoot(), "SSO-Auth", "Web", "config.js"));

        var start = js.IndexOf("resetEditor:", StringComparison.Ordinal);
        Assert.True(start >= 0, "resetEditor was not found in config.js.");
        var nextMethod = js.IndexOf("resetEditorSections:", start, StringComparison.Ordinal);
        Assert.True(nextMethod > start, "resetEditorSections (the method after resetEditor) was not found in config.js.");
        var body = js[start..nextMethod];

        // text and line-list categories clear their input value to the empty string ("").
        Assert.Matches(
            new Regex("text_fields\\.forEach\\(.*?\\.value = \"\"", RegexOptions.Singleline),
            body);
        Assert.Matches(
            new Regex("text_list_fields\\.forEach\\(.*?\\.value = \"\"", RegexOptions.Singleline),
            body);

        // checkboxes reset to unchecked.
        Assert.Matches(
            new Regex(@"check_fields\.forEach\(.*?\.checked = false;", RegexOptions.Singleline),
            body);

        // folder-list and role-map categories reset to an empty collection via their populate helpers.
        Assert.Matches(
            new Regex(@"folder_list_fields\.forEach\(.*?populateEnabledFolders\(\s*\[\]", RegexOptions.Singleline),
            body);
        Assert.Matches(
            new Regex(@"role_map_fields\.forEach\(.*?populateRoleMappings\(\s*\[\]", RegexOptions.Singleline),
            body);
    }

    [Fact]
    public void SourceFilesDeclaring_MatchesRecordStructAndStructAlongsideClass()
    {
        // #542: the helper's regex used to be "\bclass\s+{Name}\b" only, so it silently returned an empty
        // file list for a record struct/struct type instead of finding its declaring file — a latent
        // false-negative for any future rule that scans one by name. RouteSuffix and DiscoveryFacts
        // ("internal readonly record struct ...") are real record structs already living in SSO-Auth/Api,
        // so this pins the fix against actual source rather than a synthetic fixture.
        var recordStructFiles = SourceFilesDeclaring(new[] { typeof(RouteSuffix), typeof(DiscoveryFacts) });
        Assert.True(
            recordStructFiles.Count == 2,
            "SourceFilesDeclaring must find the declaring file of a record struct type (RouteSuffix, DiscoveryFacts), not just a class.");

        // The class path must keep working too — the widened regex must not have narrowed the original
        // "class Name" match.
        var classFiles = SourceFilesDeclaring(new[] { typeof(AuthorizeSession) });
        Assert.True(
            classFiles.Count == 1,
            "SourceFilesDeclaring must still find the declaring file of an ordinary class (AuthorizeSession).");
    }

    [Fact]
    public void HostProvidedFrameworkAssemblies_StayOnTheHostAbi()
    {
        // Locked in by #590 (the 4.1.0.0 field regression) and generalized per target (#135). Each
        // Jellyfin generation the plugin targets provides the whole Microsoft.Extensions.* family from its
        // ASP.NET Core shared framework — host-provided, deliberately NOT in build.yaml's artifacts. .NET
        // rolls a host assembly reference FORWARD to a newer host but never DOWN a major version, so a
        // dependency dragging one of these ABOVE the target host's .NET major compiles and keeps
        // `dotnet test` green (both run against the full publish output, which carries the newer DLL) yet
        // throws FileNotFoundException the moment the host DI constructs the plugin against its own,
        // lower-versioned assembly — disabling it. That is exactly how OidcClient 7.x (which references
        // Logging.Abstractions 10.0.0.0) broke 4.1.0.0 on the .NET 9 host. The floor is the target's host
        // .NET major: 9 for net9.0 (Jellyfin 10.11), 10 for net10.0 (Jellyfin 12.0). When a net11 target
        // is added, turn this into an #elif chain (NET11_0_OR_GREATER → 11) — NET10_0_OR_GREATER is also
        // true on net11, so leaving it would pin the floor to 10 and spuriously fail the net11 build.
#if NET10_0_OR_GREATER
        const int hostAbiMajor = 10;
#else
        const int hostAbiMajor = 9;
#endif
        var references = typeof(SSOPlugin).Assembly.GetReferencedAssemblies();

        var overshoot = references
            .Where(a => a.Name is { } n && n.StartsWith("Microsoft.Extensions.", StringComparison.Ordinal))
            .Where(a => a.Version is { } v && v.Major > hostAbiMajor)
            .Select(a => $"{a.Name} {a.Version}")
            .ToList();

        Assert.True(
            overshoot.Count == 0,
            $"SSO-Auth references a host-provided Microsoft.Extensions.* assembly above the .NET {hostAbiMajor} host ABI; this target's Jellyfin host provides only {hostAbiMajor}.x and .NET does not roll a host assembly down, so the packaged plugin would throw FileNotFoundException at construction and be disabled (#590): " + string.Join(", ", overshoot));

        // Sentinel against a vacuous pass: the keystone that broke 4.1.0.0 is
        // Microsoft.Extensions.Logging.Abstractions — SSOPlugin's ILogger<> constructor dependency, the
        // very reference the host could not satisfy. It must remain referenced, or the scan above would
        // pass for the wrong reason (an empty match set).
        Assert.True(
            references.Any(a => a.Name == "Microsoft.Extensions.Logging.Abstractions"),
            "SSO-Auth no longer references Microsoft.Extensions.Logging.Abstractions; the #590 ABI-floor scan would pass vacuously — re-anchor it on the host-provided framework assembly the plugin actually uses.");
    }

    [Fact]
    public void BuildYamlArtifacts_EqualTheTfmPublishClosure()
    {
        // Locked in by #608, the drop-list-completeness partner of HostProvidedFrameworkAssemblies_StayOnTheHostAbi
        // above (which guards the OVER-reference direction — a host assembly pulled above the host ABI). JPRM
        // packages the shipped plugin zip from exactly the files named in the build yaml's `artifacts:` list, so
        // that hand-maintained list MUST equal the plugin's NON-HOST `dotnet publish` closure for the target
        // framework. Two failure modes it closes, previously guarded only by a comment (the #605 review finding):
        // a shipped runtime dependency MISSING from the list is dropped from the zip and throws
        // FileNotFoundException the moment the host loads the plugin (the #590 class of field regression); a
        // listed-but-unpublished file makes the JPRM package step fail on a missing artifact and is dead weight.
        //
        // The publish closure is read from SSO-Auth's own SSO-Auth.deps.json — the runtime-assembly manifest the
        // ORDINARY build emits, so the test needs no separate `dotnet publish` invocation. Its per-target
        // `runtime` set is exactly the set `dotnet publish -f <tfm>` copies: the whole package/reference closure
        // MINUS the .NET + ASP.NET Core shared framework the host supplies through the FrameworkReference (proven
        // byte-for-byte equal to the publish output when #608 was written). Subtracting the remaining
        // HOST-PROVIDED families Jellyfin itself ships — Jellyfin/Emby/MediaBrowser and the EF Core, Polly and
        // Unicode/text stacks they drag in, plus Microsoft.Extensions.* and Newtonsoft.Json — leaves precisely the
        // set that must travel in the plugin zip. Per target, mirroring the ABI-floor test's #if: net9.0 ->
        // build.yaml (Jellyfin 10.11, 11 DLLs), net10.0 -> build-jf12.yaml (Jellyfin 12.0, 8 DLLs — where the SAML
        // crypto assemblies are framework-provided on .NET 10 and correctly absent from both closure and list).
#if NET10_0_OR_GREATER
        const string targetFramework = "net10.0";
        const string buildYaml = "build-jf12.yaml";
#else
        const string targetFramework = "net9.0";
        const string buildYaml = "build.yaml";
#endif
#if DEBUG
        const string configuration = "Debug";
#else
        const string configuration = "Release";
#endif

        // SSO-Auth is a ProjectReference of this test project, so building the test for this configuration/target
        // builds the plugin into SSO-Auth/bin/<config>/<tfm>/ with its deps.json alongside. RepoRoot() is the
        // same compile-time-anchored source root the source-scan rules use; the plugin build output lives under
        // it in CI (which builds and tests the one checkout).
        var depsPath = Path.Combine(RepoRoot(), "SSO-Auth", "bin", configuration, targetFramework, "SSO-Auth.deps.json");
        Assert.True(
            File.Exists(depsPath),
            $"SSO-Auth.deps.json for {configuration}/{targetFramework} was not found at {depsPath}; the plugin build output carrying the publish closure is missing, so the ship-list cannot be computed — build SSO-Auth for this target before the test runs (#608).");

        var publishClosure = PublishClosureAssemblies(depsPath);

        // Liveness against a vacuous closure: the plugin's own assembly must be in it, proving the deps.json parse
        // found the real runtime set rather than an empty one that would make the set-equality below trivially true.
        Assert.True(
            publishClosure.Contains("SSO-Auth.dll"),
            "The computed publish closure does not contain the plugin's own SSO-Auth.dll; the deps.json parse found nothing real, so the comparison would pass vacuously (#608).");

        // Liveness against a vacuous FILTER: a keystone host-provided assembly Jellyfin ships (MediaBrowser.Common)
        // must be present in the raw closure AND be removed by the host filter. If the closure ever stopped
        // carrying it, or the filter stopped matching it, the host subtraction would be doing nothing and the
        // equality could pass for the wrong reason — re-anchor the filter on what publish actually drags in.
        Assert.True(
            publishClosure.Contains("MediaBrowser.Common.dll") && IsHostProvidedAssembly("MediaBrowser.Common.dll"),
            "The publish closure no longer carries the host-provided keystone MediaBrowser.Common.dll, or the host-provided filter stopped matching it; re-anchor HostProvidedAssemblyPrefixes on the plugin's real publish output (#608).");

        var shipped = publishClosure.Where(dll => !IsHostProvidedAssembly(dll)).ToHashSet(StringComparer.Ordinal);

        var declared = ParseBuildYamlArtifacts(Path.Combine(RepoRoot(), buildYaml));
        Assert.True(
            declared.Count > 0,
            $"No artifacts were parsed from {buildYaml}; the `artifacts:` list is empty or the parse missed it, so the comparison would pass vacuously (#608).");

        var missingFromYaml = shipped.Except(declared).OrderBy(x => x, StringComparer.Ordinal).ToList();
        var extraInYaml = declared.Except(shipped).OrderBy(x => x, StringComparer.Ordinal).ToList();

        Assert.True(
            missingFromYaml.Count == 0 && extraInYaml.Count == 0,
            $"{buildYaml}'s `artifacts:` list must equal the non-host {targetFramework} publish closure (#608). "
            + $"Shipped but NOT listed (FileNotFoundException on plugin load): [{string.Join(", ", missingFromYaml)}]. "
            + $"Listed but NOT in the publish output (JPRM fails / dead artifact): [{string.Join(", ", extraInYaml)}]. "
            + "Reconcile the build yaml with `dotnet publish -f " + targetFramework + "`, or extend HostProvidedAssemblyPrefixes if a genuinely new host-provided family appeared.");
    }

    // The assembly-name families the Jellyfin host provides at runtime and therefore must NOT ship in the plugin
    // zip, even though `dotnet publish` copies them into the plugin's own publish output (they are not part of the
    // .NET/ASP.NET Core shared framework, so publish does not strip them the way it strips the framework). Matched
    // on the assembly SIMPLE name so one entry covers a whole family: "Polly" -> Polly + Polly.Core, "ICU4N" ->
    // ICU4N + ICU4N.Transliterator, "Microsoft.EntityFrameworkCore" -> its .Abstractions/.Relational, etc. This is
    // the counterpart denylist to the build yaml's allow-list of shipped deps: a genuinely new host-provided family
    // must be added here (with justification) and a new shipped dependency must be added to the build yaml —
    // either way BuildYamlArtifacts_EqualTheTfmPublishClosure fails until the two agree (fail-closed). "Microsoft."
    // is deliberately NOT a blanket prefix: Microsoft.IdentityModel.* and Microsoft.Bcl.Cryptography DO ship, so
    // only the specific host-provided Microsoft families (Extensions, EntityFrameworkCore) are listed.
    private static readonly string[] HostProvidedAssemblyPrefixes =
    {
        "Jellyfin", "Emby", "MediaBrowser", "Microsoft.Extensions", "Microsoft.EntityFrameworkCore",
        "Newtonsoft", "Polly", "BitFaster", "Diacritics", "ICU4N", "J2N", "NEbml",
    };

    private static bool IsHostProvidedAssembly(string dllFileName)
    {
        var simpleName = dllFileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            ? dllFileName[..^4]
            : dllFileName;
        return HostProvidedAssemblyPrefixes.Any(p =>
            simpleName.Equals(p, StringComparison.Ordinal)
            || simpleName.StartsWith(p + ".", StringComparison.Ordinal));
    }

    // The runtime-assembly filenames from SSO-Auth.deps.json's single build target — the exact set
    // `dotnet publish` copies for that framework (#608). A framework-dependent build has one target (the runtime
    // target); read every library's `runtime` map and take each entry's leaf filename, because deps.json keys
    // runtime items by their in-package path (e.g. "lib/net8.0/Duende.IdentityModel.dll"), not the bare name.
    private static HashSet<string> PublishClosureAssemblies(string depsJsonPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(depsJsonPath));
        var targets = doc.RootElement.GetProperty("targets");

        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var target in targets.EnumerateObject())
        {
            foreach (var library in target.Value.EnumerateObject())
            {
                if (!library.Value.TryGetProperty("runtime", out var runtime))
                {
                    continue;
                }

                foreach (var asset in runtime.EnumerateObject())
                {
                    var leaf = asset.Name.Split('/', '\\').Last();
                    if (leaf.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    {
                        result.Add(leaf);
                    }
                }
            }
        }

        return result;
    }

    // The `.dll` names under the build yaml's `artifacts:` list. Minimal hand-parse (the test project takes no YAML
    // dependency): once at the `artifacts:` key, collect the `- "X.dll"` list items, skip the interleaved comments,
    // and stop at the next top-level key. build.yaml / build-jf12.yaml keep exactly one quoted dll per list item.
    private static HashSet<string> ParseBuildYamlArtifacts(string yamlPath)
    {
        var artifacts = new HashSet<string>(StringComparer.Ordinal);
        var inArtifacts = false;
        foreach (var line in File.ReadAllLines(yamlPath))
        {
            if (!inArtifacts)
            {
                if (Regex.IsMatch(line, @"^artifacts:\s*$"))
                {
                    inArtifacts = true;
                }

                continue;
            }

            // A new top-level key (unindented and not a list item) ends the artifacts block.
            if (line.Length > 0 && !char.IsWhiteSpace(line[0]) && !line.TrimStart().StartsWith('-'))
            {
                break;
            }

            var item = Regex.Match(line, "^\\s*-\\s*\"([^\"]+)\"\\s*$");
            if (item.Success)
            {
                artifacts.Add(item.Groups[1].Value);
            }
        }

        return artifacts;
    }

    // The markup of the #sso-new-oidc-provider settings form (from the opening tag's id attribute to its
    // closing </form>). Forms are not nested here, so the first </form> after the id marker closes it; the
    // preceding #sso-load-config form is left out because its </form> sits before the marker.
    // Return the first flat "[ ... ]" array literal that follows a marker (e.g. "sensitiveFieldIds:") in
    // config.js. Used to scope a membership assertion to a specific field-id set rather than the whole file,
    // so a stray mention of an id elsewhere cannot mask a regression in the set's contents.
    private static string ArrayLiteralAfter(string source, string marker)
    {
        var m = source.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(m >= 0, $"'{marker}' was not found in config.js.");
        var open = source.IndexOf('[', m);
        Assert.True(open > m, $"No array literal follows '{marker}' in config.js.");
        var close = source.IndexOf(']', open);
        Assert.True(close > open, $"The array literal after '{marker}' is not closed in config.js.");
        return source[open..(close + 1)];
    }

    private static string OidcProviderFormMarkup(string html)
    {
        const string marker = "id=\"sso-new-oidc-provider\"";
        var start = html.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "The #sso-new-oidc-provider form was not found in configPage.html.");
        var end = html.IndexOf("</form>", start, StringComparison.Ordinal);
        Assert.True(end > start, "The #sso-new-oidc-provider form has no closing </form> tag.");
        return html[start..end];
    }

    private static string SamlProviderFormMarkup(string html)
    {
        const string marker = "id=\"sso-new-saml-provider\"";
        var start = html.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "The #sso-new-saml-provider form was not found in configPage.html.");
        var end = html.IndexOf("</form>", start, StringComparison.Ordinal);
        Assert.True(end > start, "The #sso-new-saml-provider form has no closing </form> tag.");
        return html[start..end];
    }

    // The set of persisting (marker-classed) field ids in a provider form's markup — the ids the save
    // contract reads. Shared by the #726 preset tests to prove every preset field/toggle targets one.
    private static HashSet<string> MarkedFieldIds(string formMarkup)
    {
        var markerClasses = new[] { "sso-text", "sso-line-list", "sso-toggle", "sso-folder-list", "sso-role-map" };
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match tag in Regex.Matches(formMarkup, "<[a-zA-Z][^>]*>", RegexOptions.Singleline))
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

            var idMatch = Regex.Match(tag.Value, "(?<![-\\w])id=\"([^\"]*)\"", RegexOptions.Singleline);
            if (idMatch.Success)
            {
                ids.Add(idMatch.Groups[1].Value);
            }
        }

        return ids;
    }

    // Parse a preset catalog object literal (const <name> = { … };) from config.js into the set of `fields`
    // keys and the set of `toggles` entries across all its presets. The catalog contains no nested "};", so
    // the first "};" after the declaration is its terminator; a `fields:{…}` block contains no nested "}"
    // and a `toggles:[…]` no nested "]", so the per-block regexes are exact. A field key is matched only in
    // key position (`word:` immediately followed by a quote), so a ':' inside a URL value is never mistaken
    // for a key.
    private static (HashSet<string> fieldKeys, HashSet<string> toggles) ParsePresetCatalog(string js, string constName)
    {
        var start = js.IndexOf("const " + constName + " = {", StringComparison.Ordinal);
        Assert.True(start >= 0, $"{constName} was not found in config.js.");
        var end = js.IndexOf("};", start, StringComparison.Ordinal);
        Assert.True(end > start, $"{constName} has no closing }};.");
        var region = js[start..end];

        var fieldKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match block in Regex.Matches(region, @"fields:\s*\{([^}]*)\}", RegexOptions.Singleline))
        {
            foreach (Match key in Regex.Matches(block.Groups[1].Value, "(\\w+)\\s*:\\s*\""))
            {
                fieldKeys.Add(key.Groups[1].Value);
            }
        }

        var toggles = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match block in Regex.Matches(region, @"toggles:\s*\[([^\]]*)\]", RegexOptions.Singleline))
        {
            foreach (Match t in Regex.Matches(block.Groups[1].Value, "\"(\\w+)\""))
            {
                toggles.Add(t.Groups[1].Value);
            }
        }

        return (fieldKeys, toggles);
    }

    // Parse a flat JS string-array const (const <name> = [ "a", "b" ];) from config.js into a set.
    private static HashSet<string> ParseJsStringArrayConst(string js, string constName)
    {
        var start = js.IndexOf("const " + constName + " = [", StringComparison.Ordinal);
        Assert.True(start >= 0, $"{constName} was not found in config.js.");
        var end = js.IndexOf("];", start, StringComparison.Ordinal);
        Assert.True(end > start, $"{constName} has no closing ];.");
        var region = js[start..end];

        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in Regex.Matches(region, "\"(\\w+)\""))
        {
            set.Add(m.Groups[1].Value);
        }

        return set;
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

    // The C# keywords a type declaration's name can immediately follow. "struct" alone also matches a
    // "record struct" declaration (the name follows "struct", not "record", in that form); "record" alone
    // matches a positional/reference record ("record Foo(...)"), since "record class Foo" is already
    // covered by "class".
    private static readonly string[] TypeDeclarationKeywords = { "class", "struct", "record" };

    // Every source file that declares any of the given types, matched by class/struct/record declaration
    // in the file body (not the file name), so a file rename still resolves via the type's own name.
    // Shared by ControllerSourceFiles above and the raw socket/DNS liveness check (#444) — both need
    // "which files declare these types", just for a different type set (#542).
    private static IReadOnlyList<string> SourceFilesDeclaring(IEnumerable<Type> types)
    {
        var declarations = types
            .SelectMany(t => TypeDeclarationKeywords.Select(keyword =>
                new Regex($@"\b{keyword}\s+{Regex.Escape(SimpleName(t))}\b")))
            .ToList();

        return Directory
            .EnumerateFiles(Path.Combine(RepoRoot(), "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Where(path => declarations.Any(d => d.IsMatch(File.ReadAllText(path))))
            .ToList();
    }

    // Routes whose action MUST call RateLimitCheck (#928 U2): the anonymous login-path endpoints
    // (challenge / callback / auth for both protocols, SP metadata, inbound SAML logout) and the
    // admin endpoints that drive an OUTBOUND fetch (the OpenID connection tester and SAML metadata
    // import — an authenticated admin must not be able to spin the outbound probe unthrottled), plus
    // the account-link and unregister mutations. Adding a route here without wiring the gate fails the
    // test; the reverse — an unclassified NEW route — fails EverySensitiveRoute_IsClassified below.
    private static readonly string[] MustThrottleRoutes =
    {
        "OID/r/{provider}", "OID/redirect/{provider}", "OID/p/{provider}", "OID/start/{provider}",
        "OID/Test/{provider}", "OID/Auth/{provider}",
        "SAML/p/{provider}", "SAML/post/{provider}", "SAML/start/{provider}", "SAML/metadata/{provider}",
        "SAML/Logout/{provider}", "SAML/ImportMetadata", "SAML/Auth/{provider}",
        "Unregister/{username}", "{mode}/Link/{provider}/{jellyfinUserId}",
        "{mode}/Link/{provider}/{jellyfinUserId}/{canonicalName}",
    };

    // Routes deliberately NOT rate-limited, each with the reason it is safe: an elevation-gated admin
    // operation with no outbound fetch, an authenticated user action, or a purely local (no-I/O) probe.
    // Kept as an explicit allowlist so a NEW endpoint cannot be silently exempted — it must be added to
    // one of the two lists, which is the classification decision this conformance test forces.
    private static readonly string[] RateLimitExemptRoutes =
    {
        "OID/logout/{provider}", "SAML/logout/{provider}", // [Authorize] user logout, no fetch
        "OID/Add/{provider}", "SAML/Add/{provider}", "OID/Del/{provider}", "SAML/Del/{provider}", // elevated config CRUD
        "OID/Get", "SAML/Get", "OID/GetNames", "SAML/GetNames", "OID/States", // read-only listings
        "SAML/Test/{provider}", // LOCAL certificate parse — no outbound fetch (unlike OID/Test)
        "Config/Export", "Config/Import", // elevated config transfer
        "SSO-Only/Status", "SSO-Only/Enable", "SSO-Only/Disable", "SSO-Only/BreakGlassAdmin", // elevated mode control
        "saml/links/{jellyfinUserId}", "oid/links/{jellyfinUserId}", // authenticated link listings
        "{viewName}", // SSOViewsController: read-only embedded static asset (ETag/304), no I/O, no login path
    };

    [Fact]
    public void EveryMustThrottleEndpoint_CallsTheRateLimitGate()
    {
        // #928 U2 — the structural half of "does every rate-limited endpoint actually rate-limit". The
        // per-endpoint 429 response-shape tests prove the wiring behaves; this proves the wiring EXISTS on
        // every endpoint that must have it, so the class of "a new login-path/outbound endpoint forgot the
        // RateLimitCheck call" is a red build, not a review miss.
        var actions = ControllerActionBlocks();
        var missing = new List<string>();
        foreach (var route in MustThrottleRoutes)
        {
            var block = actions.FirstOrDefault(a => a.Routes.Contains(route, StringComparer.Ordinal));
            Assert.True(block.Routes is not null, $"MustThrottleRoutes lists '{route}', but no controller action declares that route — a route was renamed; update the list (#928).");
            if (!block.Body.Contains("RateLimitCheck(SsoRateLimitClass.", StringComparison.Ordinal))
            {
                missing.Add(route);
            }
        }

        Assert.True(
            missing.Count == 0,
            "These endpoints must call RateLimitCheck(SsoRateLimitClass.…) and do not: " + string.Join(", ", missing));
    }

    [Fact]
    public void EverySensitiveRoute_IsClassified_AsThrottledOrExplicitlyExempt()
    {
        // The completeness guard: every controller route is in exactly one of the two lists. A NEW endpoint
        // therefore cannot land without a deliberate decision on whether it needs rate limiting — the whole
        // point of #928 U2's "no forgotten gate". Also fails on a stale list entry (a route no longer in
        // the controller), so the lists cannot drift out of sync with the surface.
        var declared = ControllerActionBlocks().SelectMany(a => a.Routes).ToList();
        Assert.NotEmpty(declared);

        var classified = MustThrottleRoutes.Concat(RateLimitExemptRoutes).ToHashSet(StringComparer.Ordinal);

        var unclassified = declared.Where(r => !classified.Contains(r)).ToList();
        Assert.True(
            unclassified.Count == 0,
            "These controller routes are in neither MustThrottleRoutes nor RateLimitExemptRoutes — classify each (does it need rate limiting?): " + string.Join(", ", unclassified));

        var declaredSet = declared.ToHashSet(StringComparer.Ordinal);
        var stale = classified.Where(r => !declaredSet.Contains(r)).ToList();
        Assert.True(
            stale.Count == 0,
            "These routes are listed in a rate-limit classification list but no longer exist on the controller — remove them: " + string.Join(", ", stale));
    }

    // Every controller action as (its route templates, its method-body text): the body runs from an action's
    // HTTP-attribute cluster to the next action's cluster, which is enough to see whether the (always-first)
    // RateLimitCheck statement is present. Stacked route attributes on one method (consecutive lines) are one
    // action. Route-template source scan, in the ControllerSourceFiles idiom (#388) so a controller split
    // cannot hide an endpoint.
    private static IReadOnlyList<(IReadOnlyList<string> Routes, string Body)> ControllerActionBlocks()
    {
        var attr = new Regex(
            @"^\s*\[Http(?:Get|Post|Put|Delete)\(""(?<route>[^""]*)""\)\]");
        var results = new List<(IReadOnlyList<string>, string)>();

        foreach (var path in ControllerSourceFiles())
        {
            var lines = File.ReadAllLines(path);
            var hits = new List<(int Line, string Route)>();
            for (var i = 0; i < lines.Length; i++)
            {
                var m = attr.Match(lines[i]);
                if (m.Success)
                {
                    hits.Add((i, m.Groups["route"].Value));
                }
            }

            // Group consecutive attribute lines (a method's stacked routes) into one action cluster.
            for (var i = 0; i < hits.Count;)
            {
                var routes = new List<string> { hits[i].Route };
                var last = i;
                while (last + 1 < hits.Count && hits[last + 1].Line == hits[last].Line + 1)
                {
                    routes.Add(hits[last + 1].Route);
                    last++;
                }

                var bodyStart = hits[last].Line;
                var bodyEnd = last + 1 < hits.Count ? hits[last + 1].Line : lines.Length;
                var body = string.Join("\n", lines.Skip(bodyStart).Take(bodyEnd - bodyStart));
                results.Add((routes, body));
                i = last + 1;
            }
        }

        return results;
    }

    [Fact]
    public void EverySourceFile_CarriesTheSpdxHeader()
    {
        // #747: every C# source file opens with the SPDX copyright + licence header, so the licence of any
        // one file is machine-readable at its top (REUSE / SPDX) and a new file cannot land without it.
        // GPL-3.0-only is the project's SPDX identifier — it matches the declared "GPL v3.0" exactly, with no
        // implicit "or later" broadening; the copyright line credits the authors collectively. This test is
        // the drift guard that keeps the headers complete: a file added without the two opening lines fails
        // CI here (the header must be the first two lines so it precedes the usings and the file-scoped
        // namespace, which SPDX/REUSE tooling expects).
        const string CopyrightLine = "// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors";
        const string LicenceLine = "// SPDX-License-Identifier: GPL-3.0-only";
        var offenders = new List<string>();
        foreach (var root in new[] { "SSO-Auth", "SSO-Auth.Tests", "SSO-Auth.Fuzz" })
        {
            foreach (var src in Directory.EnumerateFiles(Path.Combine(RepoRoot(), root), "*.cs", SearchOption.AllDirectories))
            {
                if (IsBuildOutput(src))
                {
                    continue;
                }

                var firstLines = File.ReadLines(src).Take(2).ToList();
                if (firstLines.Count < 2
                    || firstLines[0].Trim() != CopyrightLine
                    || firstLines[1].Trim() != LicenceLine)
                {
                    offenders.Add(Path.GetFileName(src));
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Every C# source file must open with the SPDX copyright + GPL-3.0-only header (#747). Missing or incorrect in: " + string.Join(", ", offenders));
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

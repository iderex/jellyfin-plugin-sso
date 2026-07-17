using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api;
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
        // - SSOController.DiscoveryFactsCache: the per-discovery-URL facts cache (PKCE-S256 support #141 +
        //   the RFC 9207 response-iss advertisement #210) still lives on the controller and moves into its
        //   own probe type in a later #318 step; naming the exact field keeps anything new from hiding
        //   behind the exemption.
        // - ProviderConfigBase._canonicalLinks: the persisted account-link map — serialized plugin
        //   configuration mutated only under the config lock, so a runtime store type would be the
        //   wrong home; it is config state, not in-flight state.
        var storeLike = new[] { "Store", "Cache", "Limiter" };
        var exemptions = new[] { "SSOController.DiscoveryFactsCache", "ProviderConfigBase._canonicalLinks" };

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
        const string pruneGateField = "_pruneGate";
        var caches = new[] { typeof(SamlReplayCache), typeof(SamlRequestCache), typeof(OidcStateStore) };
        var missing = caches
            .Where(t => !t.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.DeclaredOnly)
                .Any(f => f.FieldType == typeof(IntervalGate) && f.Name == pruneGateField))
            .Select(SimpleName)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Every login-path cache must throttle its expired-entry sweep through an IntervalGate field (#452): " + string.Join(", ", missing));
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
        // target token still names the link map. A property rename (CanonicalLinks -> anything) would make
        // the scan match nothing and pass for the wrong reason, so pin the property by reflection — a rename
        // fails HERE and forces a conscious update of `linkMapProperty` (and the scanned token with it).
        const string linkMapProperty = "CanonicalLinks";
        Assert.True(
            typeof(ProviderConfigBase).GetProperty(linkMapProperty, BindingFlags.Public | BindingFlags.Instance) is not null,
            $"ProviderConfigBase.{linkMapProperty} was renamed or removed; point this rule at the new provider link-map property so the scan keeps guarding it (#388).");

        var token = "." + linkMapProperty;
        var linkMapLines = ControllerSourceFiles()
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Text: line.Trim(), Number: index + 1)))
            .Where(l => l.Text.Contains(token, StringComparison.Ordinal))
            .Select(l => $"{l.File} line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            linkMapLines.Count == 0,
            "A controller must not access a provider CanonicalLinks map directly; route link-map access through CanonicalLinkService and server-managed re-injection through ServerManagedFields.Preserve. Found: " + string.Join(" | ", linkMapLines));
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
        // this roster in the same PR that adds a new security toggle.
        var securityCritical = new[]
        {
            "EnableAuthorization", "OidSecret", "DisableHttps", "DisablePushedAuthorization",
            "DoNotValidateEndpoints", "DoNotValidateIssuerName", "DoNotValidateResponseIssuer",
            "DoNotLoadProfile", "RequirePkce",
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

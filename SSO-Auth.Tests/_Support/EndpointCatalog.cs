// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// One concrete, callable endpoint discovered from the running host's live routing table, together with the
/// authorization verdict the middleware will apply to it.
/// </summary>
/// <param name="Method">The HTTP method to use.</param>
/// <param name="Url">A concrete request path with the route parameters filled by placeholders.</param>
/// <param name="Policy">The named authorization policy, or <c>null</c> for a bare <c>[Authorize]</c>.</param>
/// <param name="Action">The controller action method name, for a readable completeness assertion.</param>
public sealed record GatedEndpoint(string Method, string Url, string? Policy, string Action)
{
    public override string ToString() => $"{Method} {Url} [{Policy ?? "authenticated"}] ({Action})";
}

/// <summary>
/// Enumerates the host's <see cref="EndpointDataSource"/> and classifies every attribute-routed endpoint by
/// its authorization requirement. Reading the LIVE endpoint table (not a hardcoded list) means a newly added
/// guarded endpoint is discovered automatically, so the completeness assertion cannot silently under-cover.
/// </summary>
public sealed class EndpointCatalog
{
    private readonly List<GatedEndpoint> _elevationGated = new();
    private readonly List<GatedEndpoint> _authenticatedOnly = new();

    public EndpointCatalog(IServiceProvider services)
    {
        var source = services.GetRequiredService<EndpointDataSource>();
        foreach (var endpoint in source.Endpoints.OfType<RouteEndpoint>())
        {
            // An explicit [AllowAnonymous] beats any [Authorize]; such an endpoint is not gated.
            if (endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null)
            {
                continue;
            }

            var authorizeAttributes = endpoint.Metadata.GetOrderedMetadata<AuthorizeAttribute>();
            if (authorizeAttributes.Count == 0)
            {
                continue;
            }

            var policy = authorizeAttributes.Select(a => a.Policy).FirstOrDefault(p => !string.IsNullOrEmpty(p));
            var methods = endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? new[] { HttpMethods.Get };
            var url = BuildConcreteUrl(endpoint.RoutePattern.RawText ?? string.Empty);
            var action = endpoint.Metadata.GetMetadata<ControllerActionDescriptor>()?.ActionName ?? endpoint.DisplayName ?? url;

            foreach (var method in methods)
            {
                var gated = new GatedEndpoint(method, url, policy, action);
                if (string.IsNullOrEmpty(policy))
                {
                    _authenticatedOnly.Add(gated);
                }
                else
                {
                    _elevationGated.Add(gated);
                }
            }
        }
    }

    /// <summary>Gets the endpoints guarded by a named policy (the elevation-gated admin surface).</summary>
    public IReadOnlyList<GatedEndpoint> ElevationGated => _elevationGated;

    /// <summary>Gets the endpoints guarded by a bare <c>[Authorize]</c> (any authenticated caller).</summary>
    public IReadOnlyList<GatedEndpoint> AuthenticatedOnly => _authenticatedOnly;

    // Fills every route parameter with a placeholder segment. A GUID is used everywhere: it is a valid
    // non-empty value for a string parameter and also parses for a Guid-typed one, so routing always reaches
    // the endpoint (the authorization middleware runs before any model binding could reject the value).
    private static string BuildConcreteUrl(string rawTemplate)
    {
        var segments = rawTemplate.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var filled = segments.Select(segment => segment.StartsWith('{') ? Guid.NewGuid().ToString() : segment);
        return "/" + string.Join('/', filled);
    }
}

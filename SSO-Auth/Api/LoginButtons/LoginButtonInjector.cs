// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace Jellyfin.Plugin.SSO_Auth.Api.LoginButtons;

/// <summary>
/// Pure string logic that renders the SSO "Sign in with …" buttons and splices them into Jellyfin's
/// login-page branding disclaimer (#722). No I/O — <see cref="LoginButtonManager"/> owns the read/write of
/// the server's <c>BrandingOptions.LoginDisclaimer</c>; this type only transforms strings, so it is
/// exhaustively unit-testable, which matters because the output is rendered into an anonymous, pre-auth page.
/// </summary>
/// <remarks>
/// SECURITY — this output is HTML rendered on the login page for every visitor, so it is an XSS sink. Every
/// interpolated value is <see cref="WebUtility.HtmlEncode(string)"/>d and every provider name placed in a URL
/// is additionally <see cref="Uri.EscapeDataString(string)"/>d; the markup is assembled only from a fixed
/// template plus those encoded values — no admin string is ever passed through as raw HTML. The managed block
/// is fenced between unique marker comments so <see cref="Merge"/> can replace or remove exactly its own
/// region and never disturb an admin's surrounding disclaimer content, idempotently.
/// </remarks>
public static class LoginButtonInjector
{
    /// <summary>The opening fence of the plugin-managed region inside the login disclaimer.</summary>
    internal const string BeginMarker = "<!-- SSO-LOGIN-BUTTONS:BEGIN (managed by jellyfin-plugin-sso — do not edit inside) -->";

    /// <summary>The closing fence of the plugin-managed region.</summary>
    internal const string EndMarker = "<!-- SSO-LOGIN-BUTTONS:END -->";

    /// <summary>
    /// Renders the managed button block, or the empty string when there are no buttons. The returned string,
    /// when non-empty, always begins with <see cref="BeginMarker"/> and ends with <see cref="EndMarker"/>.
    /// </summary>
    /// <param name="buttons">The buttons to render, in order.</param>
    /// <returns>The fenced HTML block, or an empty string when <paramref name="buttons"/> is empty.</returns>
    public static string BuildBlock(IReadOnlyList<LoginButton> buttons)
    {
        ArgumentNullException.ThrowIfNull(buttons);
        if (buttons.Count == 0)
        {
            return string.Empty;
        }

        var sb = new StringBuilder();
        sb.Append(BeginMarker).Append('\n');
        sb.Append("<div class=\"sso-login-buttons\">").Append('\n');
        foreach (var button in buttons)
        {
            // Route segment is a fixed literal chosen by the enum — never interpolated from input.
            var segment = button.Protocol == LoginButtonProtocol.Saml ? "SAML" : "OID";

            // The provider name in the href is URL-encoded (path segment). Provider names are already
            // validated to exclude URI-reserved and control characters (#336), but encode regardless so a
            // future relaxation cannot turn this into an injection or a broken link.
            var href = "/sso/" + segment + "/start/" + Uri.EscapeDataString(button.Name);

            // Both the href attribute value and the visible label are HTML-encoded, so a name/label such as
            // `"><script>…` renders as inert text, never markup. HtmlEncode also encodes the quotes that
            // would otherwise break out of the attribute.
            sb.Append("  <a class=\"raised block emby-button sso-login-button\" href=\"")
                .Append(WebUtility.HtmlEncode(href))
                .Append("\">")
                .Append(WebUtility.HtmlEncode(button.Text))
                .Append("</a>")
                .Append('\n');
        }

        sb.Append("</div>").Append('\n');
        sb.Append(EndMarker);
        return sb.ToString();
    }

    /// <summary>
    /// Splices <paramref name="block"/> into <paramref name="existingDisclaimer"/> idempotently: an existing
    /// managed region (between the markers) is replaced; when none is present the block is appended; and an
    /// empty <paramref name="block"/> removes the managed region entirely, restoring the surrounding admin
    /// content. Content outside the markers — an admin's own disclaimer — is preserved, aside from the
    /// blank-line separator the managed region introduces, which is collapsed on removal so repeated
    /// enable/disable cycles cannot accumulate whitespace.
    /// </summary>
    /// <param name="existingDisclaimer">The current login disclaimer (may be null/empty).</param>
    /// <param name="block">The managed block from <see cref="BuildBlock"/> (empty to remove the region).</param>
    /// <returns>The merged disclaimer.</returns>
    public static string Merge(string? existingDisclaimer, string block)
    {
        ArgumentNullException.ThrowIfNull(block);
        var current = existingDisclaimer ?? string.Empty;

        var begin = current.IndexOf(BeginMarker, StringComparison.Ordinal);

        // Search for the CLOSING fence only AFTER the opener. Searching from 0 would let a stray END that a
        // hand-edited disclaimer placed BEFORE the BEGIN make the region look malformed on every sync, so a
        // fresh block would be re-appended each time — and because a login's canonical-link write also raises
        // the config-changed event, that would grow the disclaimer without bound, once per login. Anchoring
        // the END search past the BEGIN ignores the stray marker and converges instead.
        var end = begin >= 0
            ? current.IndexOf(EndMarker, begin + BeginMarker.Length, StringComparison.Ordinal)
            : -1;

        // A well-formed existing region is BEGIN then END-after-BEGIN. Anything else (only one marker) is
        // treated as "no managed region": we never parse a partial fence, so we cannot corrupt surrounding
        // content. A fresh block then appends cleanly.
        var hasRegion = begin >= 0 && end >= 0;

        if (!hasRegion)
        {
            if (block.Length == 0)
            {
                return current;
            }

            // Append with a single blank-line separator only when there is prior content to separate from.
            return current.Length == 0 ? block : current.TrimEnd('\n') + "\n\n" + block;
        }

        var before = current[..begin];
        var after = current[(end + EndMarker.Length)..];

        if (block.Length == 0)
        {
            // Remove the region and heal the seam: collapse the blank-line separator the insert introduced so
            // repeated enable/disable cycles do not accumulate whitespace, then trim a now-trailing gap.
            var healed = before.TrimEnd('\n');
            var tail = after.TrimStart('\n');
            if (healed.Length == 0)
            {
                return tail;
            }

            return tail.Length == 0 ? healed : healed + "\n\n" + tail;
        }

        return before + block + after;
    }
}

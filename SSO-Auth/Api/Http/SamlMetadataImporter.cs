using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>
/// Orchestrates a SAML IdP-metadata import (#735): it takes EITHER a metadata URL (fetched server-side) or
/// pasted metadata XML, and returns the parsed <see cref="SamlMetadataImport"/>. The URL is fetched through
/// the plugin's SSRF-hardened outbound client (<see cref="SsoHttp"/>) — the same transport the OpenID
/// discovery fetch uses, so an admin-supplied URL that resolves to a private/loopback address cannot be used
/// to probe internal services — with a hard body-size cap and timeout on top. The XML is then parsed with
/// the fail-closed hardening in <see cref="SamlMetadataParser"/>. Any failure throws
/// <see cref="SamlMetadataException"/> and nothing is applied.
/// </summary>
internal static class SamlMetadataImporter
{
    // The fetched body is capped at the same size the parser will accept, so an oversized document is refused
    // before it is buffered, not after.
    private const int MaxBytes = SamlMetadataParser.MaxCharactersInDocument;

    private static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Imports SAML metadata from exactly one of a URL or pasted XML.
    /// </summary>
    /// <param name="factory">The shared HTTP client factory (resolves the SSRF-hardened outbound client).</param>
    /// <param name="url">The metadata URL to fetch, or null/blank when pasting XML.</param>
    /// <param name="xml">The pasted metadata XML, or null/blank when fetching a URL.</param>
    /// <param name="cancellationToken">Cancels the outbound fetch.</param>
    /// <returns>The parsed, validated import values.</returns>
    /// <exception cref="SamlMetadataException">Neither or both inputs given, the fetch failed, or the metadata is invalid.</exception>
    internal static async Task<SamlMetadataImport> ImportAsync(IHttpClientFactory factory, string? url, string? xml, CancellationToken cancellationToken)
    {
        var hasUrl = !string.IsNullOrWhiteSpace(url);
        var hasXml = !string.IsNullOrWhiteSpace(xml);
        if (hasUrl == hasXml)
        {
            throw new SamlMetadataException("Provide exactly one of a metadata URL or pasted metadata XML.");
        }

        var metadataXml = hasXml
            ? xml!
            : await FetchAsync(factory, url!.Trim(), cancellationToken).ConfigureAwait(false);

        return SamlMetadataParser.Parse(metadataXml);
    }

    private static async Task<string> FetchAsync(IHttpClientFactory factory, string url, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)))
        {
            throw new SamlMetadataException("The metadata URL must be an absolute http(s) URL.");
        }

        using var client = SsoHttp.CreateClient(factory);
        client.Timeout = FetchTimeout;

        // An overall deadline linked to the caller's token: client.Timeout with ResponseHeadersRead covers
        // only the header fetch, so this also bounds the streamed body read — a slow-drip server cannot hold
        // the fetch open past FetchTimeout.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(FetchTimeout);

        try
        {
            using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            return await ReadCappedAsync(response, deadline.Token).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            // Unreachable host, a blocked (private/loopback) address rejected by the hardened transport, or a
            // non-success status — all fail closed with an admin-facing message; no library detail is echoed.
            throw new SamlMetadataException("The metadata URL could not be fetched (unreachable, blocked, or an error response).", ex);
        }
        catch (IOException ex)
        {
            // A mid-stream connection reset while reading the body — fail closed as a clean 400, not a 500.
            throw new SamlMetadataException("The metadata could not be read from the URL.", ex);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            // The linked deadline (or the client timeout) fired, not the caller's own cancellation.
            throw new SamlMetadataException("The metadata URL fetch timed out.", ex);
        }
    }

    // Reads the response body with a hard byte cap: the SSRF-hardened transport restricts WHERE the fetch
    // connects, and this bounds HOW MUCH it will buffer, so a hostile or accidental multi-megabyte document
    // cannot exhaust memory.
    private static async Task<string> ReadCappedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffered = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffered.Length + read > MaxBytes)
            {
                throw new SamlMetadataException("The metadata document exceeds the size limit.");
            }

            buffered.Write(chunk, 0, read);
        }

        // Decode honouring the byte-order mark: ADFS (a very common IdP) serves FederationMetadata.xml as
        // UTF-8-with-BOM, and a raw Encoding.UTF8.GetString would leave a U+FEFF before the XML declaration
        // that the reader rejects. StreamReader with BOM detection strips a UTF-8 BOM and correctly decodes a
        // UTF-16 (BOM'd) document; a plain UTF-8 body is unaffected.
        buffered.Position = 0;
        using var textReader = new StreamReader(buffered, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return await textReader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }
}

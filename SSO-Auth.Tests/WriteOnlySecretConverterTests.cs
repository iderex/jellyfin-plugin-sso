using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Behavioral tests for <see cref="WriteOnlySecretConverter"/> (#189/#192 Unit 2): the JSON converter
/// that makes a secret string property write-only across the System.Text.Json boundary, so a plaintext
/// secret (OidSecret, a SAML signing key) is never serialized back onto a configuration response while
/// an incoming save can still set/rotate it. These pin the converter in isolation; the property-level
/// wiring (which fields carry the attribute) is covered by ConfigPreservationTests.
/// </summary>
public class WriteOnlySecretConverterTests
{
    private static readonly WriteOnlySecretConverter Converter = new();

    // A minimal holder that opts one property into the converter and leaves another as a plain string,
    // so a serialize can prove the secret is dropped while an ordinary field still round-trips.
    private sealed class SecretHolder
    {
        [JsonConverter(typeof(WriteOnlySecretConverter))]
        public string? Secret { get; set; }

        public string? Public { get; set; }
    }

    [Fact]
    public void Write_EmitsJsonNull_NeverTheSecretValue()
    {
        // The load-bearing guarantee: Write must emit a JSON null literal, not the secret and not an
        // empty string. Driven directly against the converter so nothing else can mask the behavior.
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            Converter.Write(writer, "super-secret-value", JsonSerializerOptions.Default);
        }

        var json = Encoding.UTF8.GetString(stream.ToArray());
        Assert.Equal("null", json);
        Assert.DoesNotContain("super-secret-value", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Read_ReturnsTheValueVerbatim_SoInboundSetAndRotationStillWork()
    {
        // The write-only-ness must not break the read half: an incoming save value deserializes as-is.
        var bytes = Encoding.UTF8.GetBytes("\"inbound-secret\"");
        var reader = new Utf8JsonReader(bytes);
        Assert.True(reader.Read()); // position the reader on the string token, as the serializer would

        var result = Converter.Read(ref reader, typeof(string), JsonSerializerOptions.Default);

        Assert.Equal("inbound-secret", result);
    }

    [Fact]
    public void Serialize_PropertyUsingConverter_IsNulled_WhileSiblingFieldSurvives()
    {
        // Through the [JsonConverter] attribute path, exactly as the config models wire it: the secret
        // property is emitted as null (present but valueless) and its plaintext never appears, while an
        // ordinary field on the same object is untouched.
        var holder = new SecretHolder { Secret = "s3cr3t-blob", Public = "visible" };

        var json = JsonSerializer.Serialize(holder);

        Assert.DoesNotContain("s3cr3t-blob", json, StringComparison.Ordinal);
        Assert.Contains("\"Secret\":null", json, StringComparison.Ordinal);
        Assert.Contains("\"Public\":\"visible\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Serialize_UnderCamelCasePolicy_StillHidesTheSecret()
    {
        // Jellyfin core serializes the plugin config with a camelCase naming policy; the property name
        // changes but the hidden-value guarantee must not.
        var holder = new SecretHolder { Secret = "camel-secret", Public = "visible" };

        var json = JsonSerializer.Serialize(
            holder,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

        Assert.DoesNotContain("camel-secret", json, StringComparison.Ordinal);
        Assert.Contains("\"secret\":null", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Deserialize_PopulatesTheSecret_FromAnIncomingSave()
    {
        // The realistic inbound boundary (config PUT / OID Add): a typed secret survives deserialization,
        // which is the exact case a bidirectional [JsonIgnore] would have silently broken.
        var parsed = JsonSerializer.Deserialize<SecretHolder>("{\"Secret\":\"typed-secret\",\"Public\":\"p\"}");

        Assert.Equal("typed-secret", parsed!.Secret);
        Assert.Equal("p", parsed.Public);
    }

    [Fact]
    public void RoundTrip_SerializeThenDeserialize_NeverLeaksAPreviouslySetSecret()
    {
        // A GET-then-parse (the shape of reading back a configuration response) can never recover a
        // secret that was set on the server: it left as null, so it comes back null.
        var original = new SecretHolder { Secret = "leak-me-if-you-can", Public = "keep" };

        var json = JsonSerializer.Serialize(original);
        Assert.DoesNotContain("leak-me-if-you-can", json, StringComparison.Ordinal);

        var back = JsonSerializer.Deserialize<SecretHolder>(json);

        Assert.True(string.IsNullOrEmpty(back!.Secret));
        Assert.Equal("keep", back.Public);
    }
}

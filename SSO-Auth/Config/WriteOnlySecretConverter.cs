using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Makes a string property write-only across the JSON boundary (#189): it is still read
/// (deserialized) from an incoming save as normal, so the value can be set and rotated, but it is
/// never written (serialized) back out — a configuration response carries the property as
/// <c>null</c> instead of its stored value, so the plaintext secret never reaches the admin browser,
/// a HAR capture, or a proxy log. This is deliberately NOT <c>[JsonIgnore]</c>: that attribute is
/// bidirectional and would also drop the value on the incoming save, silently breaking rotation and
/// new-provider setup. The field is still persisted to the config XML (this converter only affects
/// System.Text.Json).
/// </summary>
internal sealed class WriteOnlySecretConverter : JsonConverter<string>
{
    /// <inheritdoc />
    public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => reader.TokenType == JsonTokenType.Null ? null : reader.GetString();

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
        => writer.WriteNullValue();
}

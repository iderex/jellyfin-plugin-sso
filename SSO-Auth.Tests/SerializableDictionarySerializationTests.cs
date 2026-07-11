using System;
using System.IO;
using System.Xml.Serialization;
using Jellyfin.Plugin.SSO_Auth;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Serialization round-trip tests for <see cref="SerializableDictionary{TKey,TValue}"/>. This type
/// backs the persisted plugin configuration (SamlConfigs / OidConfigs / CanonicalLinks), so its XML
/// format must stay stable — in particular, moving the type into a named namespace must not change
/// the on-disk XML, or existing installations' saved configuration would fail to load.
/// </summary>
public class SerializableDictionarySerializationTests
{
    [Fact]
    public void RoundTrip_StringToGuid_PreservesEntries()
    {
        var original = new SerializableDictionary<string, Guid>
        {
            ["alice@example.com"] = Guid.NewGuid(),
            ["bob"] = Guid.NewGuid(),
        };

        var restored = RoundTrip(original);

        Assert.Equal(original.Count, restored.Count);
        foreach (var pair in original)
        {
            Assert.Equal(pair.Value, restored[pair.Key]);
        }
    }

    [Fact]
    public void Serialize_DoesNotLeakClrNamespaceIntoXml()
    {
        // The CLR namespace must not appear in the XML: the format is defined entirely by
        // IXmlSerializable (item/key/value), so it is independent of where the type lives.
        // This is what lets the namespace move stay backward-compatible with saved config.
        var dict = new SerializableDictionary<string, Guid> { ["provider"] = Guid.NewGuid() };

        var xml = Serialize(dict);

        Assert.DoesNotContain("Jellyfin.Plugin", xml, StringComparison.Ordinal);
    }

    [Fact]
    public void Deserialize_FromLegacyFormatXml_StillLoads()
    {
        // A document in the exact shape the type has always written (as produced before the type
        // was moved into a namespace) must still deserialize unchanged.
        var id = Guid.NewGuid();
        var legacy =
            "<?xml version=\"1.0\" encoding=\"utf-16\"?>" +
            "<dictionary><item><key><string>keycloak</string></key>" +
            "<value><guid>" + id + "</guid></value></item></dictionary>";

        var serializer = new XmlSerializer(typeof(SerializableDictionary<string, Guid>));
        using var reader = new StringReader(legacy);
        var restored = (SerializableDictionary<string, Guid>)serializer.Deserialize(reader)!;

        Assert.Equal(id, restored["keycloak"]);
    }

    private static string Serialize<TKey, TValue>(SerializableDictionary<TKey, TValue> value)
    {
        var serializer = new XmlSerializer(typeof(SerializableDictionary<TKey, TValue>));
        using var writer = new StringWriter();
        serializer.Serialize(writer, value);
        return writer.ToString();
    }

    private static SerializableDictionary<TKey, TValue> RoundTrip<TKey, TValue>(SerializableDictionary<TKey, TValue> value)
    {
        var serializer = new XmlSerializer(typeof(SerializableDictionary<TKey, TValue>));
        using var reader = new StringReader(Serialize(value));
        return (SerializableDictionary<TKey, TValue>)serializer.Deserialize(reader)!;
    }
}

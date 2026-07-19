using System;
using System.IO;
using System.Xml;
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
        // The type's CLR namespace must not appear in the XML: the format is defined entirely by
        // IXmlSerializable (item/key/value), so it is independent of where the type lives. This is
        // what lets the namespace move stay backward-compatible with saved config. Assert against
        // the type's actual namespace so the test stays correct if the namespace is ever renamed.
        var dict = new SerializableDictionary<string, Guid> { ["provider"] = Guid.NewGuid() };
        var clrNamespace = typeof(SerializableDictionary<string, Guid>).Namespace;

        var xml = Serialize(dict);

        Assert.False(string.IsNullOrEmpty(clrNamespace));
        Assert.DoesNotContain(clrNamespace, xml, StringComparison.Ordinal);
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

        var restored = Deserialize<string, Guid>(legacy);

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
        => Deserialize<TKey, TValue>(Serialize(value));

    // Deserializes through the XmlReader overload with DTD processing prohibited (the
    // XmlReaderSettings default) — the hardened pattern CA5369 requires, mirroring how the
    // production type is only ever read through an XmlReader.
    private static SerializableDictionary<TKey, TValue> Deserialize<TKey, TValue>(string xml)
    {
        var serializer = new XmlSerializer(typeof(SerializableDictionary<TKey, TValue>));
        using var stringReader = new StringReader(xml);
        using var xmlReader = XmlReader.Create(stringReader, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        return (SerializableDictionary<TKey, TValue>)serializer.Deserialize(xmlReader)!;
    }
}

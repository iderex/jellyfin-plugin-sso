#nullable enable

using System.Collections.Generic;
using System.Xml.Serialization;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// For some reason, the generic Dictionary in .net 2.0 is not XML serializable. The following code snippet is a xml serializable generic dictionary. The dictionary is serializable by implementing the IXmlSerializable interface.
/// Also see https://weblogs.asp.net/pwelter34/444961 for additional information.
/// </summary>
/// <typeparam name="TKey">Type of the dictionary key.</typeparam>
/// <typeparam name="TValue">Type of the dictionary value.</typeparam>
[XmlRoot("dictionary")]
public class SerializableDictionary<TKey, TValue>
    : Dictionary<TKey, TValue>, IXmlSerializable
    where TKey : notnull
{
    /// <summary>
    /// Gets the schema of the XML object.
    /// </summary>
    /// <returns>Nothing.</returns>
    public System.Xml.Schema.XmlSchema? GetSchema()
    {
        return null;
    }

    /// <summary>
    /// Reads XML and changes this object to be an instance of that data.
    /// </summary>
    /// <param name="reader">The XML reader to read from.</param>
    public void ReadXml(System.Xml.XmlReader reader)
    {
        System.ArgumentNullException.ThrowIfNull(reader);

        XmlSerializer keySerializer = new XmlSerializer(typeof(TKey));
        XmlSerializer valueSerializer = new XmlSerializer(typeof(TValue));

        bool wasEmpty = reader.IsEmptyElement;
        reader.Read();

        if (wasEmpty)
        {
            return;
        }

        while (reader.NodeType != System.Xml.XmlNodeType.EndElement)
        {
            reader.ReadStartElement("item");

            reader.ReadStartElement("key");
            TKey key = (TKey)keySerializer.Deserialize(reader)!;
            reader.ReadEndElement();

            reader.ReadStartElement("value");
            TValue value = (TValue)valueSerializer.Deserialize(reader)!;
            reader.ReadEndElement();

            this.Add(key, value);

            reader.ReadEndElement();
            reader.MoveToContent();
        }

        reader.ReadEndElement();
    }

    /// <summary>
    /// Writes XML to the XML writer from this object.
    /// </summary>
    /// <param name="writer">An instance of the XmlWriter class.</param>
    public void WriteXml(System.Xml.XmlWriter writer)
    {
        System.ArgumentNullException.ThrowIfNull(writer);

        XmlSerializer keySerializer = new XmlSerializer(typeof(TKey));
        XmlSerializer valueSerializer = new XmlSerializer(typeof(TValue));

        foreach (TKey key in this.Keys)
        {
            writer.WriteStartElement("item");

            writer.WriteStartElement("key");
            keySerializer.Serialize(writer, key);
            writer.WriteEndElement();

            writer.WriteStartElement("value");
            TValue value = this[key];
            valueSerializer.Serialize(writer, value);
            writer.WriteEndElement();

            writer.WriteEndElement();
        }
    }
}

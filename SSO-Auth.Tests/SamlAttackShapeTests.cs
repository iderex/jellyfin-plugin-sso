using System.Xml;
using Jellyfin.Plugin.SSO_Auth;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization/regression tests pinning the SAML core's defenses against the known
/// 2025-2026 SAML attack shapes (#153). They complement <see cref="SamlResponseTests"/>
/// (which already pins SHA-1 downgrade, DOCTYPE/XXE, missing time-bounds, audience/recipient
/// confusion, plain two-assertion wrapping and relocated-signature) by adding the shapes that
/// were not yet pinned:
///
/// <list type="bullet">
///   <item>comment-truncation of NameID (CVE-2017-11428 — https://nvd.nist.gov/vuln/detail/CVE-2017-11428),</item>
///   <item>an unsigned assertion injected BEFORE the signed one,</item>
///   <item>duplicate and foreign-namespaced ID-attribute pollution (PortSwigger 'The Fragile Lock', 2025 —
///         https://portswigger.net/research/the-fragile-lock; GHSL-2024-329/330),</item>
///   <item>a ds:Signature relocated into a decoy wrapper outside the element its Reference covers,</item>
///   <item>assertion/advice confusion (a decoy assertion smuggled into saml:Advice).</item>
/// </list>
///
/// Every malicious shape must be REJECTED (or, for comment-truncation, must NOT be truncatable)
/// and the honest baseline ACCEPTED — all against the real signature-validation path in
/// <see cref="Response"/>, never a mock of the crypto. These are TESTS ONLY: they pin existing
/// fail-closed behavior; no production change is expected while that behavior holds. A shape that
/// turns out to be ACCEPTED is a real defect to be filed as its own security finding, not papered
/// over here.
/// </summary>
public class SamlAttackShapeTests
{
    private const string SamlNs = "urn:oasis:names:tc:SAML:2.0:assertion";
    private const string DsNs = "http://www.w3.org/2000/09/xmldsig#";

    private static Response Load(SamlFixture fixture, string? certificateBase64 = null)
        => new Response(certificateBase64 ?? fixture.CertificateBase64, fixture.EncodeResponse());

    [Fact]
    public void IsValid_HonestBaseline_ReturnsTrue()
    {
        // The honest, correctly-signed response is accepted — the control every negative case below
        // is measured against, so a rejection there is attributable to the injected shape, not the setup.
        Assert.True(Load(SamlTestFactory.Create()).IsValid());
    }

    // --- Comment truncation (CVE-2017-11428) ---

    [Fact]
    public void GetNameID_CommentSplitNameId_IsNotTruncated_AndSignatureStaysValid()
    {
        // CVE-2017-11428: the IdP signs NameID = "admin@attacker.example" (the attacker's real
        // account). The attacker then splits it around an XML comment — "admin<!--x-->@attacker.example"
        // — WITHOUT changing the comment-free canonical text, so exclusive C14N (comment-free) strips
        // the comment and the signature still verifies. An SP that reads only the first text node
        // (FirstChild.Value) would truncate to "admin" and grant the privileged account. The plugin
        // reads XmlNode.InnerText, which concatenates across the comment, so the value is NOT
        // truncatable. This pins that: a refactor to FirstChild.Value/InnerXml would flip it and
        // silently reintroduce the CVE.
        var fixture = SamlTestFactory.Create(nameId: "admin@attacker.example", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var nameId = doc.GetElementsByTagName("NameID", SamlNs)[0]!;
        nameId.RemoveAll();
        nameId.AppendChild(doc.CreateTextNode("admin"));
        nameId.AppendChild(doc.CreateComment("x"));
        nameId.AppendChild(doc.CreateTextNode("@attacker.example"));

        var response = Load(fixture);

        // The comment does not alter the comment-free canonical form, so the signature remains valid...
        Assert.True(response.IsValid());
        // ...and the extracted identity is the FULL address, never the truncated "admin".
        Assert.Equal("admin@attacker.example", response.GetNameID());
        Assert.NotEqual("admin", response.GetNameID());
    }

    [Fact]
    public void GetCustomAttribute_CommentSplitAttributeValue_IsNotTruncated()
    {
        // The same truncation trick applied to a Role AttributeValue: an SP that truncated at the
        // comment could read "jellyfin-" instead of "jellyfin-users" (or drop a suffix that gates a
        // role match). InnerText concatenates, so the full value survives.
        var fixture = SamlTestFactory.Create(role: "jellyfin-users", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var attributeValue = doc.GetElementsByTagName("AttributeValue", SamlNs)[0]!;
        attributeValue.RemoveAll();
        attributeValue.AppendChild(doc.CreateTextNode("jellyfin-"));
        attributeValue.AppendChild(doc.CreateComment("x"));
        attributeValue.AppendChild(doc.CreateTextNode("users"));

        var response = Load(fixture);

        Assert.True(response.IsValid());
        Assert.Equal("jellyfin-users", response.GetCustomAttribute("Role"));
    }

    // --- Assertion injected before the signed one ---

    [Fact]
    public void IsValid_UnsignedAssertionPrependedToResponseScopeSignature_ReturnsFalse()
    {
        // The whole Response is signed; the attacker prepends an unsigned assertion carrying a
        // different identity as the FIRST assertion (the one every reader consumes as Assertion[1]).
        // Rejected twice over: the single-assertion invariant now counts two direct-child assertions,
        // and prepending also perturbs the signed Response so the digest no longer matches.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Response);
        var doc = fixture.Document;
        doc.DocumentElement!.PrependChild(BuildEvilAssertion(doc, "attacker"));

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_UnsignedAssertionPrependedToAssertionScopeSignature_ReturnsFalse()
    {
        // Only the honest assertion is signed; the attacker prepends an unsigned assertion so that
        // Assertion[1] is theirs while the signature reference still resolves to the honest, second
        // assertion. The single-assertion invariant rejects the response before any reader can be
        // pointed at the attacker's node.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        doc.DocumentElement!.PrependChild(BuildEvilAssertion(doc, "attacker"));

        Assert.False(Load(fixture).IsValid());
    }

    // --- Duplicate / namespaced ID-attribute pollution (GHSL-2024-329/330, 'The Fragile Lock') ---

    [Fact]
    public void IsValid_DecoyElementReusesSignedAssertionId_ReturnsFalse()
    {
        // ID pollution: a decoy element (not an assertion, so the single-assertion count stays one)
        // is given the SAME plain ID as the signed assertion. ID resolution over the untrusted
        // document is now ambiguous; the validator must fail closed rather than let the attacker steer
        // which element the "#id" reference resolves to.
        var fixture = SamlTestFactory.Create(scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var decoy = doc.CreateElement("saml", "AuthnStatement", SamlNs);
        decoy.SetAttribute("ID", fixture.AssertionId);
        doc.DocumentElement!.PrependChild(decoy);

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_ForeignNamespacedIdOnDecoy_DoesNotSatisfyReference_ReturnsFalse()
    {
        // A decoy assertion is injected whose ID is declared only through a FOREIGN-namespace
        // attribute (xml:id), a shape parsers have historically resolved inconsistently. Here the
        // decoy also carries the reference's target value, attempting to make the "#id" reference bind
        // to attacker content. It must not: rejection stands (the extra assertion also trips the
        // single-assertion invariant), and the foreign-namespaced id never becomes a valid signature
        // target.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var decoy = BuildEvilAssertion(doc, "attacker");
        var xmlId = doc.CreateAttribute("xml", "id", "http://www.w3.org/XML/1998/namespace");
        xmlId.Value = fixture.AssertionId;
        decoy.SetAttributeNode(xmlId);
        doc.DocumentElement!.PrependChild(decoy);

        Assert.False(Load(fixture).IsValid());
    }

    // --- Signature relocated into a decoy wrapper outside the covered element ---

    [Fact]
    public void IsValid_SignatureRelocatedIntoDecoyWrapper_ReturnsFalse()
    {
        // The enveloped signature is lifted out of the assertion it covers and re-parented under a
        // decoy wrapper element hung off the Response. The reference still names the assertion ID, but
        // the position-bound signature selection only accepts a ds:Signature that is a direct child of
        // the Response or the Assertion — a signature buried in a wrapper is not selected at all, so
        // the response reads as unsigned and is rejected.
        var fixture = SamlTestFactory.Create(scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var signature = doc.GetElementsByTagName("Signature", DsNs)[0]!;
        signature.ParentNode!.RemoveChild(signature);
        var wrapper = doc.CreateElement("saml", "Advice", SamlNs);
        wrapper.AppendChild(signature);
        doc.DocumentElement!.AppendChild(wrapper);

        Assert.False(Load(fixture).IsValid());
    }

    // --- Assertion / Advice confusion ---

    [Fact]
    public void GetNameID_DecoyAssertionInsideAdvice_ReadsSignedSubjectNotAdvice()
    {
        // A decoy assertion carrying "attacker" is smuggled into the honest assertion's saml:Advice.
        // Because it is added AFTER signing it is not part of the signed content, yet saml:Advice is a
        // spec-legal container so the response must not be rejected merely for its presence — instead
        // the readers, scoped to the Response's direct-child Assertion[1]/Subject, must ignore the
        // nested decoy and continue to read the signed "alice". This pins assertion/advice confusion
        // resistance: the advice subject never shadows the real one.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Response);
        var doc = fixture.Document;
        var assertion = (XmlElement)doc.GetElementsByTagName("Assertion", SamlNs)[0]!;
        var advice = doc.CreateElement("saml", "Advice", SamlNs);
        advice.AppendChild(BuildEvilAssertion(doc, "attacker"));
        // Advice must precede Subject per the SAML schema; prepend keeps the document schema-shaped.
        assertion.PrependChild(advice);

        var response = Load(fixture);

        // Adding the (unsigned) advice perturbs the signed Response, so IsValid is false; the
        // load-bearing assertion is that identity extraction never returns the advice's "attacker".
        Assert.NotEqual("attacker", response.GetNameID());
        Assert.Equal("alice", response.GetNameID());
    }

    // Builds an unsigned attacker-controlled assertion with the given NameID, shaped like a real one
    // (ID/Version/Subject/NameID) so injection tests exercise the count/reference/position checks
    // rather than tripping on malformed XML.
    private static XmlElement BuildEvilAssertion(XmlDocument doc, string nameId)
    {
        var evil = doc.CreateElement("saml", "Assertion", SamlNs);
        evil.SetAttribute("ID", "_evil");
        evil.SetAttribute("Version", "2.0");
        var subject = doc.CreateElement("saml", "Subject", SamlNs);
        var name = doc.CreateElement("saml", "NameID", SamlNs);
        name.InnerText = nameId;
        subject.AppendChild(name);
        evil.AppendChild(subject);
        return evil;
    }
}

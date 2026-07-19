using Jellyfin.Plugin.SSO_Auth;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Interop regression tests pinning that a conformantly-signed, PRETTY-PRINTED SAML response — real
/// inter-element line breaks and indentation on the wire, the shape production IdP signing stacks emit
/// — still validates through <see cref="SamlResponse"/> (#120). Follow-up to the P2#9 XML hardening,
/// which moved the parser from <c>XmlDocument.LoadXml</c> to an <see cref="System.Xml.XmlReader"/>
/// (<see cref="System.Xml.DtdProcessing.Prohibit"/>): the reader normalizes CR/CRLF line endings to LF
/// per XML 1.0 §2.11 before building the DOM. The rest of the SAML suite exercises only COMPACT
/// single-line fixtures, so nothing pins that real-world CRLF/indentation interop survives; a
/// regression to a non-normalizing parser would break it while passing every existing test.
///
/// The whitespace between elements is signature-covered — <c>PreserveWhitespace</c> keeps it and
/// exclusive C14N includes it — so this shape is what actually exercises line-ending handling. The
/// three cases together make the pin non-vacuous and guard the load-bearing correctness point the
/// issue calls out (the <c>OuterXml</c>-escaping pitfall):
///
/// <list type="bullet">
///   <item><see cref="IsValid_WireWithRawCrlfBetweenElements_NormalizesAndValidates"/> — RAW CRLF bytes
///     (0x0D 0x0A) on the wire, encoded directly, validate against a signature computed over the LF
///     form: the core interop property.</item>
///   <item><see cref="IsValid_InterElementWhitespaceAltered_FailsClosed"/> — altering the whitespace
///     CONTENT (an extra space the IdP never signed) is a digest mismatch and is rejected. This proves
///     the whitespace is genuinely signature-covered, so the case above passes because of line-ending
///     NORMALIZATION (CRLF ≡ LF), not because the parser ignores whitespace.</item>
///   <item><see cref="IsValid_LineEndingCrAsCharacterReference_StillValidates"/> — the same line ending
///     written as a <c>&amp;#xD;</c> character reference (what serializing a CR-bearing DOM via
///     <c>OuterXml</c> emits) is exempt from §2.11 normalization, yet .NET's C14N in
///     <see cref="System.Security.Cryptography.Xml.SignedXml"/> normalizes line-ending CR as well, so
///     this form ALSO validates. A "CRLF" test built via <c>OuterXml</c> would therefore go green while
///     shipping <c>&amp;#xD;</c> instead of raw CRLF — passing for the wrong reason. Pinning this is why
///     the positive test encodes raw wire bytes and asserts the wire carries CR, not <c>&amp;#xD;</c>.
///     No security impact: only the line-ending REPRESENTATION is normalized; the content stays
///     covered (previous case).</item>
/// </list>
///
/// All three drive the real signature-validation path in <see cref="SamlResponse"/> against a genuinely
/// signed fixture (<see cref="SamlTestFactory.CreateIndented"/>), never a mock of the crypto.
/// </summary>
public class SamlCrlfInteropTests
{
    [Fact]
    public void IsValid_WireWithRawCrlfBetweenElements_NormalizesAndValidates()
    {
        var fixture = SamlTestFactory.CreateIndented();

        // The signed document serializes to an LF baseline with no stray CR — confirm that before
        // reshaping it, so the CRLF on the wire below is introduced here, not already present.
        var lfBaseline = fixture.Document.OuterXml;
        Assert.Contains("\n", lfBaseline);
        Assert.DoesNotContain("\r", lfBaseline);
        Assert.DoesNotContain("&#xD;", lfBaseline);

        // Put RAW CRLF bytes on the wire between elements — the shape a conformant IdP emits — and
        // encode those bytes directly (never via OuterXml, which would escape CR to &#xD;). The reader
        // normalizes CRLF -> LF to reproduce the signed form, so the signature verifies.
        var wire = lfBaseline.Replace("\n", "\r\n");
        Assert.Contains("\r\n", wire);
        Assert.DoesNotContain("&#xD;", wire); // raw CR bytes on the wire, not the OuterXml escape

        var response = new SamlResponse(fixture.CertificateBase64, SamlFixture.Encode(wire));

        Assert.True(response.IsValid());
        Assert.Equal("alice", response.GetNameID()); // end-to-end read-through, not just the signature
    }

    [Fact]
    public void IsValid_InterElementWhitespaceAltered_FailsClosed()
    {
        // Vacuity guard for the raw-CRLF case: the inter-element whitespace is signature-covered, so
        // changing its CONTENT — here one extra indentation space the IdP never signed — is a digest
        // mismatch and is rejected. This is what makes the raw-CRLF acceptance meaningful: it is
        // specifically line-ending normalization (CRLF ≡ LF), not the parser ignoring whitespace.
        var fixture = SamlTestFactory.CreateIndented();
        var altered = fixture.Document.OuterXml.Replace("\n", "\r\n "); // CRLF plus an extra space per break

        var response = new SamlResponse(fixture.CertificateBase64, SamlFixture.Encode(altered));

        Assert.False(response.IsValid());
    }

    [Fact]
    public void IsValid_LineEndingCrAsCharacterReference_StillValidates()
    {
        // The OuterXml-escaping pitfall, pinned: the CR of the line ending expressed as a &#xD; character
        // reference (exactly what serializing a CR-bearing DOM via OuterXml produces) is exempt from XML
        // 1.0 §2.11 normalization, yet .NET's C14N normalizes line-ending CR as well, so this validates
        // too. A "CRLF" test built via OuterXml would thus pass while shipping &#xD; rather than raw
        // CRLF — passing for the wrong reason; the positive test encodes raw bytes precisely to avoid it.
        var fixture = SamlTestFactory.CreateIndented();
        var charRefWire = fixture.Document.OuterXml.Replace("\n", "&#xD;\n");
        Assert.Contains("&#xD;", charRefWire);

        var response = new SamlResponse(fixture.CertificateBase64, SamlFixture.Encode(charRefWire));

        Assert.True(response.IsValid());
    }
}

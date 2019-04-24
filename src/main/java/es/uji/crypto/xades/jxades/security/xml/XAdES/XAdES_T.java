package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.List;

/**
 *
 * <b>4.4.3 Electronic signature formats with validation data</b>
 * <br>
 * Validation of an electronic signature in accordance with the present document requires additional data needed to
 * validate the electronic signature. This additional data is called validation data; and includes:
 * <ul>
 *  <li>Public Key Certificates (PKCs) and Attributes Certificates (ACs);</li>
 *  <li>Revocation status information for each PKC and AC;</li>
 *  <li>Trusted time-stamps applied to the digital signature or a time-mark that shall be available in an audit log;</li>
 *  <li>When appropriate, the details of a signature policy to be used to verify the electronic signature.</li>
 * </ul>
 * The validation data may be collected by the signer and/or the verifier. When the signature policy identifier is present, it
 * shall meet the requirements of the signature policy. Validation data includes CA certificates as well as revocation status
 * information in the form of Certificate Revocation Lists (CRLs) or certificate status information (OCSP) provided by an
 * on-line service. Validation data also includes evidence that the signature was created before a particular point in time.
 * This may be either a time-stamp token or time-mark.
 * The present document defines properties able to contain validation data. Clauses below summarize some signature
 * formats that incorporate them and their most relevant characteristics.
 * <p>
 * <b>4.4.3.1 Electronic signature with time (XAdES-T)</b>
 * <br>
 * XML Advanced Electronic Signature with Time (XAdES-T) is a signature for which there exists a trusted time
 * associated to the signature. The trusted time may be provided by two different means:
 * <ul>
 *  <li>The SignatureTimeStamp as an unsigned property added to the electronic signature;</li>
 *  <li>A time mark of the electronic signature provided by a trusted service provider.</li>
 *  <li>
 *   A time-mark provided by a Trusted Service would have similar effect to the SignatureTimeStamp property but in
 *   this case no property is added to the electronic signature as it is the responsibility of the TSP to provide evidence of a
 *   time mark when required to do so. The management of time marks is outside the scope of the current document.
 *  </li>
 * </ul>
 * Trusted time provides the initial steps towards providing long term validity.
 * Below follows the structure of a XAdES-T form built on a XAdES-BES or a XAdES-EPES, by direct incorporation of a
 * time-stamp token within the SignatureTimeStamp element. A XAdES-T form based on time-marks MAY exist
 * without such an element.
 * <p>
 * <pre>
 *         &lt;ds:Signature ID?&gt;
 *             ...
 *             &lt;ds:Object&gt;
 *                 &lt;QualifyingProperties&gt;
 *                     ...
 *                     &lt;UnsignedProperties&gt;
 *                         &lt;UnsignedSignatureProperties&gt;
 *                             (SignatureTimeStamp)+
 *                         &lt;/UnsignedSignatureProperties&gt;
 *                     &lt;/UnsignedProperties&gt;
 *                 &lt;/QualifyingProperties&gt;
 *             &lt;/ds:Object&gt;
 *         &lt;/ds:Signature&gt;
 * </pre>
 * @author miro */
public interface XAdES_T extends XAdES_EPES {
    List<SignatureTimeStamp> getSignatureTimeStamps();
    void setSignatureTimeStamps(List<SignatureTimeStamp> signatureTimeStamps);
}

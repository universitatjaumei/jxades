package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

/*
 <OCSPRef>
 <OCSPIdentifier URI= >
 <ResponderID>
 <ByName>String of X500Principal Name</ByName>
 or
 <ByKey>base64Binary of PublicKey DER value</ByKey>
 </ResponderID>
 <ProducedAt />
 </OCSPIdentifier>
 <DigestAlgAndValue>
 <DigestMethod Algorithm= />
 <DigestValue />
 </DigestAlgAndValue>
 <ValidationResult />
 </OCSPRef>
 */

/**
 *
 * @author miro
 */
public class OCSPRef extends XAdESStructure
{
    private OCSPIdentifier ocspIdentifier;
    private DigestAlgAndValue digestAlgAndValue;
    private ValidationResult validationResult;

    // public OCSPRef(XAdESStructure parent, XAdESRevocationStatus revocationStatus)
    // throws GeneralSecurityException
    // {
    // super(parent, "OCSPRef");
    //
    // Element thisElement = getElement();
    //
    // OCSPIdentifier ocspIdentifier;
    // OCSPResponse ocspResponse = revocationStatus.getOCSPResponse();
    // URI ocspResponderURI = revocationStatus.getOCSPResponderURI();
    // ocspIdentifier = new OCSPIdentifier(this, ocspResponse, ocspResponderURI);
    //
    // DigestAlgAndValue digestAlgAndValue;
    // digestAlgAndValue = new DigestAlgAndValue(this, ocspResponse);
    //
    // ValidationResult validationResult;
    // validationResult = new ValidationResult(this, revocationStatus);
    // }

    public OCSPRef(final Node node, final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public OCSPIdentifier getOCSPIdentifier() {
        if (this.ocspIdentifier == null) {
            final Element element = getChildElementNS("OCSPIdentifier"); //$NON-NLS-1$
            if (element != null) {
				this.ocspIdentifier = new OCSPIdentifier(element, this.xadesPrefix, this.xadesNamespace,
                        this.xmlSignaturePrefix);
			}
        }
        return this.ocspIdentifier;
    }

    public DigestAlgAndValue getDigestAlgAndValue() {
        if (this.digestAlgAndValue == null) {
            final Element element = getChildElementNS("DigestAlgAndValue"); //$NON-NLS-1$
            if (element != null) {
				this.digestAlgAndValue = new DigestAlgAndValue(
					element,
					this.xadesPrefix,
					this.xadesNamespace,
                    this.xmlSignaturePrefix
                );
			}
        }

        return this.digestAlgAndValue;
    }

    public ValidationResult getValidationResult() {
        if (this.validationResult == null) {
            final Element element = getChildElementNS("ValidationResult"); //$NON-NLS-1$
            if (element != null) {
				this.validationResult = new ValidationResult(element, this.xadesPrefix, this.xadesNamespace,
                        this.xmlSignaturePrefix);
			}
        }
        return this.validationResult;
    }
}

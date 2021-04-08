package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

/*
 <CRLRef>
 <DigestAlgAndValue>
 <DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
 <DigestValue>...</DigestValue>
 </DigestAlgAndValue>
 <CRLIdentifier URI="#Signature_1_EncapsulatedCRLValue_1">
 <Issuer>...</Issuer>
 <IssueTime>...</IssueTime>
 <Number>...</Number>
 </CRLIdentifier>
 <ValidationResult />
 </CRLRef>
 */

/**
 *
 * @author miro
 */
public class CRLRef extends XAdESStructure
{
    private DigestAlgAndValue digestAlgAndValue;
    private CRLIdentifier crlIdentifier;
    private ValidationResult validationResult;

    // public CRLRef(XAdESStructure parent, XAdESRevocationStatus revocationStatus)
    // throws GeneralSecurityException
    // {
    // super(parent, "CRLRef");
    //
    // Element thisElement = getElement();
    //
    // X509CRL crl = revocationStatus.getCheckedCRL();
    // X509CRLEntry crlEntry = revocationStatus.getCRLEntry();
    //
    // DigestAlgAndValue digestAlgAndValue;
    // digestAlgAndValue = new DigestAlgAndValue(this, crl);
    //
    // CRLIdentifier crlIdentifier = new CRLIdentifier(this, revocationStatus);
    //
    // ValidationResult validationResult;
    // validationResult = new ValidationResult(this, revocationStatus);
    // }

    public CRLRef(final Node node, final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public CRLIdentifier getCRLIdentifier()
    {
        if (this.crlIdentifier == null)
        {
            final Element element = getChildElementNS("CRLIdentifier");
            if (element != null) {
				this.crlIdentifier = new CRLIdentifier(element, this.xadesPrefix, this.xadesNamespace,
                        this.xmlSignaturePrefix);
			}
        }

        return this.crlIdentifier;
    }

    public DigestAlgAndValue getDigestAlgAndValue()
    {
        if (this.digestAlgAndValue == null)
        {
            final Element element = getChildElementNS("DigestAlgAndValue");
            if (element != null) {
				this.digestAlgAndValue = new DigestAlgAndValue(element, this.xadesPrefix, this.xadesNamespace,
                        this.xmlSignaturePrefix);
			}
        }

        return this.digestAlgAndValue;
    }

    public ValidationResult getValidationResult()
    {
        if (this.validationResult == null)
        {
            final Element element = getChildElementNS("ValidationResult");
            if (element != null) {
				this.validationResult = new ValidationResult(element, this.xadesPrefix, this.xadesNamespace,
                        this.xmlSignaturePrefix);
			}
        }

        return this.validationResult;
    }

}

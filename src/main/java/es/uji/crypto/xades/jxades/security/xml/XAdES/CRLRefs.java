package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

/*
 <CRLRefs>
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
 </CRLRefs>
 */

/**
 *
 * @author miro
 */
public class CRLRefs extends XAdESStructure
{
    private List<CRLRef> crlRefs;

    // public CRLRefs(XAdESStructure parent,
    // CertValidationInfo certValidationInfo)
    // throws GeneralSecurityException
    // {
    // super(parent, "CRLRefs");
    //
    // if(certValidationInfo == null)
    // throw new IllegalArgumentException("The CertValidationInfo can not be NULL.");
    //
    // Element thisElement = getElement();
    //
    // XAdESCertPathValidatorResult validatorResult;
    // validatorResult = certValidationInfo.getCertPathValidatorResult();
    // if(validatorResult != null)
    // {
    // for(XAdESRevocationStatus revocationStatus : validatorResult.getXAdESRevocationStatuses())
    // {
    // if(revocationStatus.getCheckedCRL() != null)
    // {
    // CRLRef crlRef = new CRLRef(this, revocationStatus);
    // }
    // }
    // }
    // }

    public CRLRefs(final Node node, final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public List<CRLRef> getCRLRefs()
    {
        if (this.crlRefs == null)
        {
            final List<Element> elements = getChildElementsNS("CRLRef"); //$NON-NLS-1$
            if (elements != null && elements.size() > 0)
            {
                this.crlRefs = new ArrayList<>(elements.size());
                for (final Element element : elements)
                {
                    this.crlRefs
                            .add(new CRLRef(element, this.xadesPrefix, this.xadesNamespace,
                                    this.xmlSignaturePrefix));
                }
            }
            else
            {
                this.crlRefs = Collections.<CRLRef> emptyList();
            }
        }

        return this.crlRefs;
    }
}

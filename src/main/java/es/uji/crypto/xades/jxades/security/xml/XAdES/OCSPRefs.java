package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

/*
 <OCSPRefs>
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
 </OCSPRefs>
 */

/**
 *
 * @author miro
 */
public class OCSPRefs extends XAdESStructure
{
    private List<OCSPRef> ocspRefs;

    // public OCSPRefs(XAdESStructure parent,
    // CertValidationInfo certValidationInfo)
    // throws GeneralSecurityException
    // {
    // super(parent, "OCSPRefs");
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
    // if(revocationStatus.getOCSPResponse() != null)
    // {
    // OCSPRef ocspRef = new OCSPRef(this, revocationStatus);
    // }
    // }
    // }
    // }

    public OCSPRefs(final Node node, final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix) {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public List<OCSPRef> getOCSPRefs() {
        if (this.ocspRefs == null) {
            final List<Element> elements = getChildElementsNS("OCSPRef"); //$NON-NLS-1$
            if (elements != null && elements.size() > 0) {
                this.ocspRefs = new ArrayList<>(elements.size());
                for (final Element element : elements) {
                    this.ocspRefs.add(new OCSPRef(element, this.xadesPrefix, this.xadesNamespace,
                            this.xmlSignaturePrefix));
                }
            }
            else {
                this.ocspRefs = Collections.<OCSPRef> emptyList();
            }
        }
        return this.ocspRefs;
    }
}

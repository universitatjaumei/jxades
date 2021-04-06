package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/*
 <ds:Signature ID?>
 ...
 <ds:Object>
 <QualifyingProperties>
 <SignedProperties>
 <SignedSignatureProperties>
 (SignaturePolicyIdentifier)
 </SignedSignatureProperties>
 </SignedProperties>
 </QualifyingProperties>
 </ds:Object>
 </ds:Signature>-
 */

/**
 * 
 * @author miro
 */
public class ExplicitPolicyXAdESImpl extends BasicXAdESImpl implements XAdES_EPES
{
    /*
     * private boolean useExplicitPolicy;
     * 
     * public ExplicitPolicyXAdES(Element baseElement) { this(baseElement, true); }
     * 
     * public ExplicitPolicyXAdES(Element baseElement, boolean useExplicitPolicy) {
     * super(baseElement); this.useExplicitPolicy = useExplicitPolicy; }
     */

    public ExplicitPolicyXAdESImpl(Document document, Element baseElement, boolean readOnlyMode,
            String xadesPrefix, String xadesNamespace, String xmlSignaturePrefix,
            String digestMethod)
    {
        super(document, baseElement, readOnlyMode, xadesPrefix, xadesNamespace, xmlSignaturePrefix,
                digestMethod);
    }

    @Override
	public void setSignaturePolicyIdentifier(SignaturePolicyIdentifier signaturePolicyIdentifier)
    {
        if (this.readOnlyMode)
        {
            throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
        }

        if (signaturePolicyIdentifier != null)
        {
            this.data.put(XAdES.Element.SIGNATURE_POLICY_IDENTIFIER, signaturePolicyIdentifier);
        }
        else
        {
            this.data.remove(XAdES.Element.SIGNATURE_POLICY_IDENTIFIER);
        }
    }

    @Override
	public SignaturePolicyIdentifier getSignaturePolicyIdentifier()
    {
        return (SignaturePolicyIdentifier) this.data.get(XAdES.Element.SIGNATURE_POLICY_IDENTIFIER);
    }
}

package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/*
 <ds:Signature ID?>
 ...
 <ds:Object>
 <QualifyingProperties>
 ...
 <UnsignedProperties>
 <UnsignedSignatureProperties>
 (SignatureTimeStamp)+
 </UnsignedSignatureProperties>
 </UnsignedProperties>
 </QualifyingProperties>
 </ds:Object>
 </ds:Signature>-
 */

/**
 * 
 * @author miro
 */
public class TimestampXAdESImpl extends ExplicitPolicyXAdESImpl implements XAdES_T
{
    /*
     * public TimeStampXAdES(Element baseElement, boolean useExplicitPolicy) { super(baseElement,
     * useExplicitPolicy); }
     */

    public TimestampXAdESImpl(Document document, Element baseElement, boolean readOnlyMode, String xadesPrefix,
            String xadesNamespace, String xmlSignaturePrefix, String digestMethod)
    {
        super(document, baseElement, readOnlyMode, xadesPrefix, xadesNamespace, xmlSignaturePrefix,
                digestMethod);
    }
    
    @Override
	@SuppressWarnings("unchecked")
    public List<SignatureTimeStamp> getSignatureTimeStamps()
    {
        return (List<SignatureTimeStamp>) this.data.get(XAdES.Element.SIGNATURE_TIME_STAMP);
    }
    
    @Override
	public void setSignatureTimeStamps(final List<SignatureTimeStamp> signatureTimeStamps)
    {
        if (this.readOnlyMode)
        {
            throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
        }

        if (signatureTimeStamps != null && signatureTimeStamps.size() > 0)
        {
            this.data.put(XAdES.Element.SIGNATURE_TIME_STAMP, signatureTimeStamps);
        }
        else
        {
            this.data.remove(XAdES.Element.SIGNATURE_TIME_STAMP);
        }
    }
}

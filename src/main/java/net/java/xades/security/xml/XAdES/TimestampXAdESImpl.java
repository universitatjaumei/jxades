package net.java.xades.security.xml.XAdES;

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
}

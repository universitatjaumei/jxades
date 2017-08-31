package es.uji.crypto.xades.jxades.security.xml.XAdES;

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
                        (CertificatesValues)
                        (RevocationValues)
                        (AttrAuthoritiesCertValues)?
                        (AttributeRevocationValues)?
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
public class ExtendedLongXAdESImpl extends ExtendedXAdESImpl implements XAdES_X_L
{

    /*
     * public ExtendedLongXAdESImpl(Element baseElement, boolean useExplicitPolicy) {
     * super(baseElement, useExplicitPolicy); }
     */

    public ExtendedLongXAdESImpl(Document document, Element baseElement, boolean readOnlyMode, String xadesPrefix,
            String xadesNamespace, String xmlSignaturePrefix, String digestMethod)
    {
        super(document, baseElement, readOnlyMode, xadesPrefix, xadesNamespace, xmlSignaturePrefix, digestMethod);
    }
}

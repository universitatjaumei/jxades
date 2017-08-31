package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

/*
 */

/**
 * 
 * @author miro
 */
public class UnsignedProperties extends XAdESStructure
{
    private UnsignedSignatureProperties unsignedSignatureProperties;
    private Document document;

    public UnsignedProperties(Document document, QualifyingProperties qp, String xadesPrefix, String xadesNamespace,
            String xmlSignaturePrefix)
    {
        super(document, qp, "UnsignedProperties", xadesPrefix, xadesNamespace, xmlSignaturePrefix);
        this.document = document;
    }

    public UnsignedProperties(Node node, String xadesPrefix, String xadesNamespace,
            String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public UnsignedSignatureProperties getUnsignedSignatureProperties()
    {
        if (unsignedSignatureProperties == null)
        {
            unsignedSignatureProperties = new UnsignedSignatureProperties(document, this, xadesPrefix,
                    xadesNamespace, xmlSignaturePrefix);
        }

        return unsignedSignatureProperties;
    }

}

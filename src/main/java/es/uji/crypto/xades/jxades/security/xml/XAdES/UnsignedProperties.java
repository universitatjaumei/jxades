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

    public UnsignedProperties(final Document document, final QualifyingProperties qp, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(document, qp, "UnsignedProperties", xadesPrefix, xadesNamespace, xmlSignaturePrefix);
        this.document = document;
    }

    public UnsignedProperties(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public UnsignedSignatureProperties getUnsignedSignatureProperties()
    {
        if (this.unsignedSignatureProperties == null)
        {
            this.unsignedSignatureProperties = new UnsignedSignatureProperties(this.document, this, this.xadesPrefix,
                    this.xadesNamespace, this.xmlSignaturePrefix);
        }

        return this.unsignedSignatureProperties;
    }

}

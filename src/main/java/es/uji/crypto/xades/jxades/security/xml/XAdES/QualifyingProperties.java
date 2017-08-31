package es.uji.crypto.xades.jxades.security.xml.XAdES;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * 
 * @author miro
 */
public class QualifyingProperties extends XAdESStructure
{
    private String signatureIdPrefix;

    private SignedProperties signedProperties;
    private UnsignedProperties unsignedProperties;

    private Document document;

    public QualifyingProperties(Document document, Node node, String signatureIdPrefix,
            String xadesPrefix, String xadesNamespace, String xmlSignaturePrefix)
    {
        this(document, node, "QualifyingProperties", signatureIdPrefix, xadesPrefix,
                xadesNamespace, xmlSignaturePrefix);
    }

    private QualifyingProperties(Document document, Node node, String elementName,
            String signatureIdPrefix, String xadesPrefix, String xadesNamespace,
            String xmlSignaturePrefix)
    {
        this(document.createElementNS(xadesNamespace, elementName), xadesPrefix, xadesNamespace,
                xmlSignaturePrefix);
        this.document = document;

        this.signatureIdPrefix = signatureIdPrefix;

        Element element = getElement();

        element.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:" + xmlSignaturePrefix,
                XMLSignature.XMLNS);
        element.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:" + xadesPrefix,
                xadesNamespace);
        element.setPrefix(xadesPrefix);

        String target = "#" + signatureIdPrefix + "-" + SIGNATURE_ELEMENT_NAME;
        setAttributeNS(null, TARGET_ATTRIBUTE, target);

        String id = signatureIdPrefix + "-" + elementName;
        setAttributeNS(null, ID_ATTRIBUTE, id);
    }

    public QualifyingProperties(Node node, String xadesPrefix, String xadesNamespace,
            String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public SignedProperties getSignedProperties()
    {
        if (signedProperties == null)
        {
            signedProperties = new SignedProperties(document, this, signatureIdPrefix, xadesPrefix,
                    xadesNamespace, xmlSignaturePrefix);
        }

        return signedProperties;
    }

    public UnsignedProperties getUnsignedProperties()
    {
        // if (unsignedProperties == null)
        // {
        // unsignedProperties = new UnsignedProperties(this, xadesPrefix, xadesNamespace,
        // xmlSignaturePrefix);
        // }

        return unsignedProperties;
    }
}

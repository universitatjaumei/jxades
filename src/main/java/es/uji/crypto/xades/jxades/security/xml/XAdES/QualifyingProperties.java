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
public class QualifyingProperties extends XAdESStructure {

    private String signatureIdPrefix;

    private SignedProperties signedProperties;
    private UnsignedProperties unsignedProperties;

    private Document document;

    public QualifyingProperties(final Document document,
    		                    final Node node,
    		                    final String signatureIdPrefix,
    		                    final String xadesPrefix,
    		                    final String xadesNamespace,
    		                    final String xmlSignaturePrefix) {
        this(
    		document,
    		node,
    		"QualifyingProperties", //$NON-NLS-1$
    		signatureIdPrefix,
    		xadesPrefix,
            xadesNamespace,
            xmlSignaturePrefix
        );
    }

    private QualifyingProperties(final Document document, final Node node, final String elementName,
            final String signatureIdPrefix, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        this(document.createElementNS(xadesNamespace, elementName), xadesPrefix, xadesNamespace,
                xmlSignaturePrefix);
        this.document = document;

        this.signatureIdPrefix = signatureIdPrefix;

        final Element element = getElement();

        element.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:" + xmlSignaturePrefix, //$NON-NLS-1$
                XMLSignature.XMLNS);
        element.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:" + xadesPrefix, //$NON-NLS-1$
                xadesNamespace);
        element.setPrefix(xadesPrefix);

        final String target = "#" + signatureIdPrefix + "-" + SIGNATURE_ELEMENT_NAME; //$NON-NLS-1$ //$NON-NLS-2$
        setAttributeNS(null, TARGET_ATTRIBUTE, target);

        final String id = signatureIdPrefix + "-" + elementName; //$NON-NLS-1$
        setAttributeNS(null, ID_ATTRIBUTE, id);
    }

    public QualifyingProperties(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public SignedProperties getSignedProperties()
    {
        if (this.signedProperties == null)
        {
            this.signedProperties = new SignedProperties(this.document, this, this.signatureIdPrefix, this.xadesPrefix,
                    this.xadesNamespace, this.xmlSignaturePrefix);
        }

        return this.signedProperties;
    }

    public UnsignedProperties getUnsignedProperties()
    {
        // if (unsignedProperties == null)
        // {
        // unsignedProperties = new UnsignedProperties(this, xadesPrefix, xadesNamespace,
        // xmlSignaturePrefix);
        // }

        return this.unsignedProperties;
    }
}

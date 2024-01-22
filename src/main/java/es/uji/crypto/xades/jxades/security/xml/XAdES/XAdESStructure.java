package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.List;

import javax.xml.crypto.dom.DOMStructure;

import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.uji.crypto.xades.jxades.util.XMLUtils;

/**
 *
 * @author miro
 */
public class XAdESStructure extends DOMStructure
{
    public static final String SIGNATURE_ELEMENT_NAME = "Signature"; //$NON-NLS-1$
    public static final String ID_ATTRIBUTE = "Id"; //$NON-NLS-1$
    public static final String TARGET_ATTRIBUTE = "Target"; //$NON-NLS-1$

    private Document baseDocument;

    public String xadesPrefix;
    public String xadesNamespace;
    public String xmlSignaturePrefix;

    public XAdESStructure(final Document document, final XAdESStructure parent, final String elementName,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
    {
        this(document, parent.getElement(), elementName, xadesPrefix, xadesNamespace,
                xmlSignaturePrefix);
    }

    public XAdESStructure(final Document document, final Element parentElement, final String elementName,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
    {
        this(document.createElementNS(xadesNamespace, elementName), xadesPrefix, xadesNamespace,
                xmlSignaturePrefix);
        this.baseDocument = document;

        this.xadesPrefix = xadesPrefix;
        this.xadesNamespace = xadesNamespace;
        this.xmlSignaturePrefix = xmlSignaturePrefix;

        final Element element = getElement();
        element.setPrefix(xadesPrefix);

        parentElement.appendChild(element);
    }

    public XAdESStructure(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node);

        this.xadesPrefix = xadesPrefix;
        this.xadesNamespace = xadesNamespace;
        this.xmlSignaturePrefix = xmlSignaturePrefix;
    }

    public Element getElement()
    {
        return (Element) getNode();
    }

    public String getId()
    {
        return getAttribute(ID_ATTRIBUTE);
    }

    protected void setAttributeNS(final String namespaceURI, final String qualifiedName, final String value)
            throws DOMException
    {
        getElement().setAttributeNS(namespaceURI, qualifiedName, value);

        if ("Id".equals(qualifiedName)) //$NON-NLS-1$
        {
            getElement().setIdAttributeNS(null, "Id", true); //$NON-NLS-1$
        }
    }

    protected String getAttribute(final String name)
    {
        return getElement().getAttribute(name);
    }

    protected String getAttributeNS(final String namespaceURI, final String qualifiedName)
    {
        return getElement().getAttributeNS(namespaceURI, qualifiedName);
    }

    protected String getTextContent()
    {
        return getElement().getTextContent();
    }

    protected void setTextContent(final String textContent)
    {
        getElement().setTextContent(textContent);
    }

    protected Element getChildElement(final String elementName)
    {
        return XMLUtils.getChildElementByTagName(getElement(), elementName);
    }

    protected Element getChildElementNS(final String elementName)
    {
        return XMLUtils.getChildElementByTagNameNS(getElement(), elementName, this.xadesNamespace);
    }

    protected Element getChildElementNS(final String elementName, final String namespace)
    {
        return XMLUtils.getChildElementByTagNameNS(getElement(), elementName, namespace);
    }

    protected List<Element> getChildElements(final String elementName)
    {
        return XMLUtils.getChildElementsByTagName(getElement(), elementName);
    }

    protected List<Element> getChildElementsNS(final String elementName)
    {
        return XMLUtils.getChildElementsByTagNameNS(getElement(), elementName, this.xadesNamespace);
    }

    protected Document getDocument()
    {
        return this.baseDocument;
    }

    protected Element createElement(final String elementName)
    {
        final Element element = getDocument().createElementNS(this.xadesNamespace, elementName);
        element.setPrefix(this.xadesPrefix);

        return element;
    }

    protected Element createElementNS(final String namespace, final String prefix, final String elementName)
    {
        final Element element = getDocument().createElementNS(namespace, elementName);
        element.setPrefix(prefix);

        return element;
    }

    protected String getChildElementTextContent(final String elementName)
    {
        final Element element = getChildElementNS(elementName);

        if (element != null)
        {
            return element.getTextContent();
        }

        return null;
    }

}

package es.uji.crypto.xades.jxades.util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.w3c.dom.CDATASection;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

/**
 * Common XML Tasks
 *
 * @author Miroslav Nachev
 */
public final class XMLUtils {

	public static final String SHA224 = "http://www.w3.org/2001/04/xmldsig-more#sha224"; //$NON-NLS-1$
	public static final String SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"; //$NON-NLS-1$

	/** The <a href="http://www.w3.org/2001/04/xmldsig-more#rsa-sha224">
     * RSA-SHA224</a> (PKCS #1) signature method algorithm URI. */
    public static final String RSA_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"; //$NON-NLS-1$

	/** The <a href="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256">
     * RSA-SHA256</a> (PKCS #1) signature method algorithm URI. */
    public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"; //$NON-NLS-1$

    /** The <a href="http://www.w3.org/2001/04/xmldsig-more#rsa-sha384">
     * RSA-SHA384</a> (PKCS #1) signature method algorithm URI. */
    public static final String RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"; //$NON-NLS-1$

    private static Charset charset = StandardCharsets.UTF_8;

    /**
     * Get the attribute with given name's value
     *
     * @param node
     *            the node which attribute's value is returned
     * @param name
     *            name of the attribute
     * @return the value af the attribute
     */
    public static String getAttributeByName(final Node node, final String name)
    {
        if (node == null)
        {
            return null;
        }

        final Node attribute = node.getAttributes().getNamedItem(name);
        if (attribute == null)
        {
            return null;
        }
		return attribute.getNodeValue().trim();
    }

    /**
     * Get the data of the element , no matter whether it is TXT ot CDATA
     *
     * @param parentNode
     *            the node which data is returned
     * @return the TEXT or CDATA of the parentNode
     */
    public static String getElementTextValueDeprecated(final Element parentNode)
    {
        final Text text = getElementTextNode(parentNode);
        if (text != null)
        {
            return text.getData();
        }
		return null;
    }

    /**
     * Sets element TEXT data
     *
     * @param e
     *            the element
     * @param data
     *            the new data
     */
    public static void setElementTextValue(final Element e, final String data)
    {
        Text txt = getElementTextNode(e);
        if (txt != null)
        {
            txt.setData(data);
        }
        else
        {
            txt = e.getOwnerDocument().createTextNode(data);
            e.appendChild(txt);
        }
    }

    /**
     * Sets element CDATA data
     *
     * @param e
     *            the lement
     * @param data
     *            the new data
     */
    public static void setElementCDataValue(final Element e, final String data)
    {
        CDATASection txt = getElementCDataNode(e);
        if (txt != null)
        {
            txt.setData(data);
        }
        else
        {
            txt = e.getOwnerDocument().createCDATASection(data);
            e.appendChild(txt);
        }
    }

    /**
     * Gets CDATA value of an element
     *
     * @param e
     *            the element
     * @return CDATA value of element e
     */
    public static String getElementCDataValue(final Element e)
    {
        final CDATASection text = getElementCDataNode(e);
        if (text != null)
        {
            return text.getData().trim();
        }
		return null;
    }

    /**
     * Returns element's CDATA Node
     *
     * @param element
     *            the element which CDATA node is returned
     * @return CDATA node
     */
    public static CDATASection getElementCDataNode(final Element element)
    {
        return (CDATASection) getChildNodeByType(element, Node.CDATA_SECTION_NODE);
    }

    /**
     * Returns element's TEXT Node
     *
     * @param element
     *            the element which TEXT node is returned
     * @return TEXT node
     */
    public static Text getElementTextNode(final Element element)
    {
        return (Text) getChildNodeByType(element, Node.TEXT_NODE);
    }

    private static Node getChildNodeByType(final Element element, final short nodeType)
    {
        if (element == null)
        {
            return null;
        }

        final NodeList nodes = element.getChildNodes();
        if (nodes == null || nodes.getLength() < 1)
        {
            return null;
        }

        Node node;
        String data;
        for (int i = 0; i < nodes.getLength(); i++)
        {
            node = nodes.item(i);
            final short type = node.getNodeType();
            if (type == nodeType)
            {
                if (type == Node.TEXT_NODE || type == Node.CDATA_SECTION_NODE)
                {
                    data = ((Text) node).getData();
                    if (data == null || data.trim().length() < 1)
                    {
                        continue;
                    }
                }

                return node;
            }
        }

        return null;
    }

    public static void writeXML(final File file, final Node node) throws FileNotFoundException
    {
        writeXML(new FileOutputStream(file), node);
    }

    public static void writeXML(final OutputStream outStream, final Node node)
    {
        writeXML(new BufferedWriter(new OutputStreamWriter(outStream, charset)), node, true);
    }

    public static void writeXML(final OutputStream outStream, final Node node, final boolean indent)
    {
        writeXML(new BufferedWriter(new OutputStreamWriter(outStream, charset)), node, indent);
    }

    /**
     * Writes the specified document to the given file. The default encoding is UTF-8.
     *
     * @param out
     *            the output File
     * @param document
     *            the document to be writen
     */
    public static void writeXML(final Writer writer, final Node node, final boolean indent)
    {
        // TODO: This section only works with XALAN transformation!!!
        // Result with JDK transformation:
        // <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"
        // xmlns:ns0="http://uri.etsi.org/01903/v1.3.2#"
        // ns0:Id="S0-QualifyingProperties"
        // xmlns:ns1="http://uri.etsi.org/01903/v1.3.2#"
        // ns1:Target="#S0-Signature">
        //
        // DOMSource domSource = new DOMSource(node);
        // StreamResult streamResult = new StreamResult(writer);
        // TransformerFactoryImpl tf = new TransformerFactoryImpl();
        // Transformer serializer = tf.newTransformer();
        // serializer.setOutputProperty(OutputKeys.ENCODING, charset.name());
        //
        // if (indent)
        // {
        // serializer.setOutputProperty(OutputKeys.INDENT, "yes");
        // }
        //
        // serializer.transform(domSource, streamResult);

        Document document = null;

        if (node instanceof Element)
        {
            document = node.getOwnerDocument();
        }
        else if (node instanceof Document)
        {
            document = (Document) node;
        }

        final DOMImplementationLS domImplLS = (DOMImplementationLS) document.getImplementation();
        final LSSerializer serializer = domImplLS.createLSSerializer();
        serializer.getDomConfig().setParameter("namespaces", false); //$NON-NLS-1$

        final DOMOutputImpl output = new DOMOutputImpl();
        output.setCharacterStream(writer);

        serializer.write(node, output);
    }

    public static void writeXML(final Writer writer, final Document document, final String doctypeSystem,
            final String doctypePublic)
    {
        final DOMImplementationLS domImplLS = (DOMImplementationLS) document.getImplementation();
        final LSSerializer serializer = domImplLS.createLSSerializer();

        final DOMOutputImpl output = new DOMOutputImpl();
        output.setCharacterStream(writer);

        serializer.write(document.getDocumentElement(), output);
    }

    /**
     * Returns the element which is at the end of the specified chain <parent><child><grandchild>...
     *
     * @param element
     * @param chain
     * @return
     */
    public static Element getChildElementByChain(final Element element, final String[] chain, final boolean create)
    {
        if (chain == null)
        {
            return null;
        }
        Element e = element;
        for (final String element2 : chain) {
            if (e == null)
            {
                return null;
            }
            e = getChildElementByTagName(e, element2);
        }
        return e;
    }

    /**
     * Creates (only if necessary) and returns the element which is at the end of the specified
     * path.
     *
     * @param doc
     *            the target document where the specified path should be created
     * @param path
     *            a dot separated string indicating the path to be created
     * @return the component at the end of the newly created path.
     */
    public static Element createLastPathComponent(final Document doc, final String[] path)
    {
        if (path == null || doc == null) {
            throw new IllegalArgumentException("Document and path must not be null"); //$NON-NLS-1$
        }
        final Element parent = (Element) doc.getFirstChild();
        if (parent == null) {
            throw new IllegalArgumentException("Document parent must not be null"); //$NON-NLS-1$
        }

        Element e = parent;
        for (final String element : path) {
            Element newEl = getChildElementByTagName(e, element);
            if (newEl == null) {
                newEl = doc.createElement(element);
                e.appendChild(newEl);
            }
            e = newEl;
        }
        return e;
    }

    public static Element getChildElementByTagNameNS(final Element parent, final String tagName, final String nsName) {
        final NodeList nl = parent.getChildNodes();
        final int size = nl.getLength();
        for (int i = 0; i < size; i++) {
            final Node node = nl.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE && tagName.equals(node.getLocalName()))
			{
			    final String ns = node.getNamespaceURI();
			    if (ns != null && ns.equals(nsName))
			    {
			        return (Element) node;
			    }
			}
        }

        return null;
    }

    /**
     * Returns the child element with the specified tagName for the specified parent element
     *
     * @param parent
     * @param tagName
     * @return
     */
    public static Element getChildElementByTagName(final Element parent, final String tagName)
    {
        if (parent == null || tagName == null)
        {
            return null;
        }

        final NodeList nodes = parent.getChildNodes();
        Node node;
        final int len = nodes.getLength();
        for (int i = 0; i < len; i++)
        {
            node = nodes.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE
                    && ((Element) node).getNodeName().equals(tagName))
            {
                return (Element) node;
            }
        }

        return null;
    }

    public static List<Element> getChildElementsByTagNameNS(final Element parent, final String tagName,
            final String nsName)
    {
        if (parent == null || tagName == null) {
			return Collections.<Element> emptyList();
		}

        final NodeList nl = parent.getChildNodes();
        final int size = nl.getLength();
        final ArrayList<Element> childElements = new ArrayList<>(size);
        for (int i = 0; i < size; i++)
        {
            final Node node = nl.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE && tagName.equals(node.getLocalName()))
			{
			    final String ns = node.getNamespaceURI();
			    if (ns != null && ns.equals(nsName))
			    {
			        childElements.add((Element) node);
			    }
			}
        }

        return childElements;
    }

    public static List<Element> getChildElementsByTagName(final Element parent, final String tagName)
    {
        if (parent == null || tagName == null) {
			return Collections.<Element> emptyList();
		}

        final NodeList nodes = parent.getChildNodes();
        Node node;
        final int len = nodes.getLength();
        final ArrayList<Element> childElements = new ArrayList<>(len);
        for (int i = 0; i < len; i++)
        {
            node = nodes.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE
                    && ((Element) node).getNodeName().equals(tagName))
            {
                childElements.add((Element) node);
            }
        }

        return childElements;
    }

    /**
     * Used for debuging
     *
     * @param parent
     *            Element
     * @param out
     *            PrintStream
     * @param deep
     *            boolean
     * @param prefix
     *            String
     */
    public static void printChildElements(final Element parent, final PrintStream out, final boolean deep,
            final String prefix)
    {
        out.print(prefix + "<" + parent.getNodeName()); //$NON-NLS-1$
        final NamedNodeMap attrs = parent.getAttributes();
        Node node;
        for (int i = 0; i < attrs.getLength(); i++)
        {
            node = attrs.item(i);
            out.print(" " + node.getNodeName() + "=\"" + node.getNodeValue() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        }
        out.println(">"); //$NON-NLS-1$

        // String data = getElementTextValueDeprecated(parent);
        String data = parent.getNodeValue();
        if (data != null && data.trim().length() > 0)
        {
            out.println(prefix + "\t" + data); //$NON-NLS-1$
        }

        data = getElementCDataValue(parent);
        if (data != null && data.trim().length() > 0)
        {
            out.println(prefix + "\t<![CDATA[" + data + "]]>"); //$NON-NLS-1$ //$NON-NLS-2$
        }

        final NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++)
        {
            node = nodes.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE)
            {
                if (deep)
                {
                    printChildElements((Element) node, out, deep, prefix + "\t"); //$NON-NLS-1$
                }
                else
                {
                    out.println(prefix + node.getNodeName());
                }
            }
        }

        out.println(prefix + "</" + parent.getNodeName() + ">"); //$NON-NLS-1$ //$NON-NLS-2$
    }

}

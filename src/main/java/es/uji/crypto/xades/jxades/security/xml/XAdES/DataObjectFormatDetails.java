package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/*
 * <p:DataObjectFormat ObjectReference="http://tempuri.org">
 *   <p:Description>p:Description</p:Description>
 *   <p:ObjectIdentifier>
 *     <p:Identifier Qualifier="OIDAsURI">http://tempuri.org</p:Identifier>
 *     <p:Description>p:Description</p:Description>
 *     <p:DocumentationReferences>
 *       <p:DocumentationReference>http://tempuri.org</p:DocumentationReference>
 *     </p:DocumentationReferences>
 *   </p:ObjectIdentifier>
 *   <p:MimeType>p:MimeType</p:MimeType>
 *   <p:Encoding>http://tempuri.org</p:Encoding>
 * </p:DataObjectFormat>
 *
 */

public class DataObjectFormatDetails extends XAdESStructure
{
    public DataObjectFormatDetails(final Document document,
            final SignedDataObjectProperties signedDataObjectProperties,
            final DataObjectFormat dataObjectFormat, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(document, signedDataObjectProperties, "DataObjectFormat", xadesPrefix, //$NON-NLS-1$
                xadesNamespace, xmlSignaturePrefix);

        final Element description = createElement("Description"); //$NON-NLS-1$
        description.setPrefix(xadesPrefix);
        description.setTextContent(dataObjectFormat.getDescription());

        getNode().appendChild(description);

        final ObjectIdentifier objectIdentifier = dataObjectFormat.getObjectIdentifier();

        if (objectIdentifier != null)
        {
            new ObjectIdentifierDetails(document, this, objectIdentifier, xadesPrefix,
                    xadesNamespace, xmlSignaturePrefix);
        }

        final Element mimetype = createElement("MimeType"); //$NON-NLS-1$
        mimetype.setPrefix(xadesPrefix);
        mimetype.setTextContent(dataObjectFormat.getMimeType());

        getNode().appendChild(mimetype);

        final Element encoding = createElement("Encoding"); //$NON-NLS-1$
        encoding.setPrefix(xadesPrefix);
        encoding.setTextContent(dataObjectFormat.getEncoding());

        getNode().appendChild(encoding);

        // TODO: must ensure that there is an ObjectReference attribute, otherwise an Exception
        // should be raised
        setAttributeNS(xadesNamespace, "ObjectReference", dataObjectFormat.getObjectReference()); //$NON-NLS-1$
    }
}

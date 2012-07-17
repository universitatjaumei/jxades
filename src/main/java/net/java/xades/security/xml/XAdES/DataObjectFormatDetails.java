package net.java.xades.security.xml.XAdES;

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
    public DataObjectFormatDetails(SignedDataObjectProperties signedDataObjectProperties,
            DataObjectFormat dataObjectFormat, String xadesPrefix, String xadesNamespace,
            String xmlSignaturePrefix)
    {
        super(signedDataObjectProperties, "DataObjectFormat", xadesPrefix, xadesNamespace,
                xmlSignaturePrefix);

        Element description = createElement("Description");
        description.setPrefix(xadesPrefix);
        description.setTextContent(dataObjectFormat.getDescription());

        getNode().appendChild(description);
        
        ObjectIdentifier objectIdentifier = dataObjectFormat.getObjectIdentifier();

        if (objectIdentifier != null)
        {
            new ObjectIdentifierDetails(this, objectIdentifier, xadesPrefix, xadesNamespace,
                    xmlSignaturePrefix);
        }

        Element mimetype = createElement("MimeType");
        mimetype.setPrefix(xadesPrefix);
        mimetype.setTextContent(dataObjectFormat.getMimeType());

        getNode().appendChild(mimetype);
        
        Element encoding = createElement("Encoding");
        encoding.setPrefix(xadesPrefix);
        encoding.setTextContent(dataObjectFormat.getEncoding());
        
        getNode().appendChild(encoding);
        
        // TODO: must ensure that there is an ObjectReference attribute, otherwise an Exception
        // should be raised
        setAttributeNS(xadesNamespace, "ObjectReference", dataObjectFormat.getObjectReference());
    }
}

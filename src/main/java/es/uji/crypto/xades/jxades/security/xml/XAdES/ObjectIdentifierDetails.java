package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/*
 * <p:ObjectIdentifier>
 *   <p:Identifier Qualifier="OIDAsURI">http://tempuri.org</p:Identifier>
 *   <p:Description>p:Description</p:Description>
 *   <p:DocumentationReferences>
 *     <p:DocumentationReference>http://tempuri.org</p:DocumentationReference>
 *   </p:DocumentationReferences>
 * </p:ObjectIdentifier>
 *
 */

public class ObjectIdentifierDetails extends XAdESStructure
{
    public ObjectIdentifierDetails(final Document document,
            final DataObjectFormatDetails dataObjectFormatDetails, final ObjectIdentifier objectIdentifier,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(document, dataObjectFormatDetails, "ObjectIdentifier", xadesPrefix, xadesNamespace, //$NON-NLS-1$
                xmlSignaturePrefix);

        final Element identifier = createElement("Identifier"); //$NON-NLS-1$
        identifier.setTextContent(objectIdentifier.getIdentifier());
        identifier.setAttributeNS(xadesNamespace, "Qualifier", objectIdentifier.getQualifier()); //$NON-NLS-1$
        getNode().appendChild(identifier);

        final Element description = createElement("Description"); //$NON-NLS-1$
        description.setTextContent(objectIdentifier.getDescription());
        getNode().appendChild(description);

        if (objectIdentifier.getDocumentationReferences().size() > 0)
        {
            final Element documentationReferences = createElement("DocumentationReferences"); //$NON-NLS-1$

            for (final String reference : objectIdentifier.getDocumentationReferences())
            {
                final Element documentationReference = createElement("DocumentationReference"); //$NON-NLS-1$
                documentationReference.setTextContent(reference);
                documentationReferences.appendChild(documentationReference);
            }

            getNode().appendChild(documentationReferences);
        }
    }
}

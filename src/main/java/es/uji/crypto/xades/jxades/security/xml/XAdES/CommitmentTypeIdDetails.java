package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/*
 *
 * <p:CommitmentTypeId>
 *   <p:Identifier Qualifier="OIDAsURI">http://tempuri.org</p:Identifier>
 *   <p:Description>p:Description</p:Description>
 *   <p:DocumentationReferences>
 *     <p:DocumentationReference>http://tempuri.org</p:DocumentationReference>
 *   </p:DocumentationReferences>
 *  </p:CommitmentTypeId>
 *
 */

public class CommitmentTypeIdDetails extends XAdESStructure
{
    public CommitmentTypeIdDetails(final Document document,
                                   final CommitmentTypeIndicationDetails commitmentTypeIndicationDetails,
                                   final CommitmentTypeId commitmentTypeId,
                                   final String xadesPrefix,
                                   final String xadesNamespace,
                                   final String xmlSignaturePrefix) {
        super(
    		document,
    		commitmentTypeIndicationDetails,
    		"CommitmentTypeId", //$NON-NLS-1$
    		xadesPrefix,
            xadesNamespace,
            xmlSignaturePrefix
        );

        final Element identifier = createElement("Identifier"); //$NON-NLS-1$
        identifier.setTextContent(commitmentTypeId.getIdentifier());
        if (commitmentTypeId.getQualifier() != null) {
        	identifier.setAttributeNS(xadesNamespace, "Qualifier", commitmentTypeId.getQualifier()); //$NON-NLS-1$
        }
        getNode().appendChild(identifier);

        final Element description = createElement("Description"); //$NON-NLS-1$
        description.setTextContent(commitmentTypeId.getDescription());
        getNode().appendChild(description);

        if (commitmentTypeId.getDocumentationReferences().size() > 0)
        {
            final Element documentationReferences = createElement("DocumentationReferences"); //$NON-NLS-1$

            for (final String reference : commitmentTypeId.getDocumentationReferences())
            {
                final Element documentationReference = createElement("DocumentationReference"); //$NON-NLS-1$
                documentationReference.setTextContent(reference);
                documentationReferences.appendChild(documentationReference);
            }

            getNode().appendChild(documentationReferences);
        }
    }
}
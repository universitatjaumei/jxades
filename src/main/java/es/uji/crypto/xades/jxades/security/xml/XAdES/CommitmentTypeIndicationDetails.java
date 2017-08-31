package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/*
 * <p:CommitmentTypeIndication>
 *   <p:CommitmentTypeId>
 *      <p:Identifier Qualifier="OIDAsURI">http://tempuri.org</p:Identifier>
 *      <p:Description>p:Description</p:Description>
 *      <p:DocumentationReferences>
 *        <p:DocumentationReference>http://tempuri.org</p:DocumentationReference>
 *      </p:DocumentationReferences>
 *   </p:CommitmentTypeId>
 *   <p:ObjectReference>http://tempuri.org</p:ObjectReference>
 *   <p:CommitmentTypeQualifiers>
 *     <p:CommitmentTypeQualifier>ANYTYPE</p:CommitmentTypeQualifier>
 *   </p:CommitmentTypeQualifiers>
 * </p:CommitmentTypeIndication>
 *
 */

public class CommitmentTypeIndicationDetails extends XAdESStructure
{
    public CommitmentTypeIndicationDetails(final Document document,
            final SignedDataObjectProperties signedDataObjectProperties,
            final CommitmentTypeIndication commitmentTypeIndication, final String xadesPrefix,
            final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(document, signedDataObjectProperties, "CommitmentTypeIndication", xadesPrefix,
                xadesNamespace, xmlSignaturePrefix);

        final CommitmentTypeId commitmentTypeId = commitmentTypeIndication.getCommitmentTypeId();

        if (commitmentTypeId != null)
        {
            new CommitmentTypeIdDetails(document, this, commitmentTypeId, xadesPrefix,
                    xadesNamespace, xmlSignaturePrefix);
        }

        final Element objectReference;
        if (commitmentTypeIndication.getObjectReference() != null) {
        	objectReference = createElement("ObjectReference");
        	objectReference.setTextContent(commitmentTypeIndication.getObjectReference());
        }
        else {
        	objectReference = createElement("AllSignedDataObjects");
        }

        final Element commitmentTypeQualifiers = createElement("CommitmentTypeQualifiers");

        for (final String qualifier : commitmentTypeIndication.getCommitmentTypeQualifiers()) {
            final Element commitmentTypeQualifier = createElement("CommitmentTypeQualifier");
            commitmentTypeQualifier.setTextContent(qualifier);
            commitmentTypeQualifiers.appendChild(commitmentTypeQualifier);
        }

    	getNode().appendChild(objectReference);

        getNode().appendChild(commitmentTypeQualifiers);
    }
}

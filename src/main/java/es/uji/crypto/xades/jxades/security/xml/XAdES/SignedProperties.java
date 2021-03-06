package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

/*
 * 
 * <SignedProperties>
 *   <SignedSignatureProperties>
 *     (SigningTime)?
 *     (SigningCertificate)?
 *     (SigningCertificateV2)?
 *     (SignatureProductionPlace)?
 *     (SignerRole)?
 *     (SignerRoleV2)?
 *   </SignedSignatureProperties>
 *   <SignedDataObjectProperties>
 *     (DataObjectFormat)*
 *     (CommitmentTypeIndication)*
 *     (AllDataObjectsTimeStamp)*
 *     (IndividualDataObjectsTimeStamp)*
 *   </SignedDataObjectProperties>
 *   </SignedProperties>
 *   
 */

/**
 * 
 * @author miro
 */
public class SignedProperties extends XAdESStructure
{
    private SignedSignatureProperties signedSignatureProperties;
    private SignedDataObjectProperties signedDataObjectProperties;
    private Document document;

    public SignedProperties(Document document, QualifyingProperties qp, String signatureIdPrefix, String xadesPrefix,
            String xadesNamespace, String xmlSignaturePrefix)
    {
        super(document, qp, "SignedProperties", xadesPrefix, xadesNamespace, xmlSignaturePrefix);
        this.document = document;

        setAttributeNS(null, ID_ATTRIBUTE, signatureIdPrefix + "-SignedProperties");
    }

    public SignedProperties(Node node, String xadesPrefix, String xadesNamespace,
            String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public SignedSignatureProperties getSignedSignatureProperties()
    {
        if (this.signedSignatureProperties == null)
        {
            this.signedSignatureProperties = new SignedSignatureProperties(this.document, this, this.xadesPrefix,
                    this.xadesNamespace, this.xmlSignaturePrefix);
        }

        return this.signedSignatureProperties;
    }

    public SignedDataObjectProperties getSignedDataObjectProperties()
    {
        if (this.signedDataObjectProperties == null)
        {
            this.signedDataObjectProperties = new SignedDataObjectProperties(this.document, this, this.xadesPrefix,
                    this.xadesNamespace, this.xmlSignaturePrefix);
        }

        return this.signedDataObjectProperties;
    }
}

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

    public SignedProperties(final Document document, final QualifyingProperties qp, final String signatureIdPrefix, final String xadesPrefix,
            final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(document, qp, "SignedProperties", xadesPrefix, xadesNamespace, xmlSignaturePrefix); //$NON-NLS-1$
        this.document = document;

        setAttributeNS(null, ID_ATTRIBUTE, signatureIdPrefix + "-SignedProperties"); //$NON-NLS-1$
    }

    public SignedProperties(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
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
        if (this.signedDataObjectProperties == null) {
            this.signedDataObjectProperties = new SignedDataObjectProperties(
        		this.document,
        		this,
        		this.xadesPrefix,
                this.xadesNamespace,
                this.xmlSignaturePrefix
            );
        }

        return this.signedDataObjectProperties;
    }
}

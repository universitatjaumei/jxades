package es.uji.crypto.xades.jxades.security.xml.XAdES;

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 *
 *
 * The correct Structure here is:
 *
 * <xades:SignaturePolicyIdentifier> <xades:SignaturePolicyId> <xades:SigPolicyId>
 * <xades:SigPolicyQualifiers> <xades:SigPolicyQualifier> </xades:SigPolicyQualifier>
 * </xades:SigPolicyQualifiers> <xades:Identifier> </xades:Identifier> <xades:Description>
 * </xades:Description> </xades:SigPolicyId> <xades:SigPolicyHash> <dsign:DigestMethod
 * Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" /> <dsign:DigestValue> </dsign:DigestValue>
 * </xades:SigPolicyHash> </xades:SignaturePolicyId> </xades:SignaturePolicyIdentifier>
 *
 *
 */

public class SignaturePolicyIdentifierDetails extends XAdESStructure
{
    public SignaturePolicyIdentifierDetails(final Document document,
            final SignedSignatureProperties signedSignatureProperties,
            final SignaturePolicyIdentifier signaturePolicyIdentifier, final String xadesPrefix,
            final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(document, signedSignatureProperties,
                "SignaturePolicyIdentifier", xadesPrefix, xadesNamespace, //$NON-NLS-1$
                xmlSignaturePrefix);

        // TODO: check if when the policy is implied other attributes are not mandatory.
        if (signaturePolicyIdentifier.isImplied())
        {
            final Element implied = createElement("SignaturePolicyImplied"); //$NON-NLS-1$
            getNode().appendChild(implied);
        }
        else
        {
            final Element signaturePolicyId = createElement("SignaturePolicyId"); //$NON-NLS-1$

            final Element identifier = createElement("Identifier"); //$NON-NLS-1$
            identifier.appendChild(getDocument().createTextNode(
                    signaturePolicyIdentifier.getIdentifier()));

            final Element description = createElement("Description"); //$NON-NLS-1$
            description.appendChild(getDocument().createTextNode(
                    signaturePolicyIdentifier.getDescription()));

            final Element sigPolicyId = createElement("SigPolicyId"); //$NON-NLS-1$
            sigPolicyId.appendChild(identifier);
            sigPolicyId.appendChild(description);
            signaturePolicyId.appendChild(sigPolicyId);

            final Element digestMethod = createElementNS(XMLSignature.XMLNS, xmlSignaturePrefix,
                    "DigestMethod"); //$NON-NLS-1$
            digestMethod.setAttributeNS(null,
                    "Algorithm", signaturePolicyIdentifier.getHashAlgorithm()); //$NON-NLS-1$

            final Element digestValue = createElementNS(XMLSignature.XMLNS, xmlSignaturePrefix,
                    "DigestValue"); //$NON-NLS-1$
            digestValue.setTextContent(signaturePolicyIdentifier.getHashBase64());

            final Element sigPolicyHash = createElement("SigPolicyHash"); //$NON-NLS-1$
            sigPolicyHash.appendChild(digestMethod);
            sigPolicyHash.appendChild(digestValue);
            signaturePolicyId.appendChild(sigPolicyHash);

            if (signaturePolicyIdentifier.getQualifier() != null)
            {
                final Element spURI = createElement("SPURI"); //$NON-NLS-1$
                spURI.setTextContent(signaturePolicyIdentifier.getQualifier());

                final Element sigPolicyQualifier = createElement("SigPolicyQualifier"); //$NON-NLS-1$
                sigPolicyQualifier.appendChild(spURI);

                final Element sigPolicyQualifiers = createElement("SigPolicyQualifiers"); //$NON-NLS-1$
                sigPolicyQualifiers.appendChild(sigPolicyQualifier);
                signaturePolicyId.appendChild(sigPolicyQualifiers);
                // getNode().appendChild(sigPolicyQualifiers);

            }

            getNode().appendChild(signaturePolicyId);
            // getNode().appendChild(sigPolicyHash);

        }
    }
}

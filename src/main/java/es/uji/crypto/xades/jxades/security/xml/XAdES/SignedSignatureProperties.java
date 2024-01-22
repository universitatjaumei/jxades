package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.security.GeneralSecurityException;
import java.util.Date;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/*
 <SignedSignatureProperties>
 (SigningTime)?
 (SigningCertificate)?
 (SigningCertificateV2)?
 (SignaturePolicyIdentifier)?
 (SignatureProductionPlace)?
 (SignatureProductionPlaceV2)?
 (SignerRole)?
 (SignerRoleV2)?
 </SignedSignatureProperties>
 */

/**
 *
 * @author miro
 */
public class SignedSignatureProperties extends XAdESStructure
{
    private Document document;

    public SignedSignatureProperties(final Document document,
    		                         final SignedProperties sp,
    		                         final String xadesPrefix,
    		                         final String xadesNamespace,
    		                         final String xmlSignaturePrefix) {
        super(document, sp, "SignedSignatureProperties", xadesPrefix, xadesNamespace, xmlSignaturePrefix); //$NON-NLS-1$
        this.document = document;
    }

    public SignedSignatureProperties(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public void setSigningTime()
    {
        setSigningTime(new Date());
    }

    public void setSigningTime(final Date signingTime)
    {
        new SigningTime(this.document, this, signingTime, this.xadesPrefix, this.xadesNamespace, this.xmlSignaturePrefix);
    }

    public void setSigner(final Signer signer)
    {
        new SignerDetails(this.document, this, signer, this.xadesPrefix, this.xadesNamespace, this.xmlSignaturePrefix);
    }

    public void setSigningCertificate(final SigningCertificate signingCertificate)
            throws GeneralSecurityException
    {
        if (signingCertificate != null)
        {
            new SigningCertificateDetails(this.document, this, signingCertificate, this.xadesPrefix, this.xadesNamespace,
                    this.xmlSignaturePrefix);
        }
    }

    public void setSigningCertificateV2(final SigningCertificateV2 signingCertificateV2) throws GeneralSecurityException {
        if (signingCertificateV2 != null) {
            new SigningCertificateV2Details(
        		this.document,
        		this,
        		signingCertificateV2,
        		this.xadesPrefix,
        		this.xadesNamespace,
                this.xmlSignaturePrefix
            );
        }
    }

    public void setSignerRole(final SignerRole signerRole)
    {
        if (signerRole != null && (signerRole.getClaimedRole().size() > 0 || signerRole.getCertifiedRole().size() > 0))
		{
		    new SignerRoleDetails(this.document, this, signerRole, this.xadesPrefix, this.xadesNamespace,
		            this.xmlSignaturePrefix);
		}
    }

    public void setSignerRoleV2(final SignerRoleV2 signerRole)
    {
        if (signerRole != null && (signerRole.getClaimedRoles().size() > 0 || signerRole.getCertifiedRolesV2().size() > 0
				 || signerRole.getSignedAssertions().size() > 0))
		{
		    new SignerRoleV2Details(this.document, this, signerRole, this.xadesPrefix,
		    		this.xadesNamespace, this.xmlSignaturePrefix);
		}
    }

    public Signer getSigner()
    {
        final SignerDetails details = getSignerDetails();
        if (details != null)
        {
            return details.getSigner();
        }

        return null;
    }

    protected SignerDetails getSignerDetails()
    {
        final Element element = getChildElementNS("SignerDetails");
        if (element != null) {
			return new SignerDetails(element, this.xadesPrefix, this.xadesNamespace, this.xmlSignaturePrefix);
		}
		return null;
    }

    public void setSignatureProductionPlace(final SignatureProductionPlace signatureProductionPlace)
    {
        if (signatureProductionPlace != null)
        {
            new SignatureProductionPlaceDetails(this.document, this, signatureProductionPlace, this.xadesPrefix,
                    this.xadesNamespace, this.xmlSignaturePrefix);
        }
    }

    public void setSignatureProductionPlaceV2(final SignatureProductionPlaceV2 signatureProductionPlace)
    {
        if (signatureProductionPlace != null)
        {
            new SignatureProductionPlaceV2Details(this.document, this, signatureProductionPlace, this.xadesPrefix,
                    this.xadesNamespace, this.xmlSignaturePrefix);
        }
    }

    public void setSignaturePolicyIdentifier(final SignaturePolicyIdentifier signaturePolicyIdentifier)
    {
        if (signaturePolicyIdentifier != null)
        {
            new SignaturePolicyIdentifierDetails(this.document, this, signaturePolicyIdentifier, this.xadesPrefix,
                    this.xadesNamespace, this.xmlSignaturePrefix);
        }
    }
}

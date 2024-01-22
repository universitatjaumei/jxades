package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 *
 * <p:SignerRole>
 * <p:ClaimedRoles>
 * <p:ClaimedRole>
 * ANYTYPE
 * </p:ClaimedRole>
 * </p:ClaimedRoles>
 * <p:CertifiedRoles>
 * <p:CertifiedRole Encoding="http://tempuri.org" Id="id">
 * 0
 * </p:CertifiedRole>
 * </p:CertifiedRoles> </p:SignerRole>
 *
 */

public class SignerRoleDetails extends XAdESStructure
{
    public SignerRoleDetails(final Document document, final SignedSignatureProperties ssp, final SignerRole signerRole,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(document, ssp, "SignerRole", xadesPrefix, xadesNamespace, xmlSignaturePrefix); //$NON-NLS-1$

        final Element claimedRoles = createElement("ClaimedRoles"); //$NON-NLS-1$
        final Element certifiedRoles = createElement("CertifiedRoles"); //$NON-NLS-1$

        for (final String sr : signerRole.getClaimedRole())
        {
            final Element claimedRole = createElement("ClaimedRole"); //$NON-NLS-1$
            claimedRole.setTextContent(sr);
            claimedRoles.appendChild(claimedRole);
        }

        // TODO: Implement support for certified role and attribute certificates management
        for (final String sr : signerRole.getCertifiedRole()) {
            final Element certifiedRole = createElement("CertifiedRole"); //$NON-NLS-1$
            certifiedRole.setTextContent(sr);
            certifiedRoles.appendChild(certifiedRole);
        }

        if (signerRole.getClaimedRole().size() > 0) {
            getNode().appendChild(claimedRoles);
        }

        if (signerRole.getCertifiedRole().size() > 0) {
            getNode().appendChild(certifiedRoles);
        }
    }

    public SignerRoleDetails(final Node node,
    		                 final String xadesPrefix,
    		                 final String xadesNamespace,
    		                 final String xmlSignaturePrefix) {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }
}

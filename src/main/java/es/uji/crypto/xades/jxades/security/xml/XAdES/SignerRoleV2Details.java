package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 *
 * <p:SignerRoleV2>
 *     <p:ClaimedRoles>
 *         <p:ClaimedRole>
 *             ANYTYPE
 *         </p:ClaimedRole>
 *     </p:ClaimedRoles>
 *     <p:CertifiedRolesV2>
 *         <p:CertifiedRole>
 *             ANYTYPE
 *         </p:CertifiedRole>
 *     </p:CertifiedRolesV2>
 *     <p:SignedAssertions>
 *         ANYTYPE
 *     <p:SignedAssertions>
 * </p:SignerRoleV2>
 */

public class SignerRoleV2Details extends XAdESStructure
{
    public SignerRoleV2Details(final Document document, final SignedSignatureProperties ssp, final SignerRoleV2 signerRoleV2,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(document, ssp, "SignerRoleV2", xadesPrefix, xadesNamespace, xmlSignaturePrefix); //$NON-NLS-1$

        final Element claimedRoles = createElement("ClaimedRoles"); //$NON-NLS-1$
        final Element certifiedRoles = createElement("CertifiedRolesV2"); //$NON-NLS-1$
        final Element signedAssertions = createElement("SignedAssertions"); //$NON-NLS-1$

        for (final String sr : signerRoleV2.getClaimedRoles()) {
            final Element claimedRole = createElement("ClaimedRole"); //$NON-NLS-1$
            claimedRole.setTextContent(sr);
            claimedRoles.appendChild(claimedRole);
        }

        // TODO: Implement support for certified role and attribute certificates management
        for (final String sr : signerRoleV2.getCertifiedRolesV2()) {
            final Element certifiedRole = createElement("CertifiedRole"); //$NON-NLS-1$
            certifiedRole.setTextContent(sr);
            certifiedRoles.appendChild(certifiedRole);
        }

        // TODO: Implement support for signed assertions
        for (final String sr : signerRoleV2.getSignedAssertions()) {
            final Element signedAssertion = createElement("SignedAssertion"); //$NON-NLS-1$
            signedAssertion.setTextContent(sr);
            signedAssertions.appendChild(signedAssertion);
        }

        if (signerRoleV2.getClaimedRoles().size() > 0) {
            getNode().appendChild(claimedRoles);
        }

        if (signerRoleV2.getCertifiedRolesV2().size() > 0) {
            getNode().appendChild(certifiedRoles);
        }

        if (signerRoleV2.getSignedAssertions().size() > 0) {
            getNode().appendChild(signedAssertions);
        }
    }

    public SignerRoleV2Details(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }
}

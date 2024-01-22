package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

/**
 *
 * @author miro
 */
public class SignerDetails extends XAdESStructure
{
    public static final String USERNAME_ATTRIBUTE = "Username"; //$NON-NLS-1$

    public SignerDetails(final Document document, final SignedSignatureProperties ssp, final Signer signer, final String xadesPrefix,
            final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(document, ssp, "SignerDetails", xadesPrefix, xadesNamespace, xmlSignaturePrefix); //$NON-NLS-1$

        String value = signer.getPersonName();
        if (value == null) {
			throw new IllegalArgumentException("The Signer personal name can not be NULL."); //$NON-NLS-1$
		}
        setTextContent(value);

        value = signer.getUserId();
        if (value != null) {
			setAttributeNS(null, ID_ATTRIBUTE, value);
		}

        value = signer.getUsername();
        if (value != null) {
			setAttributeNS(null, USERNAME_ATTRIBUTE, value);
		}
    }

    public SignerDetails(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public Signer getSigner() {
        final SignerImpl signer = new SignerImpl();
        signer.setPersonName(getTextContent());
        signer.setUserId(getAttribute(ID_ATTRIBUTE));
        signer.setUsername(getAttribute(USERNAME_ATTRIBUTE));

        return signer;
    }
}

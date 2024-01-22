package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

/*
 <CertDigest>
 <DigestMethod Algorithm="" />
 <DigestValue></DigestValue>
 </CertDigest>
 */

/**
 *
 * @author miro
 */
public class CertDigest extends DigestAlgAndValue
{
    public CertDigest(final Document document,
    		          final XAdESStructure parent,
    		          final X509Certificate cert,
    		          final String xadesPrefix,
    		          final String xadesNamespace,
    		          final String xmlSignaturePrefix) throws GeneralSecurityException {
        super(document, parent, "CertDigest", cert.getEncoded(), xadesPrefix, xadesNamespace, xmlSignaturePrefix); //$NON-NLS-1$
    }

    public CertDigest(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }
}

package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 *
 * @author miro
 */
public class CompleteCertificateRefsImpl extends XAdESStructure implements CompleteCertificateRefs
{
    private CertRefs certRefs;

    public CompleteCertificateRefsImpl(final Document document, final XAdESStructure parent,
            final Collection<X509Certificate> caCertificates, final String signatureIdPrefix,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
            throws GeneralSecurityException
    {
        super(document, parent, "CompleteCertificateRefs", xadesPrefix, xadesNamespace, //$NON-NLS-1$
                xmlSignaturePrefix);

        if (caCertificates == null || caCertificates.isEmpty())
		 {
			throw new IllegalArgumentException(
                    "The CA Certificates collection can not be NULL or empty."); //$NON-NLS-1$
		}

        this.certRefs = new CertRefs(document, this, caCertificates, signatureIdPrefix, xadesPrefix,
                xadesNamespace, xmlSignaturePrefix);
    }

    public CompleteCertificateRefsImpl(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    @Override
	public CertRefs getCertRefs()
    {
        if (this.certRefs == null)
        {
            final Element element = getChildElementNS("CertRefs"); //$NON-NLS-1$
            if (element != null)
            {
                this.certRefs = new CertRefs(element, this.xadesPrefix, this.xadesNamespace, this.xmlSignaturePrefix);
            }
        }

        return this.certRefs;
    }
}

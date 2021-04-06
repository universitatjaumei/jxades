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

    public CompleteCertificateRefsImpl(Document document, XAdESStructure parent,
            Collection<X509Certificate> caCertificates, String signatureIdPrefix,
            String xadesPrefix, String xadesNamespace, String xmlSignaturePrefix)
            throws GeneralSecurityException
    {
        super(document, parent, "CompleteCertificateRefs", xadesPrefix, xadesNamespace,
                xmlSignaturePrefix);

        if (caCertificates == null || caCertificates.isEmpty())
            throw new IllegalArgumentException(
                    "The CA Certificates collection can not be NULL or empty.");

        this.certRefs = new CertRefs(document, this, caCertificates, signatureIdPrefix, xadesPrefix,
                xadesNamespace, xmlSignaturePrefix);
    }

    public CompleteCertificateRefsImpl(Node node, String xadesPrefix, String xadesNamespace,
            String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    @Override
	public CertRefs getCertRefs()
    {
        if (this.certRefs == null)
        {
            Element element = getChildElementNS("CertRefs");
            if (element != null)
            {
                this.certRefs = new CertRefs(element, this.xadesPrefix, this.xadesNamespace, this.xmlSignaturePrefix);
            }
        }

        return this.certRefs;
    }
}

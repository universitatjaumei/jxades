package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/*
 <Cert>
 <CertDigest>
 <DigestMethod Algorithm="" />
 <DigestValue></DigestValue>
 </CertDigest>
 <IssuerSerial>
 <X509IssuerName></X509IssuerName>
 <X509SerialNumber><X509SerialNumber>
 </IssuerSerial>
 </Cert>
 */

/**
 *
 * @author miro
 */
public class Cert extends XAdESStructure {

    private CertDigest certDigest;
    private IssuerSerial issuerSerial;

    public Cert(final Document document, final XAdESStructure parent, final X509Certificate cert, final String xadesPrefix,
            final String xadesNamespace, final String xmlSignaturePrefix) throws GeneralSecurityException
    {
        super(document, parent, "Cert", xadesPrefix, xadesNamespace, xmlSignaturePrefix); //$NON-NLS-1$

        this.certDigest = new CertDigest(document, this, cert, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
        this.issuerSerial = new IssuerSerial(document, this, cert, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public Cert(final Node node, final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public CertDigest getCertDigest()
    {
        if (this.certDigest == null)
        {
            final Element element = getChildElementNS("CertDigest"); //$NON-NLS-1$
            if (element != null) {
				this.certDigest = new CertDigest(element, this.xadesPrefix, this.xadesNamespace,
                        this.xmlSignaturePrefix);
			}
        }

        return this.certDigest;
    }

    public IssuerSerial getIssuerSerial()
    {
        if (this.issuerSerial == null)
        {
            final Element element = getChildElementNS("IssuerSerial"); //$NON-NLS-1$
            if (element != null) {
				this.issuerSerial = new IssuerSerial(element, this.xadesPrefix, this.xadesNamespace,
                        this.xmlSignaturePrefix);
			}
        }

        return this.issuerSerial;
    }
}

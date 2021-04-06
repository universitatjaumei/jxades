package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/*
 */

/**
 *
 * @author miro
 */
public class UnsignedSignatureProperties extends XAdESStructure
{
    private CompleteCertificateRefs completeCertificateRefs;
    private CompleteRevocationRefs completeRevocationRefs;
    private Document document;

    public UnsignedSignatureProperties(final Document document, final UnsignedProperties up,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(document, up, XAdES.Element.UNSIGNED_SIGNATURE_PROPERTIES.getElementName(),
                xadesPrefix, xadesNamespace, xmlSignaturePrefix);
        this.document = document;
    }

    public UnsignedSignatureProperties(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public CompleteCertificateRefs getCompleteCertificateRefs()
    {
        if (this.completeCertificateRefs == null)
        {
            final Element element = getChildElementNS("CompleteCertificateRefs"); //$NON-NLS-1$
            if (element != null) {
				this.completeCertificateRefs = new CompleteCertificateRefsImpl(element, this.xadesPrefix,
                        this.xadesNamespace, this.xmlSignaturePrefix);
			}
        }

        return this.completeCertificateRefs;
    }

    public void setCompleteCertificateRefs(final Collection<X509Certificate> caCertificates,
            final String signatureIdPrefix) throws GeneralSecurityException
    {
        this.completeCertificateRefs = getCompleteCertificateRefs();
        if (this.completeCertificateRefs != null) {
			throw new UnsupportedOperationException(
                    "The collection of CA Certificates already exists."); //$NON-NLS-1$
		}

        this.completeCertificateRefs = new CompleteCertificateRefsImpl(this.document, this, caCertificates,
                signatureIdPrefix, this.xadesPrefix, this.xadesNamespace, this.xmlSignaturePrefix);
    }

    public CompleteRevocationRefs getCompleteRevocationRefs()
    {
        if (this.completeRevocationRefs == null)
        {
            final Element element = getChildElementNS("CompleteRevocationRefs"); //$NON-NLS-1$
            if (element != null) {
				this.completeRevocationRefs = new CompleteRevocationRefsImpl(element, this.xadesPrefix,
                        this.xadesNamespace, this.xmlSignaturePrefix);
			}
        }

        return this.completeRevocationRefs;
    }

    // public void setCompleteRevocationRefs(CertValidationInfo certValidationInfo,
    // String signatureIdPrefix)
    // throws GeneralSecurityException
    // {
    // completeRevocationRefs = getCompleteRevocationRefs();
    // if(completeRevocationRefs != null)
    // throw new UnsupportedOperationException("The collection of CA Certificates already exists.");
    //
    // completeRevocationRefs = new CompleteRevocationRefsImpl(this,
    // certValidationInfo,
    // signatureIdPrefix);
    // }

    public void setSignatureTimeStamp(final ArrayList<SignatureTimeStamp> signatureTimeStamp,
            final String tsaURL)
    {
        for (final SignatureTimeStamp sts : signatureTimeStamp)
        {
            new SignatureTimeStampDetails(this.document, this, sts, this.xadesPrefix, this.xadesNamespace,
                    this.xmlSignaturePrefix, tsaURL);
        }
    }
}

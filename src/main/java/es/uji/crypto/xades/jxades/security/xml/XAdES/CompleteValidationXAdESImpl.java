package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.security.cert.X509Certificate;
import java.util.Collection;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/*
 <ds:Signature ID?>
 ...
 <ds:Object>
 <QualifyingProperties>
 ...
 <UnsignedProperties>
 <UnsignedSignatureProperties>
 (CompleteCertificateRefs)
 (CompleteRevocationRefs)
 (AttributeCertificateRefs)?
 (AttributeRevocationRefs)?
 </UnsignedSignatureProperties>
 </UnsignedProperties>
 </QualifyingProperties>
 </ds:Object>
 </ds:Signature>-
 */

/**
 *
 * @author miro
 */
public class CompleteValidationXAdESImpl extends TimestampXAdESImpl implements XAdES_C
{

    /*
     * public CompleteValidationXAdESImpl(Element baseElement, boolean useExplicitPolicy) {
     * super(baseElement, useExplicitPolicy); }
     */

    public CompleteValidationXAdESImpl(final Document document, final Element baseElement, final boolean readOnlyMode,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix,
            final String digestMethod)
    {
        super(document, baseElement, readOnlyMode, xadesPrefix, xadesNamespace, xmlSignaturePrefix,
                digestMethod);
    }

    @Override
	public CompleteCertificateRefs getCompleteCertificateRefs()
    {
        return (CompleteCertificateRefs) this.data.get(XAdES.Element.COMPLETE_CERTIFICATE_REFS);
    }

    @Override
	public void setCompleteCertificateRefs(final Collection<X509Certificate> caCertificates)
    {
        if (this.readOnlyMode)
        {
            throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode."); //$NON-NLS-1$
        }

        this.data.put(XAdES.Element.COMPLETE_CERTIFICATE_REFS, caCertificates);
    }

    public CompleteRevocationRefs getCompleteRevocationRefs()
    {
        return (CompleteRevocationRefs) this.data.get(XAdES.Element.COMPLETE_REVOCATION_REFS);
    }

    // public void setCompleteRevocationRefs(CertValidationInfo certValidationInfo)
    // {
    // if (readOnlyMode)
    // {
    // throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
    // }
    //
    // data.put(XAdES.Element.COMPLETE_REVOCATION_REFS, certValidationInfo);
    // }
}

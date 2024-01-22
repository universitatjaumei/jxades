package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.Date;

import javax.xml.crypto.MarshalException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/*
 <ds:Signature ID?>
 ...
 <ds:Object>
 <QualifyingProperties>
 ...
 <UnsignedProperties>
 <UnsignedSignatureProperties>
 (ArchiveTimeStamp)+
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
public class ArchivalXAdESImpl extends ExtendedLongXAdESImpl
// implements XAdES_A
{

    /*
     * public ArchivalXAdESImpl(Element baseElement, boolean useExplicitPolicy) { super(baseElement,
     * useExplicitPolicy); }
     */

    public ArchivalXAdESImpl(final Document document, final Element baseElement, final boolean readOnlyMode, final String xadesPrefix,
            final String xadesNamespace, final String xmlSignaturePrefix, final String digestMethod)
    {
        super(document, baseElement, readOnlyMode, xadesPrefix, xadesNamespace, xmlSignaturePrefix,
                digestMethod);
    }

    protected void unmarshal() throws MarshalException {
        final QualifyingProperties qp = getQualifyingProperties();
        if (qp != null) {
            try {
                final Element qpElement = qp.getElement();

                for (final XAdES.Element key : XAdES.Element.values()) {
                    final NodeList nl = qpElement.getElementsByTagNameNS(this.xadesNamespace, key.getElementName());
                    int size;
                    if (nl != null && (size = nl.getLength()) > 0) {
                        if (XAdES.Element.SIGNING_TIME.equals(key)) {
                            final SigningTime signingTime = new SigningTime(nl.item(0), this.xadesPrefix,
                                    this.xadesNamespace, this.xmlSignaturePrefix);
                            final Date date = signingTime.getSigningTime();
                            if (date != null) {
								this.data.put(XAdES.Element.SIGNING_TIME, date);
							}
                        }
                        else if (XAdES.Element.SIGNER_DETAILS.equals(key)) {
                            final SignerDetails signerDetails = new SignerDetails(nl.item(0),
                                    this.xadesPrefix, this.xadesNamespace, this.xmlSignaturePrefix);
                            this.data.put(XAdES.Element.SIGNER, signerDetails.getSigner());
                        }
                        else if (XAdES.Element.COMPLETE_CERTIFICATE_REFS.equals(key))
                        {
                            CompleteCertificateRefsImpl completeCertificateRefs;
                            completeCertificateRefs = new CompleteCertificateRefsImpl(nl.item(0),
                                    this.xadesPrefix, this.xadesNamespace, this.xmlSignaturePrefix);
                            this.data.put(XAdES.Element.COMPLETE_CERTIFICATE_REFS,
                                    completeCertificateRefs);
                        }
                        else if (XAdES.Element.COMPLETE_REVOCATION_REFS.equals(key))
                        {
                            CompleteRevocationRefsImpl completeRevocationRefs;
                            completeRevocationRefs = new CompleteRevocationRefsImpl(nl.item(0),
                                    this.xadesPrefix, this.xadesNamespace, this.xmlSignaturePrefix);
                            this.data
                                    .put(XAdES.Element.COMPLETE_REVOCATION_REFS,
                                            completeRevocationRefs);
                        }

                    }
                }
            }
            catch (final Exception ex)
            {
                throw new MarshalException(ex);
            }
        }
    }
}

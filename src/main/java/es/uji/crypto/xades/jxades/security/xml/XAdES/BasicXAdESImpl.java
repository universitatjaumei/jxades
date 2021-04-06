package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.TreeMap;

import javax.xml.crypto.MarshalException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 *
 * @author miro
 */
public class BasicXAdESImpl extends BaseXAdESImpl implements XAdES_BES
{
    protected boolean readOnlyMode = true;
    protected TreeMap<XAdES.Element, Object> data;
    private final Element baseElement;
    private Document baseDocument;
    private QualifyingProperties qualifyingProperties;

    public String xadesPrefix;
    public String xadesNamespace;
    public String xmlSignaturePrefix;
    public String digestMethod;

    public BasicXAdESImpl(final Document document, final Element baseElement, final boolean readOnlyMode,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix,
            final String digestMethod)
    {
        this.baseDocument = document;

        if (baseElement != null)
        {
            this.baseDocument = baseElement.getOwnerDocument();
        }

        this.baseElement = baseElement;
        this.readOnlyMode = readOnlyMode;

        this.data = new TreeMap<XAdES.Element, Object>();

        this.xadesPrefix = xadesPrefix;
        this.xadesNamespace = xadesNamespace;
        this.xmlSignaturePrefix = xmlSignaturePrefix;
        this.digestMethod = digestMethod;
    }

    @Override
	public Document getBaseDocument()
    {
        return this.baseDocument;
    }

    @Override
	public Element getBaseElement()
    {
        return this.baseElement;
    }

    @Override
	public String getDigestMethod()
    {
        return this.digestMethod;
    }

    @Override
	public Date getSigningTime()
    {
        return (Date) this.data.get(XAdES.Element.SIGNING_TIME);
    }

    @Override
	public SigningCertificate getSigningCertificate()
    {
        return (SigningCertificate) this.data.get(XAdES.Element.SIGNING_CERTIFICATE);
    }

    @Override
	public SignatureProductionPlace getSignatureProductionPlace()
    {
        return (SignatureProductionPlace) this.data.get(XAdES.Element.SIGNATURE_PRODUCTION_PLACE);
    }

    @Override
	public SignerRole getSignerRole()
    {
        return (SignerRole) this.data.get(XAdES.Element.SIGNER_ROLE);
    }

    @Override
	public Signer getSigner()
    {
        return (Signer) this.data.get(XAdES.Element.SIGNER);
    }

    @Override
	@SuppressWarnings("unchecked")
    public List<DataObjectFormat> getDataObjectFormats()
    {
        return (List<DataObjectFormat>) this.data.get(XAdES.Element.DATA_OBJECT_FORMATS);
    }

    @Override
	@SuppressWarnings("unchecked")
    public List<CommitmentTypeIndication> getCommitmentTypeIndications()
    {
        return (List<CommitmentTypeIndication>) this.data.get(XAdES.Element.COMMITMENT_TYPE_INDICATIONS);
    }

    @Override
	@SuppressWarnings("unchecked")
    public List<AllDataObjectsTimeStamp> getAllDataObjectsTimeStamps()
    {
        return (List<AllDataObjectsTimeStamp>) this.data.get(XAdES.Element.ALL_DATA_OBJECTS_TIMESTAMPS);
    }

    @Override
	@SuppressWarnings("unchecked")
    public List<XAdESTimeStamp> getIndividualDataObjectsTimeStamps()
    {
        return (List<XAdESTimeStamp>) this.data.get(XAdES.Element.INDIVIDUAL_DATA_OBJECTS_TIMESTAMPS);
    }

    @Override
	@SuppressWarnings("unchecked")
    public List<CounterSignature> getCounterSignatures()
    {
        return (List<CounterSignature>) this.data.get(XAdES.Element.COUNTER_SIGNATURES);
    }

    @Override
	public void setSigningTime(final Date signingTime)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
		}

        if (signingTime != null) {
			this.data.put(XAdES.Element.SIGNING_TIME, signingTime);
		} else {
			this.data.remove(XAdES.Element.SIGNING_TIME);
		}
    }

    @Override
    public void setSigningCertificate(final X509Certificate certificate) {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
		}

        if (certificate == null) {
        	this.data.remove(XAdES.Element.SIGNING_CERTIFICATE);
		} else {
			final SigningCertificateImpl sci = new SigningCertificateImpl(certificate, this.digestMethod);
			this.data.put(XAdES.Element.SIGNING_CERTIFICATE, sci);
		}
    }

    @Override
	public void setSignatureProductionPlace(final SignatureProductionPlace productionPlace)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
		}

        if (productionPlace != null) {
			this.data.put(XAdES.Element.SIGNATURE_PRODUCTION_PLACE, productionPlace);
		} else {
			this.data.remove(XAdES.Element.SIGNATURE_PRODUCTION_PLACE);
		}
    }

    @Override
	public void setSignerRole(final SignerRole signerRole)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
		}

        if (signerRole != null) {
			this.data.put(XAdES.Element.SIGNER_ROLE, signerRole);
		} else {
			this.data.remove(XAdES.Element.SIGNER_ROLE);
		}
    }

    @Override
	public void setSigner(final Signer signer)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
		}

        if (signer != null) {
			this.data.put(XAdES.Element.SIGNER, signer);
		} else {
			this.data.remove(XAdES.Element.SIGNER);
		}
    }

    @Override
	public void setDataObjectFormats(final List<DataObjectFormat> dataObjectFormats)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
		}

        if (dataObjectFormats != null && dataObjectFormats.size() > 0) {
			this.data.put(XAdES.Element.DATA_OBJECT_FORMATS, dataObjectFormats);
		} else {
			this.data.remove(XAdES.Element.DATA_OBJECT_FORMATS);
		}
    }

    @Override
	public void setCommitmentTypeIndications(
            final List<CommitmentTypeIndication> commitmentTypeIndications)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
		}

        if (commitmentTypeIndications != null && commitmentTypeIndications.size() > 0) {
			this.data.put(XAdES.Element.COMMITMENT_TYPE_INDICATIONS, commitmentTypeIndications);
		} else {
			this.data.remove(XAdES.Element.COMMITMENT_TYPE_INDICATIONS);
		}
    }

    @Override
	public void setAllDataObjectsTimeStamps(final List<AllDataObjectsTimeStamp> allDataObjectsTimeStamps)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
		}

        if (allDataObjectsTimeStamps != null && allDataObjectsTimeStamps.size() > 0) {
			this.data.put(XAdES.Element.ALL_DATA_OBJECTS_TIMESTAMPS, allDataObjectsTimeStamps);
		} else {
			this.data.remove(XAdES.Element.ALL_DATA_OBJECTS_TIMESTAMPS);
		}
    }

    @Override
	public void setIndividualDataObjectsTimeStamps(
            final List<IndividualDataObjectsTimeStamp> individualDataObjectsTimeStamps)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
		}

        if (individualDataObjectsTimeStamps != null && individualDataObjectsTimeStamps.size() > 0) {
			this.data.put(XAdES.Element.INDIVIDUAL_DATA_OBJECTS_TIMESTAMPS,
                    individualDataObjectsTimeStamps);
		} else {
			this.data.remove(XAdES.Element.INDIVIDUAL_DATA_OBJECTS_TIMESTAMPS);
		}
    }

    @Override
	public void setCounterSignatures(final List<CounterSignature> counterSignatures)
    {
        if (this.readOnlyMode) {
			throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
		}

        if (counterSignatures != null && counterSignatures.size() > 0) {
			this.data.put(XAdES.Element.COUNTER_SIGNATURES, counterSignatures);
		} else {
			this.data.remove(XAdES.Element.COUNTER_SIGNATURES);
		}
    }

    // public void setCompleteCertificateRefs(Collection<X509Certificate> caCertificates)
    // {
    // if (readOnlyMode)
    // {
    // throw new UnsupportedOperationException("Set Method is not allowed. Read-only mode.");
    // }
    //
    // if (caCertificates != null && caCertificates.size() > 0)
    // {
    // data.put(XAdES.Element.COMPLETE_CERTIFICATE_REFS, caCertificates);
    // }
    // else
    // {
    // data.remove(XAdES.Element.COMPLETE_CERTIFICATE_REFS);
    // }
    // }

    // Each implementation have to inherit this method
    // and to return the appropriate XAdES type.
    // This is important for checking cases in new XML Advanced Signature
    protected XAdES getXAdESType()
    {
        return XAdES.BES;
    }

    protected QualifyingProperties getQualifyingProperties()
    {
        if (this.qualifyingProperties == null)
        {
            final NodeList nl = this.baseElement.getElementsByTagNameNS(this.xadesNamespace,
                    XAdES.Element.QUALIFYING_PROPERTIES.getElementName());
            if (nl != null && nl.getLength() > 0)
            {
                this.qualifyingProperties = new QualifyingProperties(nl.item(0), this.xadesPrefix,
                        this.xadesNamespace, this.xmlSignaturePrefix);
            }
        }

        return this.qualifyingProperties;
    }

    protected SignedSignatureProperties getSignedSignatureProperties(final QualifyingProperties qp)
    {
        return qp.getSignedProperties().getSignedSignatureProperties();
    }

    protected SignedDataObjectProperties getSignedDataObjectProperties(final QualifyingProperties qp)
    {
        return qp.getSignedProperties().getSignedDataObjectProperties();
    }

    protected UnsignedSignatureProperties getUnsignedSignatureProperties(final QualifyingProperties qp)
    {
        return qp.getUnsignedProperties().getUnsignedSignatureProperties();
    }

    @Override
	@SuppressWarnings("unchecked")
    protected void marshalQualifyingProperties(final QualifyingProperties qp, final String signatureIdPrefix,
            final List referencesIdList) throws MarshalException
    {
        SignedSignatureProperties ssp;
        SignedDataObjectProperties sdop;
        UnsignedSignatureProperties usp;

        try
        {
            for (final XAdES.Element key : XAdES.Element.values())
            {
                if (XAdES.Element.SIGNING_TIME.equals(key))
                {
                    ssp = getSignedSignatureProperties(qp);
                    ssp.setSigningTime();
                }
                else
                {
                    final Object value = this.data.get(key);

                    if (value != null)
                    {
                        if (XAdES.Element.SIGNER.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSigner((Signer) value);
                        }
                        else if (XAdES.Element.SIGNING_CERTIFICATE.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSigningCertificate((SigningCertificate) value);
                        }
                        else if (XAdES.Element.SIGNATURE_POLICY_IDENTIFIER.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSignaturePolicyIdentifier((SignaturePolicyIdentifier) value);
                        }
                        else if (XAdES.Element.SIGNATURE_PRODUCTION_PLACE.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSignatureProductionPlace((SignatureProductionPlace) value);
                        }
                        else if (XAdES.Element.SIGNER_ROLE.equals(key))
                        {
                            ssp = getSignedSignatureProperties(qp);
                            ssp.setSignerRole((SignerRole) value);
                        }
                        else if (XAdES.Element.DATA_OBJECT_FORMATS.equals(key))
                        {
                            sdop = getSignedDataObjectProperties(qp);
                            sdop.setDataObjectFormat((ArrayList<DataObjectFormat>) value);
                        }
                        else if (XAdES.Element.COMMITMENT_TYPE_INDICATIONS.equals(key))
                        {
                            sdop = getSignedDataObjectProperties(qp);
                            sdop.setCommitmentTypeIndications((ArrayList<CommitmentTypeIndication>) value);
                        }
                        else if (XAdES.Element.COMPLETE_CERTIFICATE_REFS.equals(key))
                        {
                            usp = getUnsignedSignatureProperties(qp);
                            usp.setCompleteCertificateRefs((Collection<X509Certificate>) value,
                                    signatureIdPrefix);
                        }
                    }
                }
            }
        }
        catch (final GeneralSecurityException ex)
        {
            throw new MarshalException(ex);
        }
    }

    @Override
	public String getXadesPrefix()
    {
        return this.xadesPrefix;
    }

    @Override
	public String getXmlSignaturePrefix()
    {
        return this.xmlSignaturePrefix;
    }

    @Override
	public String getXadesNamespace()
    {
        return this.xadesNamespace;
    }
}

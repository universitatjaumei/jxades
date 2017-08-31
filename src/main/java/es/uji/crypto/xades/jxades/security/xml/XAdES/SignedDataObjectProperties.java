package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;

public class SignedDataObjectProperties extends XAdESStructure
{
    private final Document document;

    public SignedDataObjectProperties(final Document document, final SignedProperties signedProperties,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(document, signedProperties, "SignedDataObjectProperties", xadesPrefix,
                xadesNamespace, xmlSignaturePrefix);
        this.document = document;
    }

    public void setDataObjectFormat(final ArrayList<DataObjectFormat> dataObjectFormat)
    {
        for (final DataObjectFormat dof : dataObjectFormat)
        {
            new DataObjectFormatDetails(this.document, this, dof, this.xadesPrefix, this.xadesNamespace,
                    this.xmlSignaturePrefix);
        }
    }

    public void setCommitmentTypeIndications(final List<CommitmentTypeIndication> commitmentTypeIndications) {
    	for (final CommitmentTypeIndication commitmentTypeIndication : commitmentTypeIndications) {
	        new CommitmentTypeIndicationDetails(
	    		this.document,
	    		this,
	    		commitmentTypeIndication,
	    		this.xadesPrefix,
	            this.xadesNamespace,
	            this.xmlSignaturePrefix
	        );
    	}
    }

    public void setAllDataObjectsTimeStamp(
            final ArrayList<AllDataObjectsTimeStamp> allDataObjectsTimeStamp, final String tsaURL)
    {
        for (final AllDataObjectsTimeStamp adots : allDataObjectsTimeStamp)
        {
            new AllDataObjectsTimeStampDetails(this.document, this, adots, this.xadesPrefix, this.xadesNamespace,
                    this.xmlSignaturePrefix, tsaURL);
        }
    }

    public void setIndividualDataObjectsTimeStamp(
            final ArrayList<IndividualDataObjectsTimeStamp> individualDataObjectsTimeStamp, final String tsaURL)
    {
        for (final IndividualDataObjectsTimeStamp idots : individualDataObjectsTimeStamp)
        {
            new IndividualDataObjectsTimeStampDetails(this.document, this, idots, this.xadesPrefix,
                    this.xadesNamespace, this.xmlSignaturePrefix, tsaURL);
        }
    }
}
package net.java.xades.security.xml.XAdES;

import java.util.ArrayList;

import org.w3c.dom.Document;

public class SignedDataObjectProperties extends XAdESStructure
{
    private Document document;

    public SignedDataObjectProperties(Document document, SignedProperties signedProperties,
            String xadesPrefix, String xadesNamespace, String xmlSignaturePrefix)
    {
        super(document, signedProperties, "SignedDataObjectProperties", xadesPrefix,
                xadesNamespace, xmlSignaturePrefix);
        this.document = document;
    }

    public void setDataObjectFormat(ArrayList<DataObjectFormat> dataObjectFormat)
    {
        for (DataObjectFormat dof : dataObjectFormat)
        {
            new DataObjectFormatDetails(document, this, dof, xadesPrefix, xadesNamespace,
                    xmlSignaturePrefix);
        }
    }

    public void setCommitmentTypeIndication(CommitmentTypeIndication commitmentTypeIndication)
    {
        new CommitmentTypeIndicationDetails(document, this, commitmentTypeIndication, xadesPrefix,
                xadesNamespace, xmlSignaturePrefix);
    }

    public void setAllDataObjectsTimeStamp(
            ArrayList<AllDataObjectsTimeStamp> allDataObjectsTimeStamp, String tsaURL)
    {
        for (AllDataObjectsTimeStamp adots : allDataObjectsTimeStamp)
        {
            new AllDataObjectsTimeStampDetails(document, this, adots, xadesPrefix, xadesNamespace,
                    xmlSignaturePrefix, tsaURL);
        }
    }

    public void setIndividualDataObjectsTimeStamp(
            ArrayList<IndividualDataObjectsTimeStamp> individualDataObjectsTimeStamp, String tsaURL)
    {
        for (IndividualDataObjectsTimeStamp idots : individualDataObjectsTimeStamp)
        {
            new IndividualDataObjectsTimeStampDetails(document, this, idots, xadesPrefix,
                    xadesNamespace, xmlSignaturePrefix, tsaURL);
        }
    }
}
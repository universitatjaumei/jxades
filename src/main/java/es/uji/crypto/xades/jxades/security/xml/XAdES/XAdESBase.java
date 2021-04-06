package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.Date;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public interface XAdESBase {

    Element getBaseElement();
    Document getBaseDocument();

    Date getSigningTime();
    void setSigningTime(Date signingTime);

    Signer getSigner();
    void setSigner(Signer signer);

    List<DataObjectFormat> getDataObjectFormats();
    void setDataObjectFormats(List<DataObjectFormat> dataObjectFormats);

    List<CommitmentTypeIndication> getCommitmentTypeIndications();
    void setCommitmentTypeIndications(List<CommitmentTypeIndication> commitmentTypeIndications);

    List<AllDataObjectsTimeStamp> getAllDataObjectsTimeStamps();
    void setAllDataObjectsTimeStamps(List<AllDataObjectsTimeStamp> allDataObjectsTimeStamps);

    List<XAdESTimeStamp> getIndividualDataObjectsTimeStamps();
    void setIndividualDataObjectsTimeStamps(List<IndividualDataObjectsTimeStamp> individualDataObjectsTimeStamps);

    List<CounterSignature> getCounterSignatures();
    void setCounterSignatures(List<CounterSignature> counterSignatures);

    String getXadesPrefix();
    String getXadesNamespace();
    String getXmlSignaturePrefix();

    String getDigestMethod();
    void setDigestMethod(final String algName);
}

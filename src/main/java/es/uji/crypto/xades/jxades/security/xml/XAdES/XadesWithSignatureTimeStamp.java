package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.List;

public interface XadesWithSignatureTimeStamp {

    List<SignatureTimeStamp> getSignatureTimeStamps();
    void setSignatureTimeStamps(List<SignatureTimeStamp> signatureTimeStamps);
}

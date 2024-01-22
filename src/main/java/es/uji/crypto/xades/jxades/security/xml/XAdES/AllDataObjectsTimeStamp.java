package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import org.w3c.dom.Document;

public interface AllDataObjectsTimeStamp {
    byte[] generateEncapsulatedTimeStamp(Document parent, String tsaURL) throws NoSuchAlgorithmException, SignatureException, IOException;
}

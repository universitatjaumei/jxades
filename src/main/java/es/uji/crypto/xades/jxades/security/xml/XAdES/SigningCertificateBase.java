package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.security.GeneralSecurityException;

public interface SigningCertificateBase {
	String getDigestMethodAlgorithm();
	void setDigestMethodAlgorithm(final String algName);
	String getDigestValue() throws GeneralSecurityException;
}

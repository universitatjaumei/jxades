package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.math.BigInteger;

public interface SigningCertificate extends SigningCertificateBase 
{
	public String getIssuerName();
	public BigInteger getX509SerialNumber();
}

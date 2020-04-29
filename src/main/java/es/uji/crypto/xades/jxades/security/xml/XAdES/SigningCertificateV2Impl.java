package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import javax.xml.crypto.dsig.DigestMethod;

import es.uji.crypto.xades.jxades.util.Base64;

public class SigningCertificateV2Impl implements SigningCertificateV2
{
	private X509Certificate certificate;
	private String digestMethod;
	private String issuerSerial = null;
	
	public SigningCertificateV2Impl(final X509Certificate certificate, final String digestMethod) 
	{
		this.certificate = certificate;
		this.digestMethod = digestMethod;
	}

	public String getDigestMethodAlgorithm() 
	{
		return this.digestMethod;
	}

	public String getDigestValue() throws GeneralSecurityException
	{
		String result;
		
		try
		{
		    String algorithm = "SHA-256"; //$NON-NLS-1$

		    if (DigestMethod.SHA512.equals(this.digestMethod))
		    {
                algorithm = "SHA-512"; //$NON-NLS-1$
		    }
		    
			MessageDigest md = MessageDigest.getInstance(algorithm);	
			md.update(this.certificate.getEncoded());
			result = Base64.encodeBytes(md.digest());
		}
		catch (Exception e)
		{
			throw new GeneralSecurityException(e);
		}
		
		return result;
	}

	public void setIssuerSerialV2(final String issuerSerial) {
		this.issuerSerial = issuerSerial;
	}
	
	public String getIssuerSerialV2() {
		return this.issuerSerial;
	}
}

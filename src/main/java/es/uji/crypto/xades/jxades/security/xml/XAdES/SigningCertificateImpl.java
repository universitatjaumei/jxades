package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import javax.xml.crypto.dsig.DigestMethod;

import es.uji.crypto.xades.jxades.util.Base64;

public class SigningCertificateImpl implements SigningCertificate
{
	private final X509Certificate certificate;
	private String digestMethod;

	public SigningCertificateImpl(final X509Certificate certificate, final String digestMethod) {
		this.certificate = certificate;
		this.digestMethod = digestMethod;
	}

	@Override
	public void setDigestMethodAlgorithm(final String algName) {
		if (algName == null || algName.isEmpty()) {
			throw new IllegalArgumentException("El algoritmo de nuella no puede ser nulo ni vacio"); //$NON-NLS-1$
		}
		this.digestMethod = algName;
	}

	@Override
	public String getDigestMethodAlgorithm() {
		return this.digestMethod;
	}

	@Override
	public String getDigestValue() throws GeneralSecurityException
	{
		String result;

		try
		{
		    final String algorithm;

		    if (DigestMethod.SHA512.equals(this.digestMethod)) {
                algorithm = "SHA-512"; //$NON-NLS-1$
		    }
		    else if (DigestMethod.SHA256.equals(this.digestMethod)) {
                algorithm = "SHA-256"; //$NON-NLS-1$
		    }
		    else if (DigestMethod.SHA224.equals(this.digestMethod)) {
                algorithm = "SHA-224"; //$NON-NLS-1$
		    }
		    else if (DigestMethod.SHA384.equals(this.digestMethod)) {
                algorithm = "SHA-384"; //$NON-NLS-1$
		    }
		    else {
		    	throw new GeneralSecurityException(
	    			"Algoritmo de huella no soportado: " + this.digestMethod //$NON-NLS-1$
    			);
		    }

			final MessageDigest md = MessageDigest.getInstance(algorithm);
			md.update(this.certificate.getEncoded());
			result = Base64.encodeBytes(md.digest());
		}
		catch (final Exception e) {
			throw new GeneralSecurityException(e);
		}

		return result;
	}

	@Override
	public String getIssuerName() {
		return this.certificate.getIssuerDN().getName();
	}

	@Override
	public BigInteger getX509SerialNumber() {
		return this.certificate.getSerialNumber();
	}
}

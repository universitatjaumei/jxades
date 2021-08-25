package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import javax.xml.crypto.dsig.DigestMethod;

import es.uji.crypto.xades.jxades.util.Base64;

public final class SignaturePolicyIdentifierImpl implements SignaturePolicyIdentifier {

    private boolean implied;
    private String sigPolicyId;
    private String description;
    private String sigPolicyQualifierSPURI;
    private String sigPolicyHashBase64;
    private String sigPolicyHashHashAlgorithm;

    private static final Logger LOGGER = Logger.getLogger(
		SignaturePolicyIdentifierImpl.class.getName()
	);

    public SignaturePolicyIdentifierImpl(final boolean implied) {
        this.implied = implied;
    }

    private static byte[] inputStreamToByteArray(final InputStream in) throws IOException {
        final byte[] buffer = new byte[2048];
        int length = 0;
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((length = in.read(buffer)) >= 0) {
            baos.write(buffer, 0, length);
        }
        return baos.toByteArray();
    }

    @Override
	public void setIdentifier(final String identifier) throws IOException,
	                                                          NoSuchAlgorithmException {
        setIdentifier(identifier, null, null);
    }

    @Override
	public void setIdentifier(final String identifier,
			                  final String hashBase64,
			                  final String hashAlgorithm) throws IOException,
	                                                             NoSuchAlgorithmException {

        if (hashBase64 == null || hashBase64.isEmpty() || hashAlgorithm == null || hashAlgorithm.isEmpty()) {
        	if (hashBase64 == null || hashBase64.isEmpty()) {
        		LOGGER.warning(
    				"No se ha indicado huella digital de la politica de firma, se intentara una descarga y se calculara al vuelo con SHA-256"
				);
        	}
        	else if (hashAlgorithm == null || hashAlgorithm.isEmpty()) {
        		LOGGER.warning(
    				"No se ha indicado algoritmo de huella digital de la politica de firma, se intentara una descarga y se calculara una nueva huella al vuelo con SHA-256"
				);
        	}
            final URLConnection conn = new URL(identifier).openConnection();
            final byte[] data;
            try (
        		final InputStream is = conn.getInputStream()
    		) {
            	data = inputStreamToByteArray(is);
            }
            final MessageDigest md = MessageDigest.getInstance("SHA-256"); //$NON-NLS-1$
            this.sigPolicyHashBase64 = Base64.encodeBytes(md.digest(data));
            this.sigPolicyHashHashAlgorithm = DigestMethod.SHA256;
        }
        else {
            this.sigPolicyHashBase64 = hashBase64;
            this.sigPolicyHashHashAlgorithm = hashAlgorithm;
        }
        this.sigPolicyId = identifier;
    }

    @Override
	public boolean isImplied() {
        return this.implied;
    }

    @Override
	public void setImplied(final boolean implied) {
        this.implied = implied;
    }

    @Override
	public String getIdentifier() {
        return this.sigPolicyId;
    }

    @Override
	public String getHashBase64() {
        return this.sigPolicyHashBase64;
    }

    @Override
	public String getDescription() {
        return this.description;
    }

    @Override
	public void setDescription(final String description) {
        this.description = description;
    }

    @Override
	public String getQualifier() {
        return this.sigPolicyQualifierSPURI;
    }

    @Override
	public void setQualifier(final String qualifier) {
        this.sigPolicyQualifierSPURI = qualifier;
    }

    @Override
	public String getHashAlgorithm() {
        return this.sigPolicyHashHashAlgorithm;
    }
}

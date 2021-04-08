package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.crypto.dsig.DigestMethod;

import es.uji.crypto.xades.jxades.util.Base64;

public class SignaturePolicyIdentifierImpl implements SignaturePolicyIdentifier
{
    private boolean implied;
    private String sigPolicyId;
    private String description;
    private String sigPolicyQualifierSPURI;
    private String sigPolicyHashBase64;
    private String sigPolicyHashHashAlgorithm;

    public SignaturePolicyIdentifierImpl(final boolean implied)
    {
        this.implied = implied;
    }

    private byte[] inputStreamToByteArray(final InputStream in) throws IOException
    {
        final byte[] buffer = new byte[2048];
        int length = 0;
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((length = in.read(buffer)) >= 0)
        {
            baos.write(buffer, 0, length);
        }
        return baos.toByteArray();
    }

    @Override
	public void setIdentifier(final String identifier) throws IOException, NoSuchAlgorithmException
    {
        setIdentifier(identifier, null, null);
    }

    @Override
	public void setIdentifier(final String identifier, final String hashBase64, final String hashAlgorithm) throws IOException, NoSuchAlgorithmException
    {
        if (hashBase64 == null || "".equals(hashBase64) || hashAlgorithm == null || "".equals(hashAlgorithm)) //$NON-NLS-1$ //$NON-NLS-2$
        {
            final URLConnection conn = new URL(identifier).openConnection();
            final byte[] data = inputStreamToByteArray(conn.getInputStream());
            final MessageDigest md = MessageDigest.getInstance("SHA-256"); //$NON-NLS-1$
            md.update(data);
            this.sigPolicyHashBase64 = Base64.encodeBytes(md.digest());
            this.sigPolicyHashHashAlgorithm = DigestMethod.SHA256;
        }
        else
        {
            this.sigPolicyHashBase64 = hashBase64;
            this.sigPolicyHashHashAlgorithm = hashAlgorithm;
        }
        this.sigPolicyId = identifier;
    }

    @Override
	public boolean isImplied()
    {
        return this.implied;
    }

    @Override
	public void setImplied(final boolean implied)
    {
        this.implied = implied;
    }

    @Override
	public String getIdentifier()
    {
        return this.sigPolicyId;
    }

    @Override
	public String getHashBase64()
    {
        return this.sigPolicyHashBase64;
    }

    @Override
	public String getDescription()
    {
        return this.description;
    }

    @Override
	public void setDescription(final String description)
    {
        this.description = description;
    }

    @Override
	public String getQualifier()
    {
        return this.sigPolicyQualifierSPURI;
    }

    @Override
	public void setQualifier(final String qualifier)
    {
        this.sigPolicyQualifierSPURI = qualifier;
    }

    @Override
	public String getHashAlgorithm() {
        return this.sigPolicyHashHashAlgorithm;
    }
}

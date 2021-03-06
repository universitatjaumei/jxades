package es.uji.crypto.xades.jxades.security.xml;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;

import org.junit.Test;
import org.xml.sax.SAXException;

import es.uji.crypto.xades.jxades.security.xml.XAdES.XMLAdvancedSignature;
import es.uji.crypto.xades.jxades.util.XMLUtils;

public final class TestCosign extends BaseTest
{
    @Test
    public void xades() throws FileNotFoundException, IOException, GeneralSecurityException,
            MarshalException, XMLSignatureException, TransformException,
            ParserConfigurationException, SAXException
    {
        final byte[] data = "<?xml version=\"1.0\"?><root><datafile Id=\"test\">contenido</datafile></root>" //$NON-NLS-1$
                .getBytes();

        // Default signature options
        final SignatureOptions signatureOptions = getSignatureOptions(
                "src/test/resources/catcert.p12", "PKCS12", null, "1234", "1234"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$

        // Build XAdES-EPES signature
        XMLAdvancedSignature xmlSignature = createXAdES_EPES(signatureOptions, data);
        xmlSignature.sign(signatureOptions.getCertificate(), signatureOptions.getPrivateKey(),
    		XMLUtils.RSA_SHA256, Arrays.asList("test"), "S0"); //$NON-NLS-1$ //$NON-NLS-2$

        // Show results
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        showSignature(xmlSignature, bos);
        System.out.println(new String(bos.toByteArray()));

        // Verify signature
        verify(xmlSignature);

        // Cosign
        xmlSignature = createXAdES_EPES(signatureOptions, bos.toByteArray());
        xmlSignature.sign(signatureOptions.getCertificate(), signatureOptions.getPrivateKey(),
        		XMLUtils.RSA_SHA256, Arrays.asList("test"), "S1"); //$NON-NLS-1$ //$NON-NLS-2$

        // Show results
        bos = new ByteArrayOutputStream();
        showSignature(xmlSignature, bos);
        System.out.println(new String(bos.toByteArray()));

        // Verify signature
        verify(xmlSignature);

        try (final java.io.OutputStream fos = new FileOutputStream("src/test/resources/out-cosign-jxades.xml")) { //$NON-NLS-1$
	        showSignature(
	    		xmlSignature,
	            fos
			);
        }
    }
}
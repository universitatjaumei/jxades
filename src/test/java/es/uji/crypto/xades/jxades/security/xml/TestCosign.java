package es.uji.crypto.xades.jxades.security.xml;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;

import es.uji.crypto.xades.jxades.security.xml.XAdES.XMLAdvancedSignature;

import org.junit.Test;
import org.xml.sax.SAXException;

public class TestCosign extends BaseTest
{
    @Test
    public void xades() throws FileNotFoundException, IOException, GeneralSecurityException,
            MarshalException, XMLSignatureException, TransformException,
            ParserConfigurationException, SAXException
    {
        byte[] data = "<?xml version=\"1.0\"?><root><datafile Id=\"test\">contenido</datafile></root>"
                .getBytes();

        // Default signature options
        SignatureOptions signatureOptions = getSignatureOptions(
                "src/test/resources/catcert.p12", "PKCS12", null, "1234", "1234");

        // Build XAdES-EPES signature
        XMLAdvancedSignature xmlSignature = createXAdES_EPES(signatureOptions, data);
        xmlSignature.sign(signatureOptions.getCertificate(), signatureOptions.getPrivateKey(),
                SignatureMethod.RSA_SHA1, Arrays.asList(new Object[] { "test" }), "S0");

        // Show results
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        showSignature(xmlSignature, bos);
        System.out.println(new String(bos.toByteArray()));

        // Verify signature
        verify(xmlSignature);

        // Cosign
        xmlSignature = createXAdES_EPES(signatureOptions, bos.toByteArray());
        xmlSignature.sign(signatureOptions.getCertificate(), signatureOptions.getPrivateKey(),
                SignatureMethod.RSA_SHA1, Arrays.asList(new Object[] { "test" }), "S1");

        // Show results
        bos = new ByteArrayOutputStream();
        showSignature(xmlSignature, bos);
        System.out.println(new String(bos.toByteArray()));

        // Verify signature
        verify(xmlSignature);

        showSignature(xmlSignature,
                new FileOutputStream("src/test/resources/out-cosign-jxades.xml"));
    }
}
package es.uji.crypto.xades.jxades.security.xml;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
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

public class TestDigidocOpenXAdES extends BaseTest
{
    private void signAndVerify(String fileName, int numDatafiles) throws FileNotFoundException,
            IOException, GeneralSecurityException, MarshalException, XMLSignatureException,
            TransformException, ParserConfigurationException, SAXException
    {
        byte[] document = inputStreamToByteArray(new FileInputStream("src/test/resources/"
                + fileName));

        // Default signature options
        SignatureOptions signatureOptions = getSignatureOptions(
                "src/test/resources/catcert.p12", "PKCS12", null, "1234", "1234");

        XMLAdvancedSignature xmlSignature = null;

        // Build XAdES-EPES signature chain
        for (int i = 0; i < numDatafiles; i++)
        {
            xmlSignature = createXAdES_EPES(signatureOptions, document);
            xmlSignature.sign(signatureOptions.getCertificate(), signatureOptions.getPrivateKey(),
                    SignatureMethod.RSA_SHA1, Arrays.asList(new Object[] { "D" + i }), "S" + i);

            // Show results
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            showSignature(xmlSignature, bos);

            document = bos.toByteArray();

            System.out.println(new String(document));

            // Verify signature
            verify(xmlSignature);
        }

        showSignature(xmlSignature, new FileOutputStream("src/test/resources/out-" + fileName));
    }

    @Test
    public void digiDocOpenXAdES() throws FileNotFoundException, IOException,
            GeneralSecurityException, MarshalException, XMLSignatureException, TransformException,
            ParserConfigurationException, SAXException
    {
        signAndVerify("digidoc-openxades-1.xml", 3);
        signAndVerify("digidoc-openxades-2.xml", 2);
    }
}
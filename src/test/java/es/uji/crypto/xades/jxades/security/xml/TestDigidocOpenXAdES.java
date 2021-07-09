package es.uji.crypto.xades.jxades.security.xml;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
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

public class TestDigidocOpenXAdES extends BaseTest
{
    private void signAndVerify(final String fileName, final int numDatafiles) throws FileNotFoundException,
            IOException, GeneralSecurityException, MarshalException, XMLSignatureException,
            TransformException, ParserConfigurationException, SAXException
    {
        byte[] document = inputStreamToByteArray(new FileInputStream("src/test/resources/" //$NON-NLS-1$
                + fileName));

        // Default signature options
        final SignatureOptions signatureOptions = getSignatureOptions(
                "src/test/resources/catcert.p12", "PKCS12", null, "1234", "1234"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$

        XMLAdvancedSignature xmlSignature = null;

        // Build XAdES-EPES signature chain
        for (int i = 0; i < numDatafiles; i++)
        {
            xmlSignature = createXAdES_EPES(signatureOptions, document);
            xmlSignature.sign(signatureOptions.getCertificate(), signatureOptions.getPrivateKey(),
        		XMLUtils.RSA_SHA256, Arrays.asList("D" + i), "S" + i); //$NON-NLS-1$ //$NON-NLS-2$

            // Show results
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            showSignature(xmlSignature, bos);

            document = bos.toByteArray();

            System.out.println(new String(document));

            // Verify signature
            verify(xmlSignature);
        }

        showSignature(xmlSignature, new FileOutputStream("src/test/resources/out-" + fileName)); //$NON-NLS-1$
    }

    @Test
    public void digiDocOpenXAdES() throws FileNotFoundException, IOException,
            GeneralSecurityException, MarshalException, XMLSignatureException, TransformException,
            ParserConfigurationException, SAXException
    {
        signAndVerify("digidoc-openxades-1.xml", 3); //$NON-NLS-1$
        signAndVerify("digidoc-openxades-2.xml", 2); //$NON-NLS-1$
    }
}
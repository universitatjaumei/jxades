package es.uji.crypto.xades.jxades.security.xml;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;

import es.uji.crypto.xades.jxades.security.xml.XAdES.SignaturePolicyIdentifier;
import es.uji.crypto.xades.jxades.security.xml.XAdES.SignaturePolicyIdentifierImpl;
import es.uji.crypto.xades.jxades.security.xml.XAdES.SigningCertificateV2Info;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdES;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdES_B_Level;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdES_EPES;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XMLAdvancedSignature;

import org.junit.Test;
import org.xml.sax.SAXException;

public class BLevelSignatureTest extends BaseTest
{
    @Test
    public void bLevelDetached() throws FileNotFoundException, IOException, GeneralSecurityException,
            MarshalException, XMLSignatureException, TransformException,
            ParserConfigurationException, SAXException
    {
        // Default signature options
        SignatureOptions signatureOptions = getSignatureOptions(
                "src/test/resources/catcert.p12", "PKCS12", null, "1234", "1234");

        // Build XAdES-EPES signature
        XMLAdvancedSignature xmlSignature = createXadesBLevel(signatureOptions);
        xmlSignature.sign(signatureOptions.getCertificate(), signatureOptions.getPrivateKey(),
                SignatureMethod.RSA_SHA1,
                Arrays.asList(new Object[] { "http://es.wikipedia.org/wiki/CATCert" }), "S0");

        // Show results
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        showSignature(xmlSignature, bos);
        System.out.println(new String(bos.toByteArray()));

        // Verify signature
        verify(xmlSignature);

        OutputStream os = new FileOutputStream("target/out-detached-B_Level.xml");
        showSignature(xmlSignature, os);
        os.close();
    }
    
    private static XMLAdvancedSignature createXadesBLevel(SignatureOptions signatureOptions)
            throws GeneralSecurityException
    {
        // Build XAdES-EPES signature
        XAdES_B_Level xades = (XAdES_B_Level) XAdES.newInstance(XAdES.B_LEVEL);
        xades.setSigningCertificateV2(signatureOptions.getCertificate(), null);
        
        // Enveloped signature
        return XMLAdvancedSignature.newInstance(xades);
    }
}
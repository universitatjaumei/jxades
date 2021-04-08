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

import org.junit.Test;
import org.xml.sax.SAXException;

import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdES;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdES_B_Level;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XMLAdvancedSignature;

public final class BLevelSignatureTest extends BaseTest {

    @Test
    public void bLevelDetached() throws FileNotFoundException,
                                        IOException,
                                        GeneralSecurityException,
                                        MarshalException,
                                        XMLSignatureException,
                                        TransformException,
                                        ParserConfigurationException,
                                        SAXException {
        // Default signature options
        final SignatureOptions signatureOptions = getSignatureOptions(
            "src/test/resources/catcert.p12", "PKCS12", null, "1234", "1234" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		);

        // Build XAdES-EPES signature
        final XMLAdvancedSignature xmlSignature = createXadesBLevel(signatureOptions);
        xmlSignature.sign(signatureOptions.getCertificate(), signatureOptions.getPrivateKey(),
                SignatureMethod.RSA_SHA256,
                Arrays.asList("http://es.wikipedia.org/wiki/CATCert"), "S0" //$NON-NLS-1$ //$NON-NLS-2$
		);

        // Show results
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        showSignature(xmlSignature, bos);
        System.out.println(new String(bos.toByteArray()));

        // Verify signature
        verify(xmlSignature);

        try (final OutputStream os = new FileOutputStream("target/out-detached-B_Level.xml")) { //$NON-NLS-1$
        	showSignature(xmlSignature, os);
        }
    }

    private static XMLAdvancedSignature createXadesBLevel(final SignatureOptions signatureOptions) throws GeneralSecurityException {
        // Build XAdES-EPES signature
        final XAdES_B_Level xades = (XAdES_B_Level) XAdES.newInstance(XAdES.B_LEVEL);
        xades.setSigningCertificateV2(signatureOptions.getCertificate(), null);

        // Enveloped signature
        return XMLAdvancedSignature.newInstance(xades);
    }
}
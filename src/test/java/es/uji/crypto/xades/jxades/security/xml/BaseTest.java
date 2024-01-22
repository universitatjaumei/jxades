package es.uji.crypto.xades.jxades.security.xml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import es.uji.crypto.xades.jxades.security.xml.XAdES.SignaturePolicyIdentifier;
import es.uji.crypto.xades.jxades.security.xml.XAdES.SignaturePolicyIdentifierImpl;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdES;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdES_EPES;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdES_T;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XMLAdvancedSignature;
import es.uji.crypto.xades.jxades.util.XMLUtils;

public class BaseTest
{
    protected SignatureOptions getSignatureOptions(final String keystorePath, final String keystoreType,
            final String alias, final String keystorePassword, final String keyPassword) throws KeyStoreException,
            NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException,
            FileNotFoundException, IOException
    {
        // Keystore
        final KeyStore keystore = KeyStore.getInstance(keystoreType);
        keystore.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());

        // Alias del certificado de firma
        String certificateAlias = alias;

        if (certificateAlias == null)
        {
            certificateAlias = keystore.aliases().nextElement();
        }

        // Certificado de firma
        final X509Certificate certificate = (X509Certificate) keystore.getCertificate(certificateAlias);

        // Clave privada para firmar
        final PrivateKey privateKey = (PrivateKey) keystore.getKey(certificateAlias,
                keyPassword.toCharArray());

        final SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setKeystore(keystore);
        signatureOptions.setCertificate(certificate);
        signatureOptions.setPrivateKey(privateKey);

        return signatureOptions;
    }

    protected Element getDocumentToSign(final byte[] data) throws SAXException, IOException,
            ParserConfigurationException
    {
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        final DocumentBuilder db = dbf.newDocumentBuilder();

        return db.parse(new ByteArrayInputStream(data)).getDocumentElement();
    }

    protected Element getEmptyDocument() throws SAXException, IOException,
            ParserConfigurationException
    {
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        final DocumentBuilder db = dbf.newDocumentBuilder();
        return db.newDocument().getDocumentElement();
    }

    protected boolean verify(final XMLAdvancedSignature xmlSignature)
    {
        final List<SignatureStatus> st = xmlSignature.validate();

        boolean validate = true;

        for (final SignatureStatus status : st)
        {
            if (status.getValidateResult() != ValidateResult.VALID)
            {
                System.out.println("Sign validation error: "); //$NON-NLS-1$
                System.out.println(status.getReasonsAsText());
                validate = false;
            }
        }

        if (validate)
        {
            System.out.println("OK"); //$NON-NLS-1$
        }

        return validate;
    }

    protected void showSignature(final XMLAdvancedSignature xmlSignature)
    {
        XMLUtils.writeXML(System.out, xmlSignature.getBaseElement(), false);
    }

    protected void showSignature(final XMLAdvancedSignature xmlSignature, final OutputStream output)
    {
        if (xmlSignature.getBaseElement() != null)
        {
            XMLUtils.writeXML(output, xmlSignature.getBaseElement(), false);
        }
        else
        {
            XMLUtils.writeXML(output, xmlSignature.getBaseDocument(), false);
        }
    }

    protected XMLAdvancedSignature createXAdES_EPES(final SignatureOptions signatureOptions, final byte[] data)
            throws SAXException, IOException, ParserConfigurationException,
            GeneralSecurityException
    {
        return createXAdES_EPES(signatureOptions, getDocumentToSign(data));
    }

    protected XMLAdvancedSignature createXAdES_EPES(final SignatureOptions signatureOptions, final Element data)
            throws SAXException, IOException, ParserConfigurationException,
            GeneralSecurityException
    {
        // Build XAdES-EPES signature
        final XAdES_EPES xades = (XAdES_EPES) XAdES.newInstance(XAdES.EPES, data);
        xades.setSigningCertificate(signatureOptions.getCertificate());

        // Add implied policy
        final SignaturePolicyIdentifier spi = new SignaturePolicyIdentifierImpl(true);
        xades.setSignaturePolicyIdentifier(spi);

        // Enveloped signature
        return XMLAdvancedSignature.newInstance(xades);
    }

    protected XMLAdvancedSignature createXadesEpesDetached(final SignatureOptions signatureOptions)
            throws SAXException, IOException, ParserConfigurationException,
            GeneralSecurityException
    {
        // Build XAdES-EPES signature
        final XAdES_EPES xades = (XAdES_EPES) XAdES.newInstance(XAdES.EPES);
        xades.setSigningCertificate(signatureOptions.getCertificate());

        // Add implied policy
        final SignaturePolicyIdentifier spi = new SignaturePolicyIdentifierImpl(true);
        xades.setSignaturePolicyIdentifier(spi);

        // Enveloped signature
        return XMLAdvancedSignature.newInstance(xades);
    }

    protected XMLAdvancedSignature createXAdES_T(final SignatureOptions signatureOptions, final byte[] data)
            throws SAXException, IOException, ParserConfigurationException,
            GeneralSecurityException
    {
        // Build XAdES-T signature
        final XAdES_T xades = (XAdES_T) XAdES.newInstance(XAdES.T, getDocumentToSign(data));
        xades.setSigningCertificate(signatureOptions.getCertificate());

        // Add implied policy
        final SignaturePolicyIdentifier spi = new SignaturePolicyIdentifierImpl(true);
        xades.setSignaturePolicyIdentifier(spi);

        // Enveloped signature
        return XMLAdvancedSignature.newInstance(xades);
    }

    public static byte[] inputStreamToByteArray(final InputStream in) throws IOException
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
}
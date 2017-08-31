package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509CRL;

import javax.xml.crypto.dsig.DigestMethod;

import es.uji.crypto.xades.jxades.util.Base64;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/*
 <DigestAlgAndValue>
 <DigestMethod Algorithm= />
 <DigestValue />
 </DigestAlgAndValue>
 */

/**
 * 
 * @author miro
 */
public class DigestAlgAndValue extends XAdESStructure
{
    private static final String ALGORITHM_ATTR = "Algorithm";
    private static final String DIGEST_METHOD_ELEMENT = "DigestMethod";
    private static final String DIGEST_VALUE_ELEMENT = "DigestValue";

    // public DigestAlgAndValue(XAdESStructure parent, OCSPResponse ocspResponse)
    // throws GeneralSecurityException
    // {
    // this(parent, "DigestAlgAndValue", ocspResponse.getResponseData());
    // }

    public DigestAlgAndValue(Document document, XAdESStructure parent, X509CRL crl,
            String xadesPrefix, String xadesNamespace, String xmlSignaturePrefix)
            throws GeneralSecurityException
    {
        this(document, parent, "DigestAlgAndValue", crl.getEncoded(), xadesPrefix, xadesNamespace,
                xmlSignaturePrefix);
    }

    protected DigestAlgAndValue(Document document, XAdESStructure parent, String elementName,
            byte[] data, String xadesPrefix, String xadesNamespace, String xmlSignaturePrefix)
            throws GeneralSecurityException
    {
        super(document, parent, elementName, xadesPrefix, xadesNamespace, xmlSignaturePrefix);

        Element thisElement = getElement();

        Element element = createElement(DIGEST_METHOD_ELEMENT);
        element.setPrefix(xmlSignaturePrefix);
        thisElement.appendChild(element);
        element.setAttributeNS(xmlSignaturePrefix, ALGORITHM_ATTR, DigestMethod.SHA1);

        MessageDigest md = MessageDigest.getInstance("SHA-1");

        String digestValue = Base64.encodeBytes(md.digest(data));
        element = createElement(DIGEST_VALUE_ELEMENT);
        element.setPrefix(xmlSignaturePrefix);
        thisElement.appendChild(element);
        element.setTextContent(digestValue);
    }

    protected DigestAlgAndValue(Document document, XAdESStructure parent, String xadesPrefix,
            String xadesNamespace, String xmlSignaturePrefix) throws GeneralSecurityException
    {
        super(document, parent, "DigestAlgAndValue", xadesPrefix, xadesNamespace,
                xmlSignaturePrefix);
    }

    public DigestAlgAndValue(Node node, String xadesPrefix, String xadesNamespace,
            String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public String getDigestMethod()
    {
        return getChildElementTextContent(DIGEST_METHOD_ELEMENT);
    }

    public byte[] getDigestValue() throws IOException
    {
        String value = getChildElementTextContent(DIGEST_VALUE_ELEMENT);

        if (value != null && (value = value.trim()).length() > 0)
        {
            return Base64.decode(value);
        }

        return null;
    }
}

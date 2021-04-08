package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509CRL;

import javax.xml.crypto.dsig.DigestMethod;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.uji.crypto.xades.jxades.util.Base64;

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
    private static final String ALGORITHM_ATTR = "Algorithm"; //$NON-NLS-1$
    private static final String DIGEST_METHOD_ELEMENT = "DigestMethod"; //$NON-NLS-1$
    private static final String DIGEST_VALUE_ELEMENT = "DigestValue"; //$NON-NLS-1$

    // public DigestAlgAndValue(XAdESStructure parent, OCSPResponse ocspResponse)
    // throws GeneralSecurityException
    // {
    // this(parent, "DigestAlgAndValue", ocspResponse.getResponseData());
    // }

    public DigestAlgAndValue(final Document document, final XAdESStructure parent, final X509CRL crl,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
            throws GeneralSecurityException
    {
        this(document, parent, "DigestAlgAndValue", crl.getEncoded(), xadesPrefix, xadesNamespace, //$NON-NLS-1$
                xmlSignaturePrefix);
    }

    protected DigestAlgAndValue(final Document document, final XAdESStructure parent, final String elementName,
            final byte[] data, final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
            throws GeneralSecurityException
    {
        super(document, parent, elementName, xadesPrefix, xadesNamespace, xmlSignaturePrefix);

        final Element thisElement = getElement();

        Element element = createElement(DIGEST_METHOD_ELEMENT);
        element.setPrefix(xmlSignaturePrefix);
        thisElement.appendChild(element);
        element.setAttributeNS(xmlSignaturePrefix, ALGORITHM_ATTR, DigestMethod.SHA256);

        final MessageDigest md = MessageDigest.getInstance("SHA-256"); //$NON-NLS-1$

        final String digestValue = Base64.encodeBytes(md.digest(data));
        element = createElement(DIGEST_VALUE_ELEMENT);
        element.setPrefix(xmlSignaturePrefix);
        thisElement.appendChild(element);
        element.setTextContent(digestValue);
    }

    protected DigestAlgAndValue(final Document document, final XAdESStructure parent, final String xadesPrefix,
            final String xadesNamespace, final String xmlSignaturePrefix) throws GeneralSecurityException
    {
        super(document, parent, "DigestAlgAndValue", xadesPrefix, xadesNamespace, //$NON-NLS-1$
                xmlSignaturePrefix);
    }

    public DigestAlgAndValue(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
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

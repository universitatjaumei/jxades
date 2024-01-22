package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/*
 <IssuerSerial>
 <X509IssuerName></X509IssuerName>
 <X509SerialNumber><X509SerialNumber>
 </IssuerSerial>
 */

/**
 *
 * @author miro
 */
public class IssuerSerial extends XAdESStructure
{
    public IssuerSerial(final Document document, final XAdESStructure parent, final X509Certificate cert,
            final String xadesPrefix, final String xadesNamespace, final String xmlSignaturePrefix)
    {
        this(document, parent, cert.getIssuerX500Principal(), cert.getSerialNumber(), xadesPrefix,
                xadesNamespace, xmlSignaturePrefix);
    }

    public IssuerSerial(final Document document, final XAdESStructure parent, final X500Principal issuer,
            final BigInteger serialNumber, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(document, parent, "IssuerSerial", xadesPrefix, xadesNamespace, xmlSignaturePrefix); //$NON-NLS-1$

        final Element thisElement = getElement();

        Element element = createElement("X509IssuerName"); //$NON-NLS-1$
        thisElement.appendChild(element);
        element.setTextContent(issuer.getName());

        element = createElement("X509SerialNumber"); //$NON-NLS-1$
        thisElement.appendChild(element);
        element.setTextContent(serialNumber.toString());
    }

    public IssuerSerial(final Node node,
    		            final String xadesPrefix,
    		            final String xadesNamespace,
    		            final String xmlSignaturePrefix) {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public String getIssuerName()
    {
        return getChildElementTextContent("X509IssuerName"); //$NON-NLS-1$
    }

    public String getSerialNumber()
    {
        return getChildElementTextContent("X509SerialNumber"); //$NON-NLS-1$
    }
}

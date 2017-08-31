package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import es.uji.crypto.xades.jxades.util.SystemUtils;

import org.w3c.dom.Node;

/*
 <CRLIdentifier URI="#Signature_1_EncapsulatedCRLValue_1">
 <Issuer>...</Issuer>
 <IssueTime>...</IssueTime>
 <Number>...</Number>
 </CRLIdentifier>
 */

/**
 * 
 * @author miro
 */
public class CRLIdentifier extends XAdESStructure
{
    private URI crlURI;
    private X500Principal issuer;
    private Date issueTime;
    private BigInteger crlNumber;

    public CRLIdentifier(Node node, String xadesPrefix, String xadesNamespace,
            String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public X500Principal getIssuer()
    {
        if (issuer == null)
        {
            String value = getChildElementTextContent("Issuer");
            if (value != null)
                issuer = new X500Principal(value);
        }

        return issuer;
    }

    public Date getIssueTime() throws ParseException
    {
        if (issueTime == null)
        {
            String value = getChildElementTextContent("IssueTime");
            if (value != null)
                issueTime = SystemUtils.parseDate(value);
        }

        return issueTime;
    }

    public BigInteger getCRLNumber()
    {
        if (crlNumber == null)
        {
            String value = getChildElementTextContent("Number");
            if (value != null)
                crlNumber = new BigInteger(value);
        }

        return crlNumber;
    }

    public URI getCrlURI() throws URISyntaxException
    {
        if (crlURI == null)
        {
            String value = getAttribute("URI");
            if (value != null)
                crlURI = new URI(value);
        }

        return crlURI;
    }
}

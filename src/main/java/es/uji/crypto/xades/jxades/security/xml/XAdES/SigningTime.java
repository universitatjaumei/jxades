package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.text.ParseException;
import java.util.Date;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import es.uji.crypto.xades.jxades.util.SystemUtils;

/**
 *
 * @author miro
 */
public class SigningTime extends XAdESStructure
{
    public SigningTime(final Document document, final SignedSignatureProperties ssp, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        this(document, ssp, new Date(), xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public SigningTime(final Document document, final SignedSignatureProperties ssp, final Date signingTime, final String xadesPrefix,
            final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(document, ssp, "SigningTime", xadesPrefix, xadesNamespace, xmlSignaturePrefix); //$NON-NLS-1$
        getElement().setTextContent(SystemUtils.formatDate(signingTime));
    }

    public SigningTime(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public Date getSigningTime() throws ParseException
    {
        final String value = getTextContent();

        if (value != null)
        {
            return SystemUtils.parseDate(value);
        }
		return null;
    }
}

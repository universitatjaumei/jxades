package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.io.IOException;
import java.text.ParseException;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.uji.crypto.xades.jxades.util.Base64;
import es.uji.crypto.xades.jxades.util.SystemUtils;
import es.uji.crypto.xades.jxades.util.XMLUtils;

/*
 <OCSPIdentifier URI="OCSPResponse1.der">
 <ResponderID>
 <ByName>String of X500Principal Name</ByName>
 or
 <ByKey>base64Binary of PublicKey DER value</ByKey>
 </ResponderID>
 <ProducedAt>2003−11−06T13:28:04+01:00</ProducedAt>
 </OCSPIdentifier>
 */

/**
 *
 * @author miro
 */
public class OCSPIdentifier extends XAdESStructure
{
    private X500Principal responderName;
    private byte[] responderKey;
    private Date producedAt;

    public OCSPIdentifier(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }

    public X500Principal getResponderName()
    {
        if (this.responderName == null)
        {
            Element element = getChildElementNS("ResponderID"); //$NON-NLS-1$
            if (element != null) {
                element = XMLUtils.getChildElementByTagName(element, "ByName"); //$NON-NLS-1$
                if (element != null) {
                    String value = element.getTextContent();
                    if (value != null && (value = value.trim()).length() > 0) {
						this.responderName = new X500Principal(value);
					}
                }
            }
        }

        return this.responderName;
    }

    public byte[] getResponderKey() throws IOException {
        if (this.responderKey == null) {
            Element element = getChildElementNS("ResponderID"); //$NON-NLS-1$
            if (element != null) {
                element = XMLUtils.getChildElementByTagName(element, "ByKey"); //$NON-NLS-1$
                if (element != null) {
                    String value = element.getTextContent();
                    if (value != null && (value = value.trim()).length() > 0) {
						this.responderKey = Base64.decode(value);
					}
                }
            }
        }
        return this.responderKey;
    }

    public Date getProducedAt() throws ParseException {
        if (this.producedAt == null) {
            final String value = getChildElementTextContent("ProducedAt"); //$NON-NLS-1$
            if (value != null) {
				this.producedAt = SystemUtils.parseDate(value);
			}
        }
        return this.producedAt;
    }
}

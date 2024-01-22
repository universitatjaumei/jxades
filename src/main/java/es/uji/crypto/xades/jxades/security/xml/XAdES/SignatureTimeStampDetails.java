package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import es.uji.crypto.xades.jxades.util.Base64;

public class SignatureTimeStampDetails extends XAdESStructure
{
    public SignatureTimeStampDetails(final Document document, final XAdESStructure parent,
            final SignatureTimeStamp signatureTimeStamp, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix, final String tsaURL)
    {
        super(document, parent, "SignatureTimeStamp", xadesPrefix, xadesNamespace, //$NON-NLS-1$
                xmlSignaturePrefix);

        try {
            final String tsBase64Data = Base64.encodeBytes(signatureTimeStamp
                    .generateEncapsulatedTimeStamp(getDocument(), tsaURL));

            final Element tsNode = createElement("EncapsulatedTimeStamp"); //$NON-NLS-1$
            tsNode.appendChild(getDocument().createTextNode(tsBase64Data));

            getNode().appendChild(tsNode);
        }
        catch (final Exception e) {
            e.printStackTrace();
        }
    }
}

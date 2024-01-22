package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import es.uji.crypto.xades.jxades.util.Base64;

public class AllDataObjectsTimeStampDetails extends XAdESStructure {
    public AllDataObjectsTimeStampDetails(final Document document,
                                          final SignedDataObjectProperties signedDataObjectProperties,
                                          final AllDataObjectsTimeStamp allDataObjectsTimeStamp,
                                          final String xadesPrefix,
                                          final String xadesNamespace,
                                          final String xmlSignaturePrefix,
                                          final String tsaURL) {
        super(document, signedDataObjectProperties, "AllDataObjectsTimeStamp", xadesPrefix, //$NON-NLS-1$
                xadesNamespace, xmlSignaturePrefix);

        try {
            final String tsBase64Data = Base64.encodeBytes(allDataObjectsTimeStamp
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

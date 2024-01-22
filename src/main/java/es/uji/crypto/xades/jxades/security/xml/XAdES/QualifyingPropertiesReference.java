package es.uji.crypto.xades.jxades.security.xml.XAdES;

import javax.xml.crypto.dom.DOMStructure;

import org.w3c.dom.Node;

/**
 *
 * @author miro
 */
public class QualifyingPropertiesReference extends DOMStructure {
    public QualifyingPropertiesReference(final Node node, final String xadesNamespace) {
        super(node.getOwnerDocument().createElementNS(xadesNamespace, "QualifyingPropertiesReference")); //$NON-NLS-1$
    }
}

package es.uji.crypto.xades.jxades.security.xml.XAdES;

import es.uji.crypto.xades.jxades.util.ObjectId;
import es.uji.crypto.xades.jxades.util.OccursRequirement;

/**
 *
 * @author miro
 */
public interface XadesElement
{
    public XAdES[] getXAdES();
    public ObjectId getObjectId();
    public String getElementName();
    public OccursRequirement getOccursRequirement();
    public XadesElement getParent();
}

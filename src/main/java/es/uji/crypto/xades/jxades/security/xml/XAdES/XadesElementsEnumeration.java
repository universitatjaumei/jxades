package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.TreeMap;

import es.uji.crypto.xades.jxades.util.ObjectId;

/**
 * 
 * @author miro
 */
@SuppressWarnings("serial")
public class XadesElementsEnumeration extends TreeMap<ObjectId, XadesElement>
{
    public XadesElementsEnumeration(XadesElement[] xadesElements, XAdES xadesFilter)
    {
        for (XadesElement element : xadesElements)
        {
            XAdES xades = element.getXAdES();
            if (xades != null && xades.equals(xadesFilter))
                put(element.getObjectId(), element);
        }
    }

    public XadesElementsEnumeration(XadesElement[] xadesElements)
    {
        for (XadesElement element : xadesElements)
        {
            put(element.getObjectId(), element);
        }
    }
}

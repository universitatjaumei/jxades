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
            XAdES[] xadesProfiles = element.getXAdES();
            if (xadesProfiles != null) {
            	for (XAdES xades : xadesProfiles) {
            		if (xades != null && xades.equals(xadesFilter)) {
            			put(element.getObjectId(), element);
            			break;
            		}
            	}
            }
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

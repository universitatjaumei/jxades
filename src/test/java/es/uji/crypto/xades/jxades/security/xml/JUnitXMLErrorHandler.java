package es.uji.crypto.xades.jxades.security.xml;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import junit.framework.Assert;

public class JUnitXMLErrorHandler implements ErrorHandler
{
    @Override
    public void warning(final SAXParseException exception) throws SAXException {
    	// Vacio
    }

    @Override
    public void fatalError(final SAXParseException exception) throws SAXException
    {
        Assert.fail();
    }

    @Override
    public void error(final SAXParseException exception) throws SAXException
    {
    	System.out.println(exception);
        Assert.fail();
    }
}

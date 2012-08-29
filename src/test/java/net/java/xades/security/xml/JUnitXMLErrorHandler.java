package net.java.xades.security.xml;

import junit.framework.Assert;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

public class JUnitXMLErrorHandler implements ErrorHandler
{
    @Override
    public void warning(SAXParseException exception) throws SAXException
    {
    }

    @Override
    public void fatalError(SAXParseException exception) throws SAXException
    {
        Assert.fail();
    }

    @Override
    public void error(SAXParseException exception) throws SAXException
    {
        Assert.fail();
    }
}

package es.uji.crypto.xades.jxades.security.xml;

import org.junit.Test;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class ValidateSchemaTest
{
    @Test
    public void shouldValidateXAdESv132() throws FileNotFoundException, IOException,
            GeneralSecurityException, MarshalException, XMLSignatureException, TransformException,
            ParserConfigurationException, SAXException
    {
        validaDocumentAgainsSchemaFile("xades-1.3.2.xsd");
    }

    @Test
    public void shouldValidateXAdESv141() throws FileNotFoundException, IOException,
            GeneralSecurityException, MarshalException, XMLSignatureException, TransformException,
            ParserConfigurationException, SAXException
    {
        validaDocumentAgainsSchemaFile("xades-1.4.1.xsd");
    }

    private void validaDocumentAgainsSchemaFile(String schemaFile)
            throws ParserConfigurationException, SAXException, IOException, FileNotFoundException
    {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setValidating(true);
        documentBuilderFactory.setAttribute(
                "http://java.sun.com/xml/jaxp/properties/schemaLanguage",
                "http://www.w3.org/2001/XMLSchema");
        documentBuilderFactory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource",
                new File("src/main/resources/" + schemaFile));

        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        documentBuilder.setErrorHandler(new JUnitXMLErrorHandler());

        documentBuilder.parse(new FileInputStream("src/main/resources/detached-jxades.xml"));
    }
}
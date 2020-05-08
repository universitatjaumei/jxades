package es.uji.crypto.xades.jxades.security.xml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.junit.Test;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class ValidateSchemaTest
{
    @Test
    public void shouldValidateXAdESv132() throws FileNotFoundException, IOException,
            GeneralSecurityException, MarshalException, XMLSignatureException, TransformException,
            ParserConfigurationException, SAXException
    {
        validaDocumentAgainsSchemaFile("XAdES01903v132-201601.xsd");
    }

    @Test
    public void shouldValidateXAdESv141() throws FileNotFoundException, IOException,
            GeneralSecurityException, MarshalException, XMLSignatureException, TransformException,
            ParserConfigurationException, SAXException
    {
        validaDocumentAgainsSchemaFile("XAdES01903v132-201601.xsd");
    }

    private void validaDocumentAgainsSchemaFile(final String schemaFile)
            throws ParserConfigurationException, SAXException, IOException, FileNotFoundException
    {
        final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setValidating(true);
        //documentBuilderFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "all");
        documentBuilderFactory.setAttribute(
                "http://java.sun.com/xml/jaxp/properties/schemaLanguage",
                "http://www.w3.org/2001/XMLSchema");
        documentBuilderFactory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource",
        		"http://www.w3.org/2001/datatypes.dtd");

        documentBuilderFactory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource",
                new File("src/test/resources/" + schemaFile));

        final DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        documentBuilder.setEntityResolver(new RedirectEntityResolver());
        documentBuilder.setErrorHandler(new JUnitXMLErrorHandler());

        documentBuilder.parse(new FileInputStream("src/test/resources/detached-jxades.xml"));
    }

    private static class RedirectEntityResolver implements EntityResolver {

    	private String previousUrlBase = null;

        public RedirectEntityResolver() {}

		@Override
		public InputSource resolveEntity(final String publicId, final String systemId) throws SAXException, IOException {

			System.out.println("publicId: " + publicId);
			System.out.println("systemId: " + systemId);

			String resourceUrl = systemId;
			if (resourceUrl.startsWith("file://") && this.previousUrlBase != null) {
				resourceUrl = this.previousUrlBase + systemId.substring(systemId.lastIndexOf("/"));
			}

			System.out.println("URL actualizada: " + resourceUrl);
			System.out.println("----------");

            final URL obj = new URL(resourceUrl);
            HttpURLConnection conn = (HttpURLConnection) obj.openConnection();

            final int status = conn.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK &&
                (status == HttpURLConnection.HTTP_MOVED_TEMP
                || status == HttpURLConnection.HTTP_MOVED_PERM
                || status == HttpURLConnection.HTTP_SEE_OTHER)) {

                final String newUrl = conn.getHeaderField("Location");
                conn = (HttpURLConnection) new URL(newUrl).openConnection();
            }

            this.previousUrlBase = resourceUrl.substring(0, resourceUrl.lastIndexOf("/"));

            return new InputSource(conn.getInputStream());

        }

    }
}
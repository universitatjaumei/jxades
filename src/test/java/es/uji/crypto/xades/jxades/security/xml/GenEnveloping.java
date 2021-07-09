package es.uji.crypto.xades.jxades.security.xml;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import es.uji.crypto.xades.jxades.util.XMLUtils;

public class GenEnveloping
{
    @Test
    public void envelopingOk() throws Exception
    {
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        final Document doc = dbf.newDocumentBuilder().newDocument();

        final Element root = doc.createElementNS(null, "root"); //$NON-NLS-1$
        root.setAttributeNS(null, "Id", "test"); //$NON-NLS-1$ //$NON-NLS-2$
        root.setIdAttributeNS(null, "Id", true); //$NON-NLS-1$
        root.appendChild(doc.createTextNode("perico")); //$NON-NLS-1$

        doc.appendChild(root);

        dump(doc);
        sign(doc);
    }

    @Test
    public void envelopingFail() throws Exception
    {
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        final Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(
                "<?xml version=\"1.0\"?>\n<root Id=\"test\">perico</root>".getBytes())); //$NON-NLS-1$

        doc.getDocumentElement().setIdAttributeNS(null, "Id", true); //$NON-NLS-1$

        dump(doc);
        sign(doc);
    }

    private void sign(final Document doc) throws Exception
    {
        // XMLSignature

        final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM"); //$NON-NLS-1$

        final Reference ref = fac.newReference("#test", fac.newDigestMethod(DigestMethod.SHA256, null)); //$NON-NLS-1$

        final SignedInfo si = fac.newSignedInfo(
    		fac.newCanonicalizationMethod(
				CanonicalizationMethod.INCLUSIVE,
                (C14NMethodParameterSpec) null),
    			fac.newSignatureMethod(
					XMLUtils.RSA_SHA256,
					null
				),
			Collections.singletonList(ref)
		);

        // KeyInfo

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
        kpg.initialize(512);
        final KeyPair kp = kpg.generateKeyPair();

        final KeyInfoFactory kif = fac.getKeyInfoFactory();
        final KeyValue kv = kif.newKeyValue(kp.getPublic());

        final KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

        // SignContext

        final DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), doc.getDocumentElement());

        // Signature

        final XMLSignature signature = fac.newXMLSignature(si, ki);
        signature.sign(dsc);

        // Output

        dump(doc);
    }

    private void dump(final Document doc) throws TransformerException
    {
        final TransformerFactory tf = TransformerFactory.newInstance();
        final Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(System.out));
    }
}
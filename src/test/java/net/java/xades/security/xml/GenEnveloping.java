package net.java.xades.security.xml;

import com.sun.org.apache.xerces.internal.dom.DocumentImpl;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.*;
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
import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;

public class GenEnveloping
{
    @Test
    public void envelopingOk() throws Exception
    {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentImpl doc = (DocumentImpl) dbf.newDocumentBuilder().newDocument();

        Element root = doc.createElementNS(null, "root");
        root.setAttributeNS(null, "Id", "test");
        root.setIdAttributeNS(null, "Id", true);
        root.appendChild(doc.createTextNode("perico"));

        doc.appendChild(root);

        dump(doc);
        sign(doc);
    }

    @Test
    public void envelopingFail() throws Exception
    {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(
                "<?xml version=\"1.0\"?>\n<root Id=\"test\">perico</root>".getBytes()));

        doc.getDocumentElement().setIdAttributeNS(null, "Id", true);

        dump(doc);
        sign(doc);
    }

    private void sign(Document doc) throws Exception
    {
        // XMLSignature

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        Reference ref = fac.newReference("#test", fac.newDigestMethod(DigestMethod.SHA1, null));

        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                (C14NMethodParameterSpec) null), fac.newSignatureMethod(
                SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

        // KeyInfo

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());

        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

        // SignContext

        DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), doc.getDocumentElement());

        // Signature

        XMLSignature signature = fac.newXMLSignature(si, ki);
        signature.sign(dsc);

        // Output

        dump(doc);
    }

    private void dump(Document doc) throws TransformerException
    {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(System.out));
    }
}
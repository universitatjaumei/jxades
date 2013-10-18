package net.java.xades.security.xml;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;

public class GenEnvelopingObject
{
    @Test
    public void enveloping() throws Exception
    {
        // Data

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().newDocument();
        Node text = doc.createTextNode("some text");
        XMLStructure content = new DOMStructure(text);

        // XMLSignature

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        Reference ref = fac.newReference("#object", fac.newDigestMethod(DigestMethod.SHA1, null));

        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                (C14NMethodParameterSpec) null), fac.newSignatureMethod(
                SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

        XMLObject obj = fac.newXMLObject(Collections.singletonList(content), "object", null, null);

        // KeyInfo

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());

        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

        // SignContext

        DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), doc);

        // Signature

        XMLSignature signature = fac.newXMLSignature(si, ki, Collections.singletonList(obj), null, null);
        signature.sign(dsc);

        // Output

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(System.out));
    }
}
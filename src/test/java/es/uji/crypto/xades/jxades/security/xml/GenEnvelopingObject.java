package es.uji.crypto.xades.jxades.security.xml;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
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

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

public final class GenEnvelopingObject {
    @Test
    public void enveloping() throws Exception {
        // Data

        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        final Document doc = dbf.newDocumentBuilder().newDocument();
        final Node text = doc.createTextNode("some text"); //$NON-NLS-1$
        final XMLStructure content = new DOMStructure(text);

        // XMLSignature

        final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM"); //$NON-NLS-1$

        final Reference ref = fac.newReference("#object", fac.newDigestMethod(DigestMethod.SHA256, null)); //$NON-NLS-1$

        final SignedInfo si = fac.newSignedInfo(
    		fac.newCanonicalizationMethod(
				CanonicalizationMethod.INCLUSIVE,
                (C14NMethodParameterSpec) null
            ),
			fac.newSignatureMethod(
				SignatureMethod.RSA_SHA256,
				null
			),
			Collections.singletonList(ref)
		);

        final XMLObject obj = fac.newXMLObject(Collections.singletonList(content), "object", null, null); //$NON-NLS-1$

        // KeyInfo

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
        kpg.initialize(512);
        final KeyPair kp = kpg.generateKeyPair();

        final KeyInfoFactory kif = fac.getKeyInfoFactory();
        final KeyValue kv = kif.newKeyValue(kp.getPublic());

        final KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

        // SignContext

        final DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), doc);

        // Signature

        final XMLSignature signature = fac.newXMLSignature(si, ki, Collections.singletonList(obj), null, null);
        signature.sign(dsc);

        // Output

        final TransformerFactory tf = TransformerFactory.newInstance();
        final Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(System.out));
    }
}
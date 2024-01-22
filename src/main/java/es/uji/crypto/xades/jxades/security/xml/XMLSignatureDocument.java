package es.uji.crypto.xades.jxades.security.xml;

import java.io.File;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.uji.crypto.xades.jxades.security.xml.XAdES.XMLAdvancedSignature;

/**
 *
 * @author miro
 */
public class XMLSignatureDocument
{
    private final Element baseElement;
    private XMLSignatureFactory xmlSignatureFactory;
    private DigestMethod digestMethod;

    private XmlWrappedKeyInfo wrappedKeyInfo = XmlWrappedKeyInfo.CERTIFICATE;

    private List<SignatureProperties> listOfSignatureProperties = new ArrayList<>();
    private final List<SignatureProperty> defaultSignatureProperties = new ArrayList<>();
    private String defaultSignaturePropertiesId;

    private final List<XMLObject> xmlObjects = new ArrayList<>();
    private final List<XMLStructure> defaultXMLObjectItems = new ArrayList<>();
    private String defaultXMLObjectId;
    private String defaultXMLObjectMimeType;
    private String defaultXMLObjectEncoding;

    public XMLSignatureDocument(final Element baseElement)
    {
        if(baseElement == null)
        {
            throw new IllegalArgumentException("Root/Base XML Element can not be NULL"); //$NON-NLS-1$
        }

        this.baseElement = baseElement;
    }

    public Element getBaseElement()
    {
        return this.baseElement;
    }

    protected XMLSignatureFactory getXMLSignatureFactory()
    {
        if(this.xmlSignatureFactory == null)
        {
            this.xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM"); //$NON-NLS-1$
        }
        return this.xmlSignatureFactory;
    }

    public DigestMethod getDigestMethod()
        throws GeneralSecurityException
    {
        if(this.digestMethod == null)
        {
            this.digestMethod = getXMLSignatureFactory().newDigestMethod(DigestMethod.SHA256, null);
        }
        return this.digestMethod;
    }

    public void setDigestMethod(final DigestMethod digestMethod)
    {
        this.digestMethod = digestMethod;
    }

    public List<XMLSignatureElement> getXMLSignatureElements()
    {
        final NodeList nl = this.baseElement.getElementsByTagNameNS(XMLSignature.XMLNS,
                                                         XMLAdvancedSignature.ELEMENT_SIGNATURE);
        final int size = nl.getLength();
        final ArrayList<XMLSignatureElement> signatureElements = new ArrayList<>(size);
        for(int i = 0; i < size; i++)
        {
            signatureElements.add(new XMLSignatureElement((Element)nl.item(i)));
        }

        return signatureElements;
    }

    public XmlWrappedKeyInfo getXmlWrappedKeyInfo()
    {
        return this.wrappedKeyInfo;
    }

    public void setXmlWrappedKeyInfo(final XmlWrappedKeyInfo wrappedKeyInfo)
    {
        this.wrappedKeyInfo = wrappedKeyInfo;
    }

    public WrappedKeyStorePlace getWrappedKeyStorePlace()
    {
        return WrappedKeyStorePlace.KEY_INFO;
    }

    public void setWrappedKeyStorePlace(final WrappedKeyStorePlace wrappedKeyStorePlace)
    {
    }

    protected Reference getReference(final String uri)
        throws GeneralSecurityException
    {
        return getReference(uri, null);
    }

    protected Reference getReference(final String uri, final String type)
        throws GeneralSecurityException
    {
        return getReference(uri, null, type, null);
    }

    protected Reference getReference(final String uri,
                                     final List transforms,
                                     final String type)
        throws GeneralSecurityException
    {
        return getReference(uri, transforms, type, null);
    }

    protected Reference getReference(String uri,
                                     final List transforms,
                                     final String type,
                                     final String referenceId)
        throws GeneralSecurityException
    {
        final XMLSignatureFactory fac = getXMLSignatureFactory();
        final DigestMethod dm = getDigestMethod();
        uri = uri.trim();
        if(!uri.startsWith("#")) { //$NON-NLS-1$
			uri = "#" + uri; //$NON-NLS-1$
		}
        return fac.newReference(uri, dm, transforms, type, referenceId);
    }

    protected List<Reference> getReferences(final List idList)
        throws GeneralSecurityException
    {
        final ArrayList<Reference> references = new ArrayList<>(idList.size());
        for(final Object id : idList)
        {
            if(id instanceof Reference) {
				references.add((Reference)id);
			} else
            {
                references.add(getReference((String)id));
            }
        }

        return references;
    }

    public List<SignatureStatus> validate()
    {
        ArrayList<SignatureStatus> validateResult;
        final List<XMLSignatureElement> signatureElements = getXMLSignatureElements();
        validateResult = new ArrayList<>(signatureElements.size());
        for(final XMLSignatureElement signatureElement : signatureElements)
        {
            validateResult.add(signatureElement.validate());
        }

        return validateResult;
    }

    public void sign(final X509Certificate certificate,
                     final PrivateKey privateKey,
                     final String signatureMethod,
                     final List referencesIdList,
                     final String signatureIdPrefix,
                     final String xadesPrefix,
                     final String xadesNamespace,
                     final String xmlSignaturePrefix)
        throws MarshalException,
               XMLSignatureException,
               GeneralSecurityException
    {
        final String signatureId = getSignatureId(signatureIdPrefix);
        final String signatureValueId = getSignatureValueId(signatureIdPrefix);

        final XMLSignatureFactory fac = getXMLSignatureFactory();
        final CanonicalizationMethod cm = fac.newCanonicalizationMethod(
            CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
            (C14NMethodParameterSpec)null);

        final List<Reference> documentReferences = getReferences(referencesIdList);
        final String keyInfoId = getKeyInfoId(signatureIdPrefix);
        documentReferences.add(fac.newReference("#" + keyInfoId, getDigestMethod())); //$NON-NLS-1$

        final SignatureMethod sm = fac.newSignatureMethod(signatureMethod, null);
        final SignedInfo si = fac.newSignedInfo(cm, sm, documentReferences);

        final XMLSignature signature = fac.newXMLSignature(si,
                                                     newKeyInfo(certificate, keyInfoId),
                                                     getXMLObjects(),
                                                     signatureId,
                                                     signatureValueId);

        final DOMSignContext signContext = new DOMSignContext(privateKey, this.baseElement);
        signContext.putNamespacePrefix(XMLSignature.XMLNS, xmlSignaturePrefix);
        signContext.putNamespacePrefix(xadesNamespace, xadesPrefix);

        signature.sign(signContext);
    }

    protected String getSignatureId(final String idPrefix)
    {
        return idPrefix + "-Signature"; //$NON-NLS-1$
    }

    protected String getSignatureValueId(final String idPrefix)
    {
        return idPrefix + "-SignatureValue"; //$NON-NLS-1$
    }

    protected String getKeyInfoId(final String idPrefix)
    {
        return idPrefix + "-KeyInfo"; //$NON-NLS-1$
    }

    public KeyInfo newKeyInfo(final X509Certificate certificate, final String keyInfoId)
        throws KeyException
    {
        final KeyInfoFactory kif = getXMLSignatureFactory().getKeyInfoFactory();
        if(XmlWrappedKeyInfo.PUBLIC_KEY.equals(getXmlWrappedKeyInfo()))
        {
            final KeyValue kv = kif.newKeyValue(certificate.getPublicKey());
            return kif.newKeyInfo(Collections.singletonList(kv), keyInfoId);
        }
		final X509Data certData = kif.newX509Data(Collections.singletonList(certificate));
		return kif.newKeyInfo(Collections.singletonList(certData), keyInfoId);
    }

    public List<SignatureProperties> getListOfSignatureProperties()
    {
        this.listOfSignatureProperties.add(getDefaultSignatureProperties());
        return this.listOfSignatureProperties;
    }

    public void setListOfSignatureProperties(final List<SignatureProperties> listOfSignatureProperties)
    {
        this.listOfSignatureProperties = listOfSignatureProperties;
    }

    public void addSignatureProperty(final SignatureProperty signatureProperty)
    {
        this.defaultSignatureProperties.add(signatureProperty);
    }

    public void addSignatureProperty(final List<DOMStructure> content,
                                     final String target,
                                     final String id)
    {
        final XMLSignatureFactory fac = getXMLSignatureFactory();
        addSignatureProperty(fac.newSignatureProperty(content, target, id));
    }

    public SignatureProperties getDefaultSignatureProperties()
    {
        final XMLSignatureFactory fac = getXMLSignatureFactory();
        return fac.newSignatureProperties(this.defaultSignatureProperties, this.defaultSignaturePropertiesId);
    }

    public void setDefaultSignaturePropertiesId(final String id)
    {
        this.defaultSignaturePropertiesId = id;
    }

    public String getDefaultSignaturePropertiesId()
    {
        return this.defaultSignaturePropertiesId;
    }

    public XMLObject newXMLObject(final List<XMLStructure> xmlObjects)
    {
        return newXMLObject(xmlObjects, getDefaultXMLObjectId());
    }

    public XMLObject newXMLObject(final List<XMLStructure> xmlObjects, final String id)
    {
        return newXMLObject(xmlObjects, id, getDefaultXMLObjectMimeType());
    }

    public XMLObject newXMLObject(final List<XMLStructure> xmlObjects, final String id, final String mimeType)
    {
        return newXMLObject(xmlObjects, id, mimeType, getDefaultXMLObjectEncoding());
    }

    public XMLObject newXMLObject(final List<XMLStructure> xmlObjects,
                                  final String id,
                                  final String mimeType,
                                  final String encoding)
    {
        final XMLSignatureFactory fac = getXMLSignatureFactory();
        return fac.newXMLObject(xmlObjects, id, mimeType, encoding);
    }

    public XMLObject addXMLObject(final List<XMLStructure> xmlObjects)
    {
        final XMLSignatureFactory fac = getXMLSignatureFactory();
        return addXMLObject(fac.newXMLObject(xmlObjects,
                            getDefaultXMLObjectId(),
                            getDefaultXMLObjectMimeType(),
                            getDefaultXMLObjectEncoding()));
    }

    public XMLObject addXMLObject(final XMLObject xmlObject)
    {
        this.xmlObjects.add(xmlObject);
        return xmlObject;
    }

    public List<XMLObject> getXMLObjects()
    {
        return this.xmlObjects;
    }

    public void addXMLObjectItem(final XMLStructure xmlObjectItem)
    {
        this.defaultXMLObjectItems.add(xmlObjectItem);
    }

    public XMLObject getDefaultXMLObject()
    {
        final XMLSignatureFactory fac = getXMLSignatureFactory();
        return fac.newXMLObject(getXMLObjectItems(),
                                getDefaultXMLObjectId(),
                                getDefaultXMLObjectMimeType(),
                                getDefaultXMLObjectEncoding());
    }

    public List<XMLStructure> getXMLObjectItems()
    {
        return this.defaultXMLObjectItems;
    }

    public void setDefaultXMLObjectId(final String defaultXMLObjectId)
    {
        this.defaultXMLObjectId = defaultXMLObjectId;
    }

    public String getDefaultXMLObjectId()
    {
        return this.defaultXMLObjectId;
    }

    public void setDefaultXMLObjectMimeType(final String defaultXMLObjectMimeType)
    {
        this.defaultXMLObjectMimeType = defaultXMLObjectMimeType;
    }

    public String getDefaultXMLObjectMimeType()
    {
        return this.defaultXMLObjectMimeType;
    }

    public void setDefaultXMLObjectEncoding(final String defaultXMLObjectEncoding)
    {
        this.defaultXMLObjectEncoding = defaultXMLObjectEncoding;
    }

    public String getDefaultXMLObjectEncoding()
    {
        return this.defaultXMLObjectEncoding;
    }

    private static Document loadEncryptionDocument()
        throws Exception
    {
        final String fileName = "BluesRecorderPro.log.wse"; //$NON-NLS-1$
        final File encryptionFile = new File(fileName);
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        final DocumentBuilder db = dbf.newDocumentBuilder();
        final Document document = db.parse(encryptionFile);
        System.out.println("Encryption document loaded from " + //$NON-NLS-1$
            encryptionFile.toString());
        return document;
    }

    public static void printDocument(final Node node)
        throws TransformerException
    {
        final OutputStream os = System.out;
        final TransformerFactory tf = TransformerFactory.newInstance();
        final Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(node), new StreamResult(os));
    }
}

package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.uji.crypto.xades.jxades.security.xml.SignatureStatus;
import es.uji.crypto.xades.jxades.security.xml.WrappedKeyStorePlace;
import es.uji.crypto.xades.jxades.security.xml.XMLSignatureElement;
import es.uji.crypto.xades.jxades.security.xml.XmlWrappedKeyInfo;

/**
 *
 * @author miro
 */
public class XMLAdvancedSignature {

    public static final String XADES_v132 = "http://uri.etsi.org/01903/v1.3.2#"; //$NON-NLS-1$
    public static final String XADES_v141 = "http://uri.etsi.org/01903/v1.4.1#"; //$NON-NLS-1$

    public String signedPropertiesTypeUrl = "http://uri.etsi.org/01903#SignedProperties"; //$NON-NLS-1$

    public static final String ELEMENT_SIGNATURE = "Signature"; //$NON-NLS-1$
    public static final String ELEMENT_SIGNATURE_VALUE = "SignatureValue"; //$NON-NLS-1$

    protected BaseXAdESImpl xades;
    protected Element baseElement;
    protected XMLSignatureFactory xmlSignatureFactory;
    protected DigestMethod digestMethod;
    protected String xadesNamespace;
    protected XmlWrappedKeyInfo wrappedKeyInfo = XmlWrappedKeyInfo.CERTIFICATE;

    protected List<XMLObject> xmlObjects = new ArrayList<>();

    protected List<XMLStructure> defaultXMLObjectItems = new ArrayList<>();
    protected String defaultXMLObjectId;
    protected String defaultXMLObjectMimeType;
    protected String defaultXMLObjectEncoding;

    protected XMLSignature signature;
    protected DOMSignContext signContext;

    protected XMLAdvancedSignature(final XAdESBase xades) {
        if (xades == null) {
            throw new IllegalArgumentException("XAdES parameter can not be NULL."); //$NON-NLS-1$
        }
        this.baseElement = xades.getBaseElement();
        this.xades = (BaseXAdESImpl) xades;
    }

    public static XMLAdvancedSignature newInstance(final XAdESBase xades) throws GeneralSecurityException {
        final XMLAdvancedSignature result = new XMLAdvancedSignature(xades);
        result.setDigestMethod(xades.getDigestMethod());
        result.setXadesNamespace(xades.getXadesNamespace());
        return result;
    }

    public static XMLAdvancedSignature getInstance(final XAdESBase xades) throws GeneralSecurityException {
        return newInstance(xades);
    }

    public Element getBaseElement() {
        return this.baseElement;
    }

    public Document getBaseDocument() {
        return this.xades.getBaseDocument();
    }

    public void setXadesNamespace(final String xadesNamespace) {
        this.xadesNamespace = xadesNamespace;
    }

    public void setSignedPropertiesTypeUrl(final String signedPropertiesTypeUrl) {
        this.signedPropertiesTypeUrl = signedPropertiesTypeUrl;
    }

    public void sign(final X509Certificate signingCert,
    		         final PrivateKey privateKey,
    		         final String signatureMethod,
    		         final List<Object> refsIdList,
    		         final String signatureIdPrefix) throws MarshalException,
                                                            XMLSignatureException,
                                                            GeneralSecurityException {
    	sign(
			signingCert,
			privateKey,
			signatureMethod,
			refsIdList,
			signatureIdPrefix,
			null
		);
    }

    public void sign(final X509Certificate certificate,
    		         final PrivateKey privateKey,
    		         final String signatureMethod,
    		         final List<Object> refsIdList,
    		         final String signatureIdPrefix,
    		         final SigningCertificateInfo signingCertInfo) throws MarshalException,
                                                                          XMLSignatureException,
                                                                          GeneralSecurityException {
        final List<Object> referencesIdList = new ArrayList<>(refsIdList);

        if (WrappedKeyStorePlace.SIGNING_CERTIFICATE_PROPERTY.equals(getWrappedKeyStorePlace())) {
        	if (this.xades instanceof XadesWithBasicAttributes) {
        		((XadesWithBasicAttributes) this.xades).setSigningCertificate(certificate);
        	}
        	else if (this.xades instanceof XadesWithBaselineAttributes) {
        		final SigningCertificateV2Info certInfo = (SigningCertificateV2Info) signingCertInfo;
        		((XadesWithBaselineAttributes) this.xades).setSigningCertificateV2(certificate, certInfo);
        	}
        	else {
        		throw new XMLSignatureException("Unsupported signature profile"); //$NON-NLS-1$
        	}
        }
        else {
            /*
             * @ToDo The ds:KeyInfo element also MAY contain other certificates forming a chain that
             * MAY reach the point of trust;
             */
        }

        final XMLObject xadesObject = marshalXMLSignature(
    		this.xadesNamespace,
            this.signedPropertiesTypeUrl,
            signatureIdPrefix,
            referencesIdList
        );
        addXMLObject(xadesObject);

        final String signatureId = getSignatureId(signatureIdPrefix);
        final String signatureValueId = getSignatureValueId(signatureIdPrefix);

        final XMLSignatureFactory fac = getXMLSignatureFactory();
        final CanonicalizationMethod cm = fac.newCanonicalizationMethod(
    		CanonicalizationMethod.INCLUSIVE,
            (C14NMethodParameterSpec) null
        );

        final List<Reference> documentReferences = getReferences(referencesIdList);
        final String keyInfoId = getKeyInfoId(signatureIdPrefix);
        documentReferences.add(fac.newReference("#" + keyInfoId, getDigestMethod())); //$NON-NLS-1$

        final SignatureMethod sm = fac.newSignatureMethod(signatureMethod, null);
        final SignedInfo si = fac.newSignedInfo(cm, sm, documentReferences);

        this.signature = fac.newXMLSignature(si, newKeyInfo(certificate, keyInfoId),
                getXMLObjects(), signatureId, signatureValueId);

        if (this.baseElement != null) {
            this.signContext = new DOMSignContext(privateKey, getBaseElement());
        }
        else {
            this.signContext = new DOMSignContext(privateKey, getBaseDocument());
        }

        this.signContext.putNamespacePrefix(XMLSignature.XMLNS, this.xades.getXmlSignaturePrefix());
        this.signContext.putNamespacePrefix(this.xadesNamespace, this.xades.getXadesPrefix());

        this.signature.sign(this.signContext);
    }

    public List<SignatureStatus> validate() {
        ArrayList<SignatureStatus> validateResult;
        final List<XMLSignatureElement> signatureElements = getXMLSignatureElements();
        validateResult = new ArrayList<>(signatureElements.size());
        for (final XMLSignatureElement signatureElement : signatureElements) {
            validateResult.add(signatureElement.validate());
        }
        return validateResult;
    }

    public static WrappedKeyStorePlace getWrappedKeyStorePlace() {
        return WrappedKeyStorePlace.KEY_INFO;
    }

    public void setWrappedKeyStorePlace(final WrappedKeyStorePlace wrappedKeyStorePlace) {
    	// Vacio
    }

    public XmlWrappedKeyInfo getXmlWrappedKeyInfo() {
        return this.wrappedKeyInfo;
    }

    public List<XMLObject> getXMLObjects() {
        return this.xmlObjects;
    }

    public void setXmlWrappedKeyInfo(final XmlWrappedKeyInfo wrappedKeyInfo) {
        this.wrappedKeyInfo = wrappedKeyInfo;
    }

    protected List<XMLSignatureElement> getXMLSignatureElements() {

        final NodeList nl;
        if (this.baseElement != null) {
            nl = getBaseElement().getElementsByTagNameNS(
        		XMLSignature.XMLNS, ELEMENT_SIGNATURE
    		);
        }
        else {
            nl = getBaseDocument().getElementsByTagNameNS(XMLSignature.XMLNS,
                    ELEMENT_SIGNATURE);
        }

        final int size = nl.getLength();
        final ArrayList<XMLSignatureElement> signatureElements = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            signatureElements.add(new XMLSignatureElement((Element) nl.item(i)));
        }

        return signatureElements;
    }

    protected String getSignatureId(final String idPrefix) {
        return idPrefix + "-Signature"; //$NON-NLS-1$
    }

    protected String getSignatureValueId(final String idPrefix) {
        return idPrefix + "-SignatureValue"; //$NON-NLS-1$
    }

    protected String getKeyInfoId(final String idPrefix) {
        return idPrefix + "-KeyInfo"; //$NON-NLS-1$
    }

    protected XMLSignatureFactory getXMLSignatureFactory() {
        if (this.xmlSignatureFactory == null) {
            this.xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM"); //$NON-NLS-1$
        }
        return this.xmlSignatureFactory;
    }

    protected Reference getReference(final String uri) throws GeneralSecurityException {
        return getReference(uri, null);
    }

    protected Reference getReference(final String uri, final String type) throws GeneralSecurityException {
        return getReference(uri, null, type, null);
    }

    protected Reference getReference(final String uri, final List<Transform> transforms, final String type) throws GeneralSecurityException {
        return getReference(uri, transforms, type, null);
    }

    protected Reference getReference(String uri,
    		                         List<Transform> transforms,
    		                         final String type,
    		                         final String referenceId) throws GeneralSecurityException {

        final XMLSignatureFactory fac = getXMLSignatureFactory();
        final DigestMethod dm = getDigestMethod();
        uri = uri.trim();

        if (uri.isEmpty()) {
            final Transform envelopedTransform = fac.newTransform(
        		Transform.ENVELOPED,
                (TransformParameterSpec) null
            );

            if (transforms != null) {
                transforms.add(envelopedTransform);
            }
            else {
                transforms = Collections.singletonList(envelopedTransform);
            }
        }
        else if (!uri.startsWith("#") && !uri.startsWith("http://") && !uri.startsWith("https://")) { //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            uri = "#" + uri; //$NON-NLS-1$
        }

        return fac.newReference(uri, dm, transforms, type, referenceId);
    }

    protected List<Reference> getReferences(final List<?> idList) throws GeneralSecurityException {
        final ArrayList<Reference> references = new ArrayList<>(idList.size());

        for (final Object id : idList) {
            if (id instanceof Reference) {
                references.add((Reference) id);
            }
            else {
                references.add(getReference((String) id));
            }
        }

        return references;
    }

    protected DigestMethod getDigestMethod() throws GeneralSecurityException {
        if (this.digestMethod == null) {
            this.digestMethod = getXMLSignatureFactory().newDigestMethod(DigestMethod.SHA256, null);
        }
        return this.digestMethod;
    }

    public void setDigestMethod(final String method) throws GeneralSecurityException {
        this.digestMethod = getXMLSignatureFactory().newDigestMethod(method, null);
        if (this.xades instanceof BLevelXAdESImpl) {
        	this.xades.setDigestMethod(method);
        }
    }

    protected KeyInfo newKeyInfo(final X509Certificate certificate, final String keyInfoId) throws KeyException
    {
        final KeyInfoFactory keyInfoFactory = getXMLSignatureFactory().getKeyInfoFactory();
        final KeyValue keyValue = keyInfoFactory.newKeyValue(certificate.getPublicKey());

        final List<Object> x509DataList = new ArrayList<>();

        if (!XmlWrappedKeyInfo.PUBLIC_KEY.equals(getXmlWrappedKeyInfo())) {
            x509DataList.add(certificate);
        }

        final X509IssuerSerial x509IssuerSerial = keyInfoFactory.newX509IssuerSerial(
    		certificate.getIssuerDN().getName(),
    		certificate.getSerialNumber()
		);

        x509DataList.add(certificate.getSubjectX500Principal().getName("RFC1779")); //$NON-NLS-1$
        x509DataList.add(x509IssuerSerial);

        final X509Data x509Data = keyInfoFactory.newX509Data(x509DataList);

        final List<XMLStructure> newList = new ArrayList<>();
        newList.add(keyValue);
        newList.add(x509Data);

        return keyInfoFactory.newKeyInfo(newList, keyInfoId);
    }

    protected XMLObject newXMLObject(final List<XMLStructure> xmlObjects) {
        return newXMLObject(xmlObjects, getDefaultXMLObjectId());
    }

    protected XMLObject newXMLObject(final List<XMLStructure> xmlObjects, final String id) {
        return newXMLObject(xmlObjects, id, getDefaultXMLObjectMimeType());
    }

    protected XMLObject newXMLObject(final List<XMLStructure> xmlObjects, final String id, final String mimeType) {
        return newXMLObject(xmlObjects, id, mimeType, getDefaultXMLObjectEncoding());
    }

    protected XMLObject newXMLObject(final List<XMLStructure> xmlObjects, final String id, final String mimeType, final String encoding) {
        final XMLSignatureFactory fac = getXMLSignatureFactory();
        return fac.newXMLObject(xmlObjects, id, mimeType, encoding);
    }

    protected String getDefaultXMLObjectId(){
        return this.defaultXMLObjectId;
    }

    protected String getDefaultXMLObjectMimeType() {
        return this.defaultXMLObjectMimeType;
    }

    protected String getDefaultXMLObjectEncoding() {
        return this.defaultXMLObjectEncoding;
    }

    public XMLObject addXMLObject(final XMLObject xmlObject) {
        this.xmlObjects.add(xmlObject);
        return xmlObject;
    }

    private List<QualifyingPropertiesReference> qualifyingPropertiesReferences;

    protected QualifyingProperties marshalQualifyingProperties(final String xmlNamespace,
    		                                                   final String signedPropertiesTypeUrl1,
    		                                                   final String signatureIdPrefix,
    		                                                   final List<Object> referencesIdList) throws GeneralSecurityException,
                                                                                                   MarshalException {
    	return marshalQualifyingProperties(
			xmlNamespace,
			signedPropertiesTypeUrl1,
			signatureIdPrefix,
			referencesIdList,
			null
		);
    }

    protected QualifyingProperties marshalQualifyingProperties(final String xmlNamespace,
                                                               final String signedPropertiesTypeUrl,
                                                               final String signatureIdPrefix,
                                                               final List<Object> referencesIdList,
                                                               final List<Transform> transforms) throws GeneralSecurityException,
                                                                                                   MarshalException {
        final QualifyingProperties qp = new QualifyingProperties(
    		this.xades.getBaseDocument(),
    		getBaseElement(),
            signatureIdPrefix,
            this.xades.getXadesPrefix(),
            xmlNamespace,
            this.xades.getXmlSignaturePrefix()
        );

        this.xades.marshalQualifyingProperties(qp, signatureIdPrefix, referencesIdList);

        final SignedProperties sp = qp.getSignedProperties();

        final String spId = sp.getId();
        final Reference spReference = getReference(
    		spId,
    		transforms,
    		this.signedPropertiesTypeUrl
		);
        referencesIdList.add(spReference);

        return qp;
    }

    protected XMLObject marshalXMLSignature(final String xadesNamespace,
                                            final String signedPropertiesTypeUrl,
                                            final String signatureIdPrefix,
                                            final List<Object> referencesIdList) throws GeneralSecurityException,
                                                                                MarshalException {
    	return marshalXMLSignature(
			xadesNamespace,
			signedPropertiesTypeUrl,
			signatureIdPrefix,
			referencesIdList,
			null
		);
    }

    protected XMLObject marshalXMLSignature(final String xadesNamespace,
    		                                final String signedPropertiesTypeUrl,
                                            final String signatureIdPrefix,
                                            final List<Object> referencesIdList,
                                            final List<Transform> SignedPropertiesTransforms) throws GeneralSecurityException,
                                                                                                     MarshalException {
        final QualifyingProperties qp = marshalQualifyingProperties(
    		xadesNamespace,
    		signedPropertiesTypeUrl,
            signatureIdPrefix,
            referencesIdList,
            SignedPropertiesTransforms
        );

        final List<QualifyingPropertiesReference> qpr = getQualifyingPropertiesReferences();
        final ArrayList<XMLStructure> content = new ArrayList<>(qpr.size() + 1);
        content.add(qp);
        content.addAll(qpr);

        return newXMLObject(content);
    }

    public List<QualifyingPropertiesReference> getQualifyingPropertiesReferences() {
        if (this.qualifyingPropertiesReferences == null) {
            this.qualifyingPropertiesReferences = new ArrayList<>();
        }
        return this.qualifyingPropertiesReferences;
    }

    public void setQualifyingPropertiesReferences(final List<QualifyingPropertiesReference> refs) {
        this.qualifyingPropertiesReferences = refs;
    }
}

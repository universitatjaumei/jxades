package es.uji.crypto.xades.jxades.security.xml.XAdES;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import es.uji.crypto.xades.jxades.util.ObjectId;
import es.uji.crypto.xades.jxades.util.OccursRequirement;

/**
 * Xml Advanced Electronic Signature (XAdES) profiles are
 * defined in:
 * <ul>
 *   <li>ETSI TS 101 903 V1.3.2 (2006-03)</li>
 *   <li>ETSI EN 319 132-1 V1.1.1 (2016-04)</li>
 * </ul>
 *
 * Similar/related projects/standards:
 * - RFC3126 (http://www.ietf.org/rfc/rfc3126.txt,
 *            http://www.faqs.org/rfcs/rfc3126.html,
 *            http://rfc.net/rfc3126.html
 * - http://www.oasis-open.org/
 **/

/**
 *
 * @author miro
 */
public enum XAdES {
    /**
     * 4.4 Electronic signature forms The current clause specifies four forms of XML advanced
     * electronic signatures, namely the Basic Electronic Signature (XAdES-BES), the Explicit Policy
     * based Electronic Signature (XAdES-EPES), and the Electronic Signature with Validation Data
     * (XAdES-T and XAdES-C). Conformance to the present document mandates the signer to create one
     * of these formats. The informative annex B defines extended forms of XAdES. Conformance to the
     * present document does not mandate the signer to create any of the forms defined in annex B.
     **/
    BES("XAdES-BES", "4.4.1", "Basic Electronic Signature"), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    EPES("XAdES-EPES", "4.4.2", "Explicit Policy Electronic Signatures"), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    T("XAdES-T", "4.4.3.1", "Electronic Signature with Time"), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    C("XAdES-C", "4.4.3.2", "Electronic Signature with Complete Validation Data References"), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

    /**
     * 4.5 Validation process The Validation Process validates an electronic signature, the output
     * status of the validation process can be: - invalid; - incomplete validation; - valid. An
     * Invalid response indicates that either the signature format is incorrect or that the digital
     * signature value fails verification (e.g. the integrity check on the digital signature value
     * fails or any of the certificates on which the digital signature verification depends is known
     * to be invalid or revoked). An Incomplete Validation response indicates that the format and
     * digital signature verifications have not failed but there is insufficient information to
     * determine if the electronic signature is valid. For example; all the required certificates
     * are not available or the grace period is not completed. In the case of Incomplete Validation,
     * the electronic signature may be checked again at some later time when additional validation
     * information becomes available. Also, in the case of incomplete validation, additional
     * information may be made available to the application or user, thus allowing the application
     * or user to decide what to do with partially correct electronic signatures. A Valid response
     * indicates that the signature has passed verification and it complies with the signature
     * validation policy. Informative annex G gives details on technical rules that verifiers should
     * follow for verifying XAdES signatures.
     *
     * 4.6 Arbitration In case of arbitration, a XAdES-C form provides reliable evidence for a valid
     * electronic signature, provided that: - the arbitrator knows where to retrieve the signer's
     * certificate (if not already present), all the required certificates and CRLs, ACRLs or OCSP
     * responses referenced in the XAdES-C; - when time-stamping in the XAdES-T is being used, the
     * certificate from the TSU that has issued the time-stamp token in the XAdES-T format is still
     * within its validity period; - when time-stamping in the XAdES-T is being used, the
     * certificate from the TSU that has issued the time-stamp token in the XAdES-T format is not
     * revoked at the time of arbitration; - when time-marking in the XAdES-T is being used, a
     * reliable audit trail from the Time-Marking Authority is available for examination regarding
     * the time; - none of the private keys corresponding to the certificates used to verify the
     * signature chain have ever been compromised; - the cryptography used at the time the XAdES-C
     * was built has not been broken at the time the arbitration is performed. If the signature
     * policy can be explicitly or implicitly identified then an arbitrator is able to determine the
     * rules required to validate the electronic signature.
     *
     * Annex B (informative): Extended electronic signature forms The XAdES forms specified in
     * clause 4.4 can be extended by addition of certain unsigned properties that are defined in the
     * present document. These properties are applicable for very long term verification, and for
     * preventing some disaster situations which have been identified in the normative part of the
     * present document. The clauses below give an overview of the various forms of extended
     * signature formats in the present document.
     **/
    X("XAdES-X", "B.1", "Extended Signatures with Time Forms"), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    X_L("XAdES-X-L", "B.2", "Extended Long Electronic Signatures with Time"), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    A("XAdES-A", "B.3", "Archival Electronic Signatures"), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

    /**
     * ETSI EN 319 132-1 V1.1.1 6.3<br>
     * <br>
     * 6.1 Signature levels<br>
     * Clause 6 defines four levels of XAdES baseline signatures, intended to facilitate interoperability and to encompass the
     * life cycle of XAdES signature, namely:<br>
     * <ol>
     * <li>B-B level provides requirements for the incorporation of signed and some unsigned qualifying properties when
     * the signature is generated.</li>
     * <li>B-T level provides requirements for the generation and inclusion, for an existing signature, of a trusted token
     * proving that the signature itself actually existed at a certain date and time.</li>
     * <li>B-LT level provides requirements for the incorporation of all the material required for validating the signature
     * in the signature document. This level aims to tackle the long term availability of the validation material.</li>
     * <li>B-LTA level provides requirements for the incorporation of electronic time-stamps that allow validation of the
     * signature long time after its generation. This level aims to tackle the long term availability and integrity of the
     * validation material.</li>
     * </ol>
     */
    B_LEVEL("B-B-LEVEL", "ETSI EN 319 132-1 V1.1.1 6.3", "XAdES BASELINE B-LEVEL"), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
	T_LEVEL("B-T-LEVEL", "ETSI EN 319 132-1 V1.1.1 6.3", "XAdES BASELINE T-LEVEL"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

    XAdES(final String nickname, final String contentsId, final String title)
    {
        this.nickname = nickname;
        this.contentsId = contentsId;
        this.title = title;
    }

    private String nickname;
    private String contentsId;
    private String title;

    public String getNickname()
    {
        return this.nickname;
    }

    public String getContentsId()
    {
        return this.contentsId;
    }

    public String getTitle()
    {
        return this.title;
    }

    public enum Element implements XadesElement
    {
        OBJECT(null, "Object"), //$NON-NLS-1$
        QUALIFYING_PROPERTIES(OBJECT, "QualifyingProperties"), //$NON-NLS-1$
        SIGNED_PROPERTIES(QUALIFYING_PROPERTIES, "SignedProperties"), //$NON-NLS-1$
        SIGNED_SIGNATURE_PROPERTIES(SIGNED_PROPERTIES, "SignedSignatureProperties"), //$NON-NLS-1$
        SIGNING_TIME(new XAdES[] {XAdES.BES, XAdES.B_LEVEL}, SIGNED_SIGNATURE_PROPERTIES, "SigningTime", OccursRequirement.ZERO_OR_ONE), //$NON-NLS-1$
        SIGNING_CERTIFICATE(XAdES.BES, SIGNED_SIGNATURE_PROPERTIES, "SigningCertificate", OccursRequirement.ZERO_OR_ONE), //$NON-NLS-1$
        SIGNATURE_POLICY_IDENTIFIER(new XAdES[] {XAdES.EPES, XAdES.B_LEVEL}, SIGNED_SIGNATURE_PROPERTIES, "SignaturePolicyIdentifier", OccursRequirement.EXACTLY_ONE), //$NON-NLS-1$
        SIGNATURE_PRODUCTION_PLACE(XAdES.BES, SIGNED_SIGNATURE_PROPERTIES, "SignatureProductionPlace", OccursRequirement.ZERO_OR_ONE), //$NON-NLS-1$
        SIGNER_ROLE(XAdES.BES, SIGNED_SIGNATURE_PROPERTIES, "SignerRole", OccursRequirement.ZERO_OR_ONE), //$NON-NLS-1$
        CLAIMED_ROLES(new XAdES[] {XAdES.BES, XAdES.B_LEVEL}, SIGNER_ROLE, "ClaimedRoles", OccursRequirement.ZERO_OR_MORE), //$NON-NLS-1$
        CERTIFIED_ROLES(XAdES.BES, SIGNER_ROLE, "CertifiedRoles", OccursRequirement.ZERO_OR_MORE), //$NON-NLS-1$
        SIGNER(new XAdES[] {XAdES.BES, XAdES.B_LEVEL}, SIGNED_SIGNATURE_PROPERTIES, "Signer", OccursRequirement.ZERO_OR_ONE), //$NON-NLS-1$
        SIGNER_DETAILS(new XAdES[] {XAdES.BES, XAdES.B_LEVEL}, SIGNED_SIGNATURE_PROPERTIES, "SignerDetails", OccursRequirement.ZERO_OR_ONE), //$NON-NLS-1$
        SIGNED_DATA_OBJECT_PROPERTIES(SIGNED_PROPERTIES, "SignedDataObjectProperties"), //$NON-NLS-1$
        DATA_OBJECT_FORMATS(new XAdES[] {XAdES.BES, XAdES.B_LEVEL}, SIGNED_DATA_OBJECT_PROPERTIES, "DataObjectFormat", OccursRequirement.ZERO_OR_MORE), //$NON-NLS-1$
        COMMITMENT_TYPE_INDICATIONS(new XAdES[] {XAdES.BES, XAdES.B_LEVEL}, SIGNED_DATA_OBJECT_PROPERTIES, "CommitmentTypeIndication", OccursRequirement.ZERO_OR_MORE), //$NON-NLS-1$
        ALL_DATA_OBJECTS_TIMESTAMPS(new XAdES[] {XAdES.BES, XAdES.B_LEVEL}, SIGNED_DATA_OBJECT_PROPERTIES, "AllDataObjectsTimeStamp", OccursRequirement.ZERO_OR_MORE), //$NON-NLS-1$
        INDIVIDUAL_DATA_OBJECTS_TIMESTAMPS(new XAdES[] {XAdES.BES, XAdES.B_LEVEL}, SIGNED_DATA_OBJECT_PROPERTIES, "IndividualDataObjectsTimeStamp", OccursRequirement.ZERO_OR_MORE), //$NON-NLS-1$
        UNSIGNED_PROPERTIES(QUALIFYING_PROPERTIES, "UnsignedProperties"), //$NON-NLS-1$
        UNSIGNED_SIGNATURE_PROPERTIES(UNSIGNED_PROPERTIES, "UnsignedSignatureProperties"), //$NON-NLS-1$
        COUNTER_SIGNATURES(new XAdES[] {XAdES.BES, XAdES.B_LEVEL}, UNSIGNED_SIGNATURE_PROPERTIES, "CounterSignature", OccursRequirement.ZERO_OR_MORE), //$NON-NLS-1$
        SIGNATURE_TIME_STAMP(new XAdES[] {XAdES.T, XAdES.T_LEVEL}, UNSIGNED_SIGNATURE_PROPERTIES, "SignatureTimeStamp", OccursRequirement.ONE_OR_MORE), //$NON-NLS-1$
        COMPLETE_CERTIFICATE_REFS(XAdES.C, UNSIGNED_SIGNATURE_PROPERTIES, "CompleteCertificateRefs", OccursRequirement.EXACTLY_ONE), //$NON-NLS-1$
        COMPLETE_REVOCATION_REFS(XAdES.C, UNSIGNED_SIGNATURE_PROPERTIES, "CompleteRevocationRefs", OccursRequirement.EXACTLY_ONE), //$NON-NLS-1$
        ATTRIBUTE_CERTIFICATE_REFS(XAdES.C, UNSIGNED_SIGNATURE_PROPERTIES, "AttributeCertificateRefs", OccursRequirement.ZERO_OR_ONE), //$NON-NLS-1$
        ATTRIBUTE_REVOCATION_REFS(XAdES.C, UNSIGNED_SIGNATURE_PROPERTIES, "CompleteCertificateRefs", OccursRequirement.ZERO_OR_ONE), //$NON-NLS-1$
        QUALIFYING_PROPERTIES_REFERENCE(OBJECT, "QualifyingPropertiesReference"), //$NON-NLS-1$

        /** XAdES Baseline attributes */
        SIGNING_CERTIFICATE_V2(XAdES.B_LEVEL, SIGNED_SIGNATURE_PROPERTIES, "SigningCertificateV2", OccursRequirement.EXACTLY_ONE), //$NON-NLS-1$
        SIGNATURE_PRODUCTION_PLACE_V2(XAdES.B_LEVEL, SIGNED_SIGNATURE_PROPERTIES, "SignatureProductionPlaceV2", OccursRequirement.ZERO_OR_ONE), //$NON-NLS-1$
        SIGNER_ROLE_V2(XAdES.B_LEVEL, SIGNED_SIGNATURE_PROPERTIES, "SignerRoleV2", OccursRequirement.ZERO_OR_ONE), //$NON-NLS-1$
    	CERTIFIED_ROLES_V2(XAdES.B_LEVEL, SIGNER_ROLE_V2, "CertifiedRolesV2", OccursRequirement.ZERO_OR_MORE), //$NON-NLS-1$
    	SIGNED_ASSERTIONS(XAdES.B_LEVEL, SIGNER_ROLE_V2, "SignedAssertions", OccursRequirement.ZERO_OR_MORE); //$NON-NLS-1$

        Element(final XadesElement parent, final String elementName)
        {
            this((XAdES[]) null, parent, elementName, OccursRequirement.EXACTLY_ONE);
        }

        Element(final XAdES xades, final XadesElement parent, final String elementName,
                final OccursRequirement occursRequirement)
        {
			this(xades != null ? new XAdES[] { xades } : (XAdES[]) null, parent, elementName, OccursRequirement.EXACTLY_ONE);
        }

        Element(final XAdES[] xades, final XadesElement parent, final String elementName,
                final OccursRequirement occursRequirement)
        {
            this.xades = xades;
            this.parent = parent;
            this.elementName = elementName;
            this.occursRequirement = OccursRequirement.EXACTLY_ONE;
        }

        @Override
		public XAdES[] getXAdES()
        {
            return this.xades == null ? null : (XAdES[]) this.xades.clone();
        }

        @Override
		public ObjectId getObjectId()
        {
            if (this.objectId == null)
            {
                int components[];
                if (this.parent != null)
                {
                    final int[] parentComps = this.parent.getObjectId().getComponents();
                    final int size = parentComps.length;
                    components = new int[size + 1];
                    System.arraycopy(parentComps, 0, components, 0, size);
                    components[size] = ordinal() + 1;
                }
                else
                {
                    components = new int[] { 0, ordinal() + 1 };
                }
                this.objectId = new ObjectId(components);
            }

            return this.objectId;
        }

        @Override
		public String getElementName()
        {
            return this.elementName;
        }

        @Override
		public OccursRequirement getOccursRequirement()
        {
            return this.occursRequirement;
        }

        @Override
		public XadesElement getParent()
        {
            return this.parent;
        }

        @Override
		public String toString()
        {
            return "[" + getObjectId() + "] " + getElementName(); //$NON-NLS-1$ //$NON-NLS-2$
        }

        private XAdES[] xades;
        private ObjectId objectId;
        private String elementName;
        private OccursRequirement occursRequirement;
        private XadesElement parent;

    }

    public static final XadesElementsEnumeration XAdES_ELEMENTS = new XadesElementsEnumeration(
            Element.values());
    public static final XadesElementsEnumeration XAdES_BES_ELEMENTS = new XadesElementsEnumeration(
            Element.values(), BES);
    public static final XadesElementsEnumeration XAdES_EPES_ELEMENTS = new XadesElementsEnumeration(
            Element.values(), EPES);
    public static final XadesElementsEnumeration XAdES_T_ELEMENTS = new XadesElementsEnumeration(
            Element.values(), T);
    public static final XadesElementsEnumeration XAdES_C_ELEMENTS = new XadesElementsEnumeration(
            Element.values(), C);
    public static final XadesElementsEnumeration XAdES_X_ELEMENTS = new XadesElementsEnumeration(
            Element.values(), X);
    public static final XadesElementsEnumeration XAdES_X_L_ELEMENTS = new XadesElementsEnumeration(
            Element.values(), X_L);
    public static final XadesElementsEnumeration XAdES_A_ELEMENTS = new XadesElementsEnumeration(
            Element.values(), A);
    public static final XadesElementsEnumeration XAdES_B_LEVEL_ELEMENTS = new XadesElementsEnumeration(
            Element.values(), XAdES.B_LEVEL);
    public static final XadesElementsEnumeration XAdES_T_LEVEL_ELEMENTS = new XadesElementsEnumeration(
            Element.values(), XAdES.T_LEVEL);

    public static XAdESBase newInstance(final XAdES xades, final org.w3c.dom.Element baseElement)
    {
        return newInstance(xades, XMLAdvancedSignature.XADES_v132, "xades", "dsign", //$NON-NLS-1$ //$NON-NLS-2$
                DigestMethod.SHA1, baseElement.getOwnerDocument(), baseElement);
    }

    public static XAdESBase newInstance(final XAdES xades)
    {
        try
        {
            final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder documentBuilder;
            documentBuilder = documentBuilderFactory.newDocumentBuilder();
            final Document document = documentBuilder.newDocument();

            return newInstance(xades, XMLAdvancedSignature.XADES_v132, "xades", "dsign", //$NON-NLS-1$ //$NON-NLS-2$
                    DigestMethod.SHA1, document, null);
        }
        catch (final ParserConfigurationException e)
        {
            return null;
        }
    }

    public static XAdESBase newInstance(final XAdES xades, final String xadesNamespace, final String xadesPrefix,
            final String xmlSignaturePrefix, final String digestMethod, final Document document,
            final org.w3c.dom.Element baseElement)
    {
        setDefinedIdAttributesAsDOMIds(document);

        if (BES.equals(xades))
        {
            return new BasicXAdESImpl(document, baseElement, false, xadesPrefix, xadesNamespace,
                    xmlSignaturePrefix, digestMethod);
        }
		if (EPES.equals(xades))
        {
            return new ExplicitPolicyXAdESImpl(document, baseElement, false, xadesPrefix,
                    xadesNamespace, xmlSignaturePrefix, digestMethod);
        }
		if (T.equals(xades))
        {
            return new TimestampXAdESImpl(document, baseElement, false, xadesPrefix,
                    xadesNamespace, xmlSignaturePrefix, digestMethod);
        }
		if (C.equals(xades))
        {
            return new CompleteValidationXAdESImpl(document, baseElement, false, xadesPrefix,
                    xadesNamespace, xmlSignaturePrefix, digestMethod);
        }
		if (X.equals(xades))
        {
            return new ExtendedXAdESImpl(document, baseElement, false, xadesPrefix, xadesNamespace,
                    xmlSignaturePrefix, digestMethod);
        }
		if (X_L.equals(xades))
        {
            return new ExtendedLongXAdESImpl(document, baseElement, false, xadesPrefix,
                    xadesNamespace, xmlSignaturePrefix, digestMethod);
        }
		if (A.equals(xades)) {
            return new ArchivalXAdESImpl(
        		document,
        		baseElement,
        		false,
        		xadesPrefix,
        		xadesNamespace,
                xmlSignaturePrefix,
                digestMethod
            );
        }
        else if (B_LEVEL.equals(xades)) {
            return new BLevelXAdESImpl(
        		document,
        		baseElement,
        		false,
        		xadesPrefix,
        		xadesNamespace,
                xmlSignaturePrefix,
                digestMethod
            );
        }
        else if (T_LEVEL.equals(xades))
        {
            return new TLevelXAdESImpl(document, baseElement, false, xadesPrefix, xadesNamespace,
                    xmlSignaturePrefix, digestMethod);
        }

        throw new IllegalArgumentException("Unknown XAdES type: " + xades); //$NON-NLS-1$
    }

    private static void setDefinedIdAttributesAsDOMIds(final Document document)
    {
        final NodeList nodes = document.getElementsByTagName("*"); //$NON-NLS-1$

        for (int i=0 ; i<nodes.getLength() ; i++)
        {
            final org.w3c.dom.Element node = (org.w3c.dom.Element) nodes.item(i);

            if (node.getAttribute("Id") != null && !node.getAttribute("Id").isEmpty()) //$NON-NLS-1$ //$NON-NLS-2$
            {
                node.setIdAttributeNS(null, "Id", true); //$NON-NLS-1$
            }
        }
    }
}

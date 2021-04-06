package es.uji.crypto.xades.jxades.security.xml;

import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignature.SignatureValue;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import org.w3c.dom.Element;

/**
 *
 * @author miro
 */
public class XMLSignatureElement
{
    private final Element signatureElement;
    private XMLSignatureFactory xmlSignatureFactory;
    private KeySelector keySelector;

    public XMLSignatureElement(final Element signatureElement)
    {
        if (signatureElement == null)
        {
            throw new IllegalArgumentException("Signature Element can not be NULL.");
        }
        this.signatureElement = signatureElement;
    }

    protected XMLSignatureFactory getXMLSignatureFactory()
    {
        if (this.xmlSignatureFactory == null)
        {
            this.xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");
        }
        return this.xmlSignatureFactory;
    }

    protected KeySelector getKeySelector()
    {
        if (this.keySelector == null)
        {
            this.keySelector = new KeyValueKeySelector();
        }
        return this.keySelector;
    }

    public XMLSignature getXMLSignature() throws MarshalException
    {
        final DOMValidateContext valContext = new DOMValidateContext(getKeySelector(), this.signatureElement);
        final XMLSignatureFactory fac = getXMLSignatureFactory();
        return fac.unmarshalXMLSignature(valContext);
    }

    public KeyInfo getKeyInfo() throws MarshalException
    {
        final XMLSignature xmlSignature = getXMLSignature();
        if (xmlSignature != null)
        {
            return xmlSignature.getKeyInfo();
        }

        return null;
    }

    public X509Data getX509Data() throws MarshalException
    {
        final KeyInfo keyInfo = getKeyInfo();
        if (keyInfo != null)
        {
            for (final Object o1 : keyInfo.getContent())
            {
                if (o1 instanceof X509Data)
                {
                    return (X509Data) o1;
                }
            }
        }

        return null;
    }

    public X509Certificate getX509Certificate() throws MarshalException
    {
        final X509Data x509Data = getX509Data();
        if (x509Data != null)
        {
            for (final Object o1 : x509Data.getContent())
            {
                if (o1 instanceof X509Certificate)
                {
                    return (X509Certificate) o1;
                }
            }
        }

        return null;
    }

    public SignatureStatus validate()
    {
        final DOMValidateContext valContext = new DOMValidateContext(getKeySelector(), this.signatureElement);
        final XMLSignatureFactory fac = getXMLSignatureFactory();
        String signatureId = this.signatureElement.getAttribute("Id");
        XMLSignature signature = null;
        try
        {
            signature = fac.unmarshalXMLSignature(valContext);
        }
        catch (final NullPointerException ex)
        {
            return new SignatureStatus(signatureId, ex);
        }
        catch (final ClassCastException ex)
        {
            return new SignatureStatus(signatureId, ex);
        }
        catch (final MarshalException ex)
        {
            return new SignatureStatus(signatureId, ex);
        }

        final String signId = signature.getId();
        if (signatureId == null || signId != null && !signId.equals(signatureId)) {
			signatureId = signId;
		}

        boolean status = false;
        try
        {
            status = signature.validate(valContext);
        }
        catch (final ClassCastException ex)
        {
            final InvalidSignatureReason reason = new InvalidSignatureReason(
                    InvalidSignature.NOT_COMPATIBLE_VALIDATE_CONTEXT, ex);
            return new SignatureStatus(signatureId, ValidateResult.INVALID, reason);
        }
        catch (final NullPointerException ex)
        {
            final InvalidSignatureReason reason = new InvalidSignatureReason("XMLSignature", ex);
            return new SignatureStatus(signatureId, ValidateResult.INVALID, reason);
        }
        catch (final XMLSignatureException ex)
        {
            final InvalidSignatureReason reason = new InvalidSignatureReason("XMLSignature", ex);
            return new SignatureStatus(signatureId, ValidateResult.INVALID, reason);
        }

        SignatureStatus validateResult;

        if (!status)
        {
            validateResult = new SignatureStatus(signatureId, ValidateResult.INVALID);
            final SignatureValue sv = signature.getSignatureValue();
            try
            {
                if (!sv.validate(valContext))
                {
                    final InvalidSignatureReason reason = new InvalidSignatureReason(sv);
                    validateResult.addInvalidSignatureReason(reason);
                }
            }
            catch (final NullPointerException ex)
            {
                final InvalidSignatureReason reason = new InvalidSignatureReason("SignatureValue", ex);
                validateResult.addInvalidSignatureReason(reason);
            }
            catch (final XMLSignatureException ex)
            {
                final InvalidSignatureReason reason = new InvalidSignatureReason("SignatureValue", ex);
                validateResult.addInvalidSignatureReason(reason);
            }

            final Iterator iter = signature.getSignedInfo().getReferences().iterator();
            for (int i = 0; iter.hasNext(); i++)
            {
                final Reference ref = (Reference) iter.next();
                try
                {
                    if (!ref.validate(valContext))
                    {
                        final InvalidSignatureReason reason = new InvalidSignatureReason(ref);
                        validateResult.addInvalidSignatureReason(reason);
                    }
                }
                catch (final NullPointerException ex)
                {
                    final InvalidSignatureReason reason = new InvalidSignatureReason("Reference", ex);
                    validateResult.addInvalidSignatureReason(reason);
                }
                catch (final XMLSignatureException ex)
                {
                    final InvalidSignatureReason reason = new InvalidSignatureReason("Reference", ex);
                    validateResult.addInvalidSignatureReason(reason);
                }
            }
        }
        else
        {
            validateResult = new SignatureStatus(signatureId, ValidateResult.VALID);
        }

        return validateResult;
    }

    private static class KeyValueKeySelector extends KeySelector {

        KeyValueKeySelector() {
			// Vacio
		}

		@Override
		public KeySelectorResult select(final KeyInfo keyInfo, final KeySelector.Purpose purpose,
                final AlgorithmMethod method, final XMLCryptoContext context) throws KeySelectorException
        {
            if (keyInfo == null)
            {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            final SignatureMethod sm = (SignatureMethod) method;
            final List list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++)
            {
                final XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof KeyValue)
                {
                    PublicKey pk = null;
                    try
                    {
                        pk = ((KeyValue) xmlStructure).getPublicKey();
                    }
                    catch (final KeyException ke)
                    {
                        throw new KeySelectorException(ke);
                    }
                    // make sure algorithm is compatible with method
                    if (algEquals(sm.getAlgorithm(), pk.getAlgorithm()))
                    {
                        return new SimpleKeySelectorResult(pk);
                    }
                }
                else if (xmlStructure instanceof X509Data)
                {
                    X509Certificate cert = null;
                    final List dataList = ((X509Data) xmlStructure).getContent();
                    for (final Object dataObject : dataList)
                    {
                        if (dataObject instanceof X509Certificate) {
							cert = (X509Certificate) dataObject;
						}
                    }
                    if (cert != null)
                    {
                        final PublicKey pk = cert.getPublicKey();

                        if (algEquals(sm.getAlgorithm(), pk.getAlgorithm()))
                        {
                            return new X509DataKeySelectorResult((X509Data) xmlStructure);
                        }
                    }
                }
            }
            throw new KeySelectorException("No KeyValue element found!");
        }

        static boolean algEquals(final String algURI, final String algName)
        {
            if (algName.equalsIgnoreCase("DSA") && algURI.toUpperCase().contains("DSA"))
            {
                return true;
            }
			if (algName.equalsIgnoreCase("RSA") && algURI.toUpperCase().contains("RSA"))
			{
			    return true;
			}
			else
			{
			    return false;
			}
        }
    }

    private static class SimpleKeySelectorResult implements KeySelectorResult
    {
        private final PublicKey pk;

        SimpleKeySelectorResult(final PublicKey pk)
        {
            this.pk = pk;
        }

        @Override
		public Key getKey()
        {
            return this.pk;
        }
    }

}

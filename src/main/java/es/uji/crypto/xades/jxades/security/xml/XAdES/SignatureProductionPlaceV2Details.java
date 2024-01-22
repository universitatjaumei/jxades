package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Sample usage of signing SignatureProductionPlaceV2:
 * <p>
 * {@code
 * <xades:SignatureProductionPlace>
 *     <xades:City>City</xades:City>
 *     <xades:StreetAddress>StreetAddress</xades:StreetAddress>
 *     <xades:StateOrProvince>StateOrProvince</xades:StateOrProvince>
 *     <xades:PostalCode>PostalCode</xades:PostalCode>
 *     <xades:CountryName>CountryName</xades:CountryName>
 * </xades:SignatureProductionPlace>
 * }
 * </p>
 */
public class SignatureProductionPlaceV2Details extends XAdESStructure
{
    public SignatureProductionPlaceV2Details(final Document document, final SignedSignatureProperties ssp,
            final SignatureProductionPlaceV2 signatureProductionPlace, final String xadesPrefix,
            final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(document, ssp, "SignatureProductionPlaceV2", xadesPrefix, xadesNamespace, //$NON-NLS-1$
                xmlSignaturePrefix);

        if (signatureProductionPlace.getCity() != null)
        {
            final Element city = createElement("City"); //$NON-NLS-1$
            city.setTextContent(signatureProductionPlace.getCity());
            getNode().appendChild(city);
        }

        if (signatureProductionPlace.getStreetAddress() != null)
        {
            final Element streetAddress = createElement("StreetAddress"); //$NON-NLS-1$
            streetAddress.setTextContent(signatureProductionPlace.getStreetAddress());
            getNode().appendChild(streetAddress);
        }

        if (signatureProductionPlace.getStateOrProvince() != null)
        {
            final Element stateOrProvince = createElement("StateOrProvince"); //$NON-NLS-1$
            stateOrProvince.setTextContent(signatureProductionPlace.getStateOrProvince());
            getNode().appendChild(stateOrProvince);
        }

        if (signatureProductionPlace.getPostalCode() != null)
        {
            final Element postalCode = createElement("PostalCode"); //$NON-NLS-1$
            postalCode.setTextContent(signatureProductionPlace.getPostalCode());
            getNode().appendChild(postalCode);
        }

        if (signatureProductionPlace.getCountryName() != null)
        {
            final Element countryName = createElement("CountryName"); //$NON-NLS-1$
            countryName.setTextContent(signatureProductionPlace.getCountryName());
            getNode().appendChild(countryName);
        }
    }

    public SignatureProductionPlaceV2Details(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }
}
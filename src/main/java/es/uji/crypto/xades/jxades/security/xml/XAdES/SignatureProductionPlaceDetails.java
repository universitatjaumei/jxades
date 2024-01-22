package es.uji.crypto.xades.jxades.security.xml.XAdES;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 *
 * Sample usage of signing SignatureProductionPlace:
 *
 * <xades:SignatureProductionPlace> <xades:City>p:City</p:City>
 * <xades:StateOrProvince>p:StateOrProvince</p:StateOrProvince>
 * <xades:PostalCode>p:PostalCode</p:PostalCode> <xades:CountryName>p:CountryName</p:CountryName>
 * </xades:SignatureProductionPlace>
 *
 */

public class SignatureProductionPlaceDetails extends XAdESStructure
{
    public SignatureProductionPlaceDetails(final Document document, final SignedSignatureProperties ssp,
            final SignatureProductionPlace signatureProductionPlace, final String xadesPrefix,
            final String xadesNamespace, final String xmlSignaturePrefix)
    {
        super(document, ssp, "SignatureProductionPlace", xadesPrefix, xadesNamespace, //$NON-NLS-1$
                xmlSignaturePrefix);

        if (signatureProductionPlace.getCity() != null) {
            final Element city = createElement("City"); //$NON-NLS-1$
            city.setTextContent(signatureProductionPlace.getCity());
            getNode().appendChild(city);
        }

        if (signatureProductionPlace.getStateOrProvince() != null) {
            final Element stateOrProvince = createElement("StateOrProvince"); //$NON-NLS-1$
            stateOrProvince.setTextContent(signatureProductionPlace.getStateOrProvince());
            getNode().appendChild(stateOrProvince);
        }

        if (signatureProductionPlace.getPostalCode() != null) {
            final Element postalCode = createElement("PostalCode"); //$NON-NLS-1$
            postalCode.setTextContent(signatureProductionPlace.getPostalCode());
            getNode().appendChild(postalCode);
        }

        if (signatureProductionPlace.getCountryName() != null) {
            final Element countryName = createElement("CountryName"); //$NON-NLS-1$
            countryName.setTextContent(signatureProductionPlace.getCountryName());
            getNode().appendChild(countryName);
        }
    }

    public SignatureProductionPlaceDetails(final Node node, final String xadesPrefix, final String xadesNamespace,
            final String xmlSignaturePrefix)
    {
        super(node, xadesPrefix, xadesNamespace, xmlSignaturePrefix);
    }
}
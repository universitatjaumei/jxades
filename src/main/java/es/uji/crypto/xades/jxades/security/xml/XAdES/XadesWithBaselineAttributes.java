package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public interface XadesWithBaselineAttributes {
	
	SigningCertificateV2 getSigningCertificateV2();

    /**
     * Set the signing certificate.
     * @param signingCertificate Signing certificate information.
     */
    void setSigningCertificateV2(X509Certificate signingCertificate, SigningCertificateV2Info additionalInfo);

    SignatureProductionPlace getSignatureProductionPlace();
    void setSignatureProductionPlace(SignatureProductionPlace productionPlace);

    SignerRole getSignerRole();
    void setSignerRole(SignerRole signerRole);
}

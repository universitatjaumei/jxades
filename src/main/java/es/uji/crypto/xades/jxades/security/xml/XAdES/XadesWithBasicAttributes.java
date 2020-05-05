package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.security.cert.X509Certificate;

public interface XadesWithBasicAttributes {
	
    public SigningCertificate getSigningCertificate();
    public void setSigningCertificate(X509Certificate certificate);
    
    public SignatureProductionPlace getSignatureProductionPlace();
    public void setSignatureProductionPlace(SignatureProductionPlace productionPlace);

    public SignerRole getSignerRole();
    public void setSignerRole(SignerRole signerRole);
}

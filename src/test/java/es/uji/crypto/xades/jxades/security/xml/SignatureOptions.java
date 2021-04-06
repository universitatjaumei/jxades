package es.uji.crypto.xades.jxades.security.xml;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class SignatureOptions
{
    private KeyStore keystore;
    private X509Certificate certificate;
    private PrivateKey privateKey;

    public KeyStore getKeystore()
    {
        return this.keystore;
    }

    public void setKeystore(KeyStore keystore)
    {
        this.keystore = keystore;
    }

    public X509Certificate getCertificate()
    {
        return this.certificate;
    }

    public void setCertificate(X509Certificate certificate)
    {
        this.certificate = certificate;
    }

    public PrivateKey getPrivateKey()
    {
        return this.privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }
}

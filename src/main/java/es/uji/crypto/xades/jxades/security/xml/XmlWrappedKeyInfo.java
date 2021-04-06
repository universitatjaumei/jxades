package es.uji.crypto.xades.jxades.security.xml;

/**
 * 
 * @author miro
 */
public enum XmlWrappedKeyInfo
{
    PUBLIC_KEY("PublicKey"), CERTIFICATE("Certificate");

    private XmlWrappedKeyInfo(String wrappedKeyInfoName)
    {
        this.wrappedKeyInfoName = wrappedKeyInfoName;
    }

    public String getWrappedKeyInfoName()
    {
        return this.wrappedKeyInfoName;
    }

    @Override
	public String toString()
    {
        return getWrappedKeyInfoName();
    }

    private String wrappedKeyInfoName;
}

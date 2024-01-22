package es.uji.crypto.xades.jxades.security.xml;

/**
 *
 * @author miro
 */
public enum XmlWrappedKeyInfo {

    PUBLIC_KEY("PublicKey"), //$NON-NLS-1$
    CERTIFICATE("Certificate"); //$NON-NLS-1$

    XmlWrappedKeyInfo(final String wrappedKeyInfoName) {
        this.wrappedKeyInfoName = wrappedKeyInfoName;
    }

    public String getWrappedKeyInfoName() {
        return this.wrappedKeyInfoName;
    }

    @Override
	public String toString() {
        return getWrappedKeyInfoName();
    }

    private final String wrappedKeyInfoName;
}

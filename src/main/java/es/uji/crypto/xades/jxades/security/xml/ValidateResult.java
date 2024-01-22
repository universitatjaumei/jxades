package es.uji.crypto.xades.jxades.security.xml;

/**
 *
 * @author miro
 */
public enum ValidateResult {

    VALID("Valida"), INCOMPLETE("Validacion incompleta"), INVALID("Invalida"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

    ValidateResult(final String resultName) {
        this.resultName = resultName;
    }

    public String getResultName() {
        return this.resultName;
    }

    @Override
	public String toString() {
        return getResultName();
    }

    private final String resultName;
}

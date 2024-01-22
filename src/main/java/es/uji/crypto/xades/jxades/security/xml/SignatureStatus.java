package es.uji.crypto.xades.jxades.security.xml;

import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.MarshalException;

import es.uji.crypto.xades.jxades.util.ComparableBean;

/**
 *
 * @author miro
 */
public class SignatureStatus implements ComparableBean
{
    private String signatureId;
    private ValidateResult validateResult;
    private final ArrayList<InvalidSignatureReason> invalidSignatureReasons = new ArrayList<>();

    public SignatureStatus()
    {
    }

    public SignatureStatus(final String signatureId, final MarshalException ex)
    {
        this(signatureId, ValidateResult.INVALID, new InvalidSignatureReason(ex));
    }

    public SignatureStatus(final String signatureId, final NullPointerException ex)
    {
        this(signatureId, ValidateResult.INVALID, new InvalidSignatureReason("XML", ex)); //$NON-NLS-1$
    }

    public SignatureStatus(final String signatureId, final ClassCastException ex)
    {
        this(signatureId, ValidateResult.INVALID, new InvalidSignatureReason(
                InvalidSignature.INAPPROPRIATE_XML_CONTEXT, ex));
    }

    public SignatureStatus(final String signatureId, final ValidateResult validateResult,
            final InvalidSignatureReason reason)
    {
        this(signatureId, validateResult);
        addInvalidSignatureReason(reason);
    }

    public SignatureStatus(final String signatureId, final ValidateResult validateResult)
    {
        this.signatureId = signatureId;
        this.validateResult = validateResult;
    }

    public ValidateResult getValidateResult()
    {
        return this.validateResult;
    }

    public String getSignatureId()
    {
        return this.signatureId;
    }

    public void addInvalidSignatureReason(final InvalidSignatureReason reason)
    {
        this.invalidSignatureReasons.add(reason);
    }

    public List<InvalidSignatureReason> getInvalidSignatureReasons()
    {
        return this.invalidSignatureReasons;
    }

    public String getReasonsAsText()
    {
        final StringBuilder sb = new StringBuilder();
        boolean isFirst = true;
        final List<InvalidSignatureReason> reasons = getInvalidSignatureReasons();
        for (final InvalidSignatureReason reason : reasons)
        {
            if (isFirst)
            {
                isFirst = false;
                sb.append(reason.getReason());
            }
            else
            {
                sb.append(", ").append(reason.getReason()); //$NON-NLS-1$
            }
        }

        return sb.toString();
    }

    @Override
	public String toString()
    {
        return this.validateResult.toString();
    }

    public static boolean isValid(final List<SignatureStatus> validateResults)
    {
        for (final SignatureStatus signStatus : validateResults)
        {
            if (!ValidateResult.VALID.equals(signStatus.getValidateResult())) {
				return false;
			}
        }

        return true;
    }

    @Override
	public Comparable getIndexKey()
    {
        return getSignatureId();
    }
}

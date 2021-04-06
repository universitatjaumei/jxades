package es.uji.crypto.xades.jxades.security.xml.XAdES;

/**
 *
 * @author miro
 */
class SignerImpl
    implements Signer
{
    private String userId;
    private String username;
    private String personName;
    private RoleType roleType;
    
    
    public SignerImpl()
    {
    }

    @Override
	public String getUserId()
    {
        return this.userId;
    }

    @Override
	public void setUserId(String userId)
    {
        this.userId = userId;
    }

    @Override
	public String getUsername()
    {
        return this.username;
    }

    @Override
	public void setUsername(String username)
    {
        this.username = username;
    }

    @Override
	public String getPersonName()
    {
        return this.personName;
    }

    @Override
	public void setPersonName(String personName)
    {
        this.personName = personName;
    }

    @Override
	public RoleType getRoleType()
    {
        return this.roleType;
    }

    @Override
	public void setRoleType(RoleType roleType)
    {
        this.roleType = roleType;
    }

}

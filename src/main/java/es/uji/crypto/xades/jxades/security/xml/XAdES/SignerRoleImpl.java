package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.ArrayList;

public class SignerRoleImpl implements SignerRole
{
	private ArrayList<String> claimedRole;
	private ArrayList<String> certifiedRole;

	public SignerRoleImpl()
	{
		this.claimedRole = new ArrayList<>();
		this.certifiedRole = new ArrayList<>();
	}

	@Override
	public ArrayList<String> getCertifiedRole()
	{
		return this.certifiedRole;
	}

	@Override
	public void setCertifiedRole(final ArrayList<String> certifiedRole)
	{
		this.certifiedRole = certifiedRole;
	}

	@Override
	public ArrayList<String> getClaimedRole()
	{
		return this.claimedRole;
	}

	@Override
	public void setClaimedRole(final ArrayList<String> claimedRole)
	{
		this.claimedRole = claimedRole;
	}

	@Override
	public void addClaimedRole(final String role)
	{
		this.claimedRole.add(role);
	}

	@Override
	public void addCertifiedRole(final String role)
	{
		this.certifiedRole.add(role);
	}
}
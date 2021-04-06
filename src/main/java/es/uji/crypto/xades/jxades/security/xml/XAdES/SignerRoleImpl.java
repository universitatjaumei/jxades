package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.ArrayList;

public class SignerRoleImpl implements SignerRole
{
	private ArrayList<String> claimedRole;
	private ArrayList<String> certifiedRole;

	public SignerRoleImpl()
	{
		this.claimedRole = new ArrayList<String>();
		this.certifiedRole = new ArrayList<String>();
	}

	@Override
	public ArrayList<String> getCertifiedRole()
	{
		return this.certifiedRole;
	}

	@Override
	public void setCertifiedRole(ArrayList<String> certifiedRole)
	{
		this.certifiedRole = certifiedRole;
	}

	@Override
	public ArrayList<String> getClaimedRole()
	{
		return this.claimedRole;
	}

	@Override
	public void setClaimedRole(ArrayList<String> claimedRole)
	{
		this.claimedRole = claimedRole;
	}

	@Override
	public void addClaimedRole(String role)
	{
		this.claimedRole.add(role);
	}

	@Override
	public void addCertifiedRole(String role)
	{
		this.certifiedRole.add(role);
	}
}
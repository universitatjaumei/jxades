package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.ArrayList;

public class SignerRoleV2Impl implements SignerRoleV2
{
	private ArrayList<String> claimedRoles;
	private ArrayList<String> certifiedRolesV2;
	private ArrayList<String> signedAssertions;

	public SignerRoleV2Impl()
	{
		this.claimedRoles = new ArrayList<String>();
		this.certifiedRolesV2 = new ArrayList<String>();
		this.signedAssertions = new ArrayList<String>();
	}

	@Override
	public ArrayList<String> getClaimedRoles()
	{
		return this.claimedRoles;
	}

	@Override
	public void setClaimedRoles(ArrayList<String> claimedRole)
	{
		this.claimedRoles = claimedRole;
	}

	@Override
	public void addClaimedRole(String role)
	{
		this.claimedRoles.add(role);
	}
	
	@Override
	public ArrayList<String> getCertifiedRolesV2()
	{
		return this.certifiedRolesV2;
	}

	@Override
	public void setCertifiedRolesV2(ArrayList<String> certifiedRole)
	{
		this.certifiedRolesV2 = certifiedRole;
	}

	@Override
	public void addCertifiedRoleV2(String role)
	{
		this.certifiedRolesV2.add(role);
	}
	
	@Override
	public ArrayList<String> getSignedAssertions()
	{
		return this.signedAssertions;
	}

	@Override
	public void setSignedAssertions(ArrayList<String> signedAssertions)
	{
		this.signedAssertions = signedAssertions;
	}
}
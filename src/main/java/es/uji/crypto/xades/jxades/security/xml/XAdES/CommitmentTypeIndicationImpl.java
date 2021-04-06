package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.ArrayList;

public class CommitmentTypeIndicationImpl implements CommitmentTypeIndication 
{
	private CommitmentTypeId commitmentTypeId;
	private String objectReference;
	private ArrayList<String> commitmentTypeQualifiers;	   
	
	public CommitmentTypeIndicationImpl()
	{		
	}

	public CommitmentTypeIndicationImpl(CommitmentTypeId commitmentTypeId, String objectReference, ArrayList<String> commitmentTypeQualifiers)
	{		
		this.commitmentTypeId = commitmentTypeId;
		this.objectReference = objectReference;
		this.commitmentTypeQualifiers = commitmentTypeQualifiers;
	}

	@Override
	public CommitmentTypeId getCommitmentTypeId() 
	{
		return this.commitmentTypeId;
	}

	@Override
	public void setCommitmentTypeId(CommitmentTypeId commitmentTypeId) 
	{
		this.commitmentTypeId = commitmentTypeId;
	}

	@Override
	public String getObjectReference() 
	{
		return this.objectReference;
	}

	@Override
	public void setObjectReference(String objectReference) 
	{
		this.objectReference = objectReference;
	}

	@Override
	public ArrayList<String> getCommitmentTypeQualifiers() 
	{
		return this.commitmentTypeQualifiers;
	}

	@Override
	public void setCommitmentTypeQualifiers(ArrayList<String> commitmentTypeQualifiers) 
	{
		this.commitmentTypeQualifiers = commitmentTypeQualifiers;
	}
}

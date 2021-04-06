package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.ArrayList;

public class CommitmentTypeIdImpl implements CommitmentTypeId
{
    private String qualifier;
    private String identifier;
    private String description;
    private ArrayList<String> documentationReferences;

	public CommitmentTypeIdImpl(String qualifier, String identifier, String description, ArrayList<String> documentationReferences) 
	{
		this.qualifier = qualifier;
		this.identifier = identifier;
		this.description = description;
		this.documentationReferences = documentationReferences;
	}

	@Override
	public String getQualifier() 
	{
		return this.qualifier;
	}

	public void setQualifier(String qualifier) 
	{
		this.qualifier = qualifier;
	}

	@Override
	public String getIdentifier() 
	{
		return this.identifier;
	}

	public void setIdentifier(String identifier) 
	{
		this.identifier = identifier;
	}

	@Override
	public String getDescription() 
	{
		return this.description;
	}

	public void setDescription(String description) 
	{
		this.description = description;
	}

	@Override
	public ArrayList<String> getDocumentationReferences() 
	{
		return this.documentationReferences;
	}

	public void setDocumentationReferences(ArrayList<String> documentationReferences) 
	{
		this.documentationReferences = documentationReferences;
	}
}

package es.uji.crypto.xades.jxades.security.xml.XAdES;

import java.util.ArrayList;

public class ObjectIdentifierImpl implements ObjectIdentifier
{
    private String qualifier;
    private String identifier;
    private String description;
    private ArrayList<String> documentationReferences;

	public ObjectIdentifierImpl(String qualifier, String identifier, String description, ArrayList<String> documentationReferences) 
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

	@Override
	public void setQualifier(String qualifier) 
	{
		this.qualifier = qualifier;
	}

	@Override
	public String getIdentifier() 
	{
		return this.identifier;
	}

	@Override
	public void setIdentifier(String identifier) 
	{
		this.identifier = identifier;
	}

	@Override
	public String getDescription() 
	{
		return this.description;
	}

	@Override
	public void setDescription(String description) 
	{
		this.description = description;
	}

	@Override
	public ArrayList<String> getDocumentationReferences() 
	{
		return this.documentationReferences;
	}

	@Override
	public void setDocumentationReferences(ArrayList<String> documentationReferences) 
	{
		this.documentationReferences = documentationReferences;
	}
}

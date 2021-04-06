package es.uji.crypto.xades.jxades.security.xml.XAdES;

public class DataObjectFormatImpl implements DataObjectFormat 
{
	private String description;
	private ObjectIdentifier objectIdentifier;
	private String mimeType;
	private String encoding;
	private String objectReference;
	
	public DataObjectFormatImpl()
	{		
	}

	public DataObjectFormatImpl(String description, ObjectIdentifier objectIdentifier, String mimeType, String encoding, String objectReference)
	{		
		this.description = description;
		this.objectIdentifier = objectIdentifier;
		this.mimeType = mimeType;
		this.encoding = encoding;
		this.objectReference = objectReference;
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
	public ObjectIdentifier getObjectIdentifier() 
	{
		return this.objectIdentifier;
	}
	
	public void setObjectIdentifier(ObjectIdentifier objectIdentifier) 
	{
		this.objectIdentifier = objectIdentifier;
	}
	
	@Override
	public String getMimeType() 
	{
		return this.mimeType;
	}
	
	public void setMimeType(String mimeType) 
	{
		this.mimeType = mimeType;
	}
	
	@Override
	public String getEncoding() 
	{
		return this.encoding;
	}
	
	public void setEncoding(String encoding) 
	{
		this.encoding = encoding;
	}

	@Override
	public String getObjectReference() {
		return this.objectReference;
	}

	public void setObjectReference(String objectReference) {
		this.objectReference = objectReference;
	}
	
	
}

package es.uji.crypto.xades.jxades.security.xml.XAdES;

public class SignatureProductionPlaceImpl implements SignatureProductionPlace
{
	private String city;
	private String stateOrProvince;
	private String postalCode;
	private String countryName;

	public SignatureProductionPlaceImpl() 
	{
	}

	public SignatureProductionPlaceImpl(String city, String stateOrProvince, String postalCode, String countryName) 
	{
		this.city = city;
		this.stateOrProvince = stateOrProvince;
		this.postalCode = postalCode;
		this.countryName = countryName;
	}
	
	@Override
	public String getCity() 
	{
		return this.city;
	}

	@Override
	public void setCity(String city) 
	{
		this.city = city;
	}

	@Override
	public String getStateOrProvince() 
	{
		return this.stateOrProvince;
	}

	@Override
	public void setStateOrProvince(String stateOrProvince) 
	{
		this.stateOrProvince = stateOrProvince;
	}

	@Override
	public String getPostalCode() 
	{
		return this.postalCode;
	}

	@Override
	public void setPostalCode(String postalCode) 
	{
		this.postalCode = postalCode;
	}

	@Override
	public String getCountryName() 
	{
		return this.countryName;
	}

	@Override
	public void setCountryName(String countryName) 
	{
		this.countryName = countryName;
	}
}
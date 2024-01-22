package es.uji.crypto.xades.jxades.util;

import java.util.Arrays;
import java.util.List;
import java.util.TreeMap;

/**
 *
 * @author miro
 */
public enum DefaultFileExtension
    implements FileExtension
{
    CERTIFICATE_KEY_STORE_P12(".p12", "P12 Certificate Files"), //$NON-NLS-1$
    CERTIFICATE_KEY_STORE_PFX(".pfx", "PFX Certificate Files"), //$NON-NLS-1$
    CERTIFICATE_KEY_STORES("PKCS #12 Certificate Files", CERTIFICATE_KEY_STORE_P12, CERTIFICATE_KEY_STORE_PFX),
    CERTIFICATE_CER(".cer", "CER Certificate Files"), //$NON-NLS-1$
    CERTIFICATE_CRT(".crt", "CRT Certificate Files"), //$NON-NLS-1$
    CERTIFICATE_DER(".der", "DER Certificate Files"), //$NON-NLS-1$
    ALL_CERTIFICATES("All Certificate Files", CERTIFICATE_CER, CERTIFICATE_CRT, CERTIFICATE_DER),
    CERTIFICATE_REVOCATION_LIST(".crl", "Certificate Revocation Lists", "CRL Files"), //$NON-NLS-1$
    WINDOWS_SYSTEM_LIBRARY(".dll", "Windows System Library", "DLL Files"), //$NON-NLS-1$
    LINUX_SYSTEM_LIBRARY(".so", "Linux System Library", "SO Files"), //$NON-NLS-1$
    TXT_FILES(".txt", "Text Documents (*.txt) with UTF-8 encoding"), //$NON-NLS-1$
    ALL_FILES(".*", "All files", "All Files"); //$NON-NLS-1$

    DefaultFileExtension(final String extension,
                                 final String description)
    {
        this(extension, description, description, "*");
    }

    DefaultFileExtension(final String extension,
                                 final String description,
                                 final String fileFilterName)
    {
        this(extension, description, fileFilterName, "*");
    }

    DefaultFileExtension(final String extension,
                                 final String description,
                                 final String fileFilterName,
                                 final String prefixFileFilterPattern)
    {
        this.extension = extension;
        this.description = description;
        this.fileFilterName = fileFilterName;
        this.fileFilterPattern = prefixFileFilterPattern + extension;
    }

    DefaultFileExtension(final String description,
                                 final FileExtension... exts)
    {
        this(description, description, Arrays.asList(exts));
    }

    DefaultFileExtension(final String description,
                                 final String fileFilterName,
                                 final FileExtension... exts)
    {
        this(description, fileFilterName, Arrays.asList(exts));
    }

    DefaultFileExtension(final String description,
                                 final String fileFilterName,
                                 final List<FileExtension> exts)
    {
        this.description = description;
        this.fileFilterName = fileFilterName;
        this.extensions = exts;
    }

    @Override
	public String getDescription()
    {
        return this.description;
    }

    @Override
	public String getExtension()
    {
        return this.extension;
    }

    @Override
	public String getFileFilterName()
    {
        return this.fileFilterName;
    }

    @Override
	public String getFileFilterPattern()
    {
        return this.fileFilterPattern;
    }

    @Override
	public List<FileExtension> getExtensions()
    {
        return this.extensions;
    }

    @Override
	public boolean contains(final FileExtension object)
    {
        if(this.extension != null) {
			return equals(object);
		}
		if(this.extensions != null)
        {
            for (final FileExtension element : this.extensions) {
                if(element.equals(object)) {
					return true;
				}
            }
        }
        return false;
    }

    private String extension;
    private final String description;
    private final String fileFilterName;
    private String fileFilterPattern;
    private List<FileExtension> extensions;


    public static DefaultFileExtension getEnumById(final String extension)
    {
        return (DefaultFileExtension)getFileExtensionById(DefaultFileExtension.class, extension);
    }

    private static final TreeMap<String, TreeMap<String, FileExtension>> fileExtensionsMap =
        new TreeMap<>();

    public static FileExtension getFileExtensionById(final Class fileExtnsionEnumClass, final String extension)
    {
        if(fileExtnsionEnumClass == null || extension == null) {
			throw new NullPointerException("Invalid parameter(s): 'fileExtnsionEnumClass' and 'extension' can not be NULL."); //$NON-NLS-1$
		}

        if(!fileExtnsionEnumClass.isEnum()) {
			throw new IllegalArgumentException("Invalid parameter 'fileExtnsionEnumClass'. The parameter must exends Enum class."); //$NON-NLS-1$
		}

        if(!FileExtension.class.isAssignableFrom(fileExtnsionEnumClass)) {
			throw new IllegalArgumentException("Invalid parameter 'fileExtnsionEnumClass'. The class must implements 'FileExtension' interface."); //$NON-NLS-1$
		}

        final String className = fileExtnsionEnumClass.getName();
        TreeMap<String, FileExtension> enumMap = fileExtensionsMap.get(className);
        if(enumMap == null)
        {
            enumMap = new TreeMap<>();
            for(final Object enumObject : fileExtnsionEnumClass.getEnumConstants())
            {
                final FileExtension fileExt = (FileExtension)enumObject;
                final String ext = fileExt.getExtension();
                if(ext != null)
                {
                    enumMap.put(ext, fileExt);
                }
            }
            fileExtensionsMap.put(className, enumMap);
        }

        if(extension.charAt(0) != '.') {
			return enumMap.get("." + extension.toLowerCase()); //$NON-NLS-1$
		}
		return enumMap.get(extension.toLowerCase());
    }


    public static void main(final String[] args)
    {
        final DefaultFileExtension fileExt = getEnumById("CRL"); //$NON-NLS-1$
        System.out.println("fileExt: " + fileExt); //$NON-NLS-1$
    }
}

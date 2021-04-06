package es.uji.crypto.xades.jxades.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 *
 * @author miro
 */
public class ResourceHelper
{
    private final String classFileName;
    private final String resourceFolderName;
    private URL resourceURL;
    private Enumeration<ResourceEntry> resourceEntries;

    public ResourceHelper(final Class clazz)
        throws IOException
    {
        this(clazz, null);
    }

    public ResourceHelper(final Class clazz, final String resourceFolderName)
        throws IOException
    {
        this.resourceFolderName = resourceFolderName;
        this.classFileName = clazz.getName().replace('.', '/') + ".class"; //$NON-NLS-1$
        final ClassLoader classLoader = clazz.getClassLoader();
        this.resourceURL = ClassLoader.getSystemResource(this.classFileName);
        if(this.resourceURL == null)
        {
            this.resourceURL = classLoader.getResource(this.classFileName);
        }
        if(this.resourceURL == null) {
			throw new IOException("Impossible to find Resource URL."); //$NON-NLS-1$
		}
    }

    public URL getResourceURL()
    {
        return this.resourceURL;
    }

    public Enumeration<ResourceEntry> resourceEntries()
        throws IOException
    {
        if(this.resourceEntries == null)
        {
            final String protocol = this.resourceURL.getProtocol().toLowerCase();
            if("file".equals(protocol)) //$NON-NLS-1$
            {
                final String path = this.resourceURL.getPath();
                final int pos = path.length() - this.classFileName.length();
                final String basePath = path.substring(0, pos);
                File baseFolder = new File(basePath);
                if(this.resourceFolderName != null) {
					baseFolder = new File(baseFolder, this.resourceFolderName);
				}
                final List<File> fileStore = new ArrayList<File>();
                loadFiles(baseFolder, fileStore);
                return new FileResourceEntries(fileStore);
            }
			if("jar".equals(protocol)) //$NON-NLS-1$
            {
                final JarURLConnection jarConn = (JarURLConnection)this.resourceURL.openConnection();
                final JarFile jarFile = jarConn.getJarFile();
                this.resourceEntries = new JarResourceEntries(jarFile, this.resourceFolderName);
            } else {
				this.resourceEntries = new EmptyResourceEntries();
			}
        }

        return this.resourceEntries;
    }

    private void loadFiles(final File folder, final List<File> fileStore)
    {
        for(final File file : folder.listFiles())
        {
            fileStore.add(file);
            if(file.isDirectory()) {
				loadFiles(file, fileStore);
			}
        }
    }

    private static class EmptyResourceEntries implements Enumeration<ResourceEntry> {

        EmptyResourceEntries() {
			// vacio
		}

		@Override
		public boolean hasMoreElements() {
            return false;
        }

        @Override
		public ResourceEntry nextElement() {
            throw new NoSuchElementException();
        }
    }

    private static class JarResourceEntries
        implements Enumeration<ResourceEntry>
    {
        private final JarFile jarFile;
        private final Iterator<JarEntry> entries;

        public JarResourceEntries(final JarFile jarFile, final String resourceFolderName)
        {
            this.jarFile = jarFile;
            final List<JarEntry> jarEntryList = new ArrayList<JarEntry>();
            final Enumeration<JarEntry> jarEntries = jarFile.entries();
            while(jarEntries.hasMoreElements())
            {
                final JarEntry entry = jarEntries.nextElement();
                if(resourceFolderName == null || entry.getName().startsWith(resourceFolderName)) {
					jarEntryList.add(entry);
				}
            }

            this.entries = jarEntryList.iterator();
        }

        @Override
		public boolean hasMoreElements()
        {
            return this.entries.hasNext();
        }

        @Override
		public ResourceEntry nextElement()
        {
            return new JarResourceEntry(this.jarFile, this.entries.next());
        }
    }

    private static class FileResourceEntries
        implements Enumeration<ResourceEntry>
    {
        private final Iterator<File> entries;

        public FileResourceEntries(final List<File> fileStore)
        {
            this.entries = fileStore.iterator();
        }

        @Override
		public boolean hasMoreElements()
        {
            return this.entries.hasNext();
        }

        @Override
		public ResourceEntry nextElement()
        {
            return new FileResourceEntry(this.entries.next());
        }
    }

    public interface ResourceEntry
    {
        String getPathName();
        boolean isDirectory();
        InputStream getInputStream()
            throws IOException;
    }

    private static class FileResourceEntry
        implements ResourceEntry
    {
        private final File file;

        public FileResourceEntry(final File file)
        {
            this.file = file;
        }

        @Override
		public String getPathName()
        {
            return this.file.getAbsolutePath();
        }

        @Override
		public boolean isDirectory()
        {
            return this.file.isDirectory();
        }

        @Override
		public InputStream getInputStream()
            throws IOException
        {
            return new FileInputStream(this.file);
        }
    }

    private static class JarResourceEntry
        implements ResourceEntry
    {
        private final JarFile jarFile;
        private final JarEntry entry;

        public JarResourceEntry(final JarFile jarFile, final JarEntry entry)
        {
            this.entry = entry;
            this.jarFile = jarFile;
        }

        @Override
		public String getPathName()
        {
            return this.entry.getName();
        }

        @Override
		public boolean isDirectory()
        {
            return this.entry.isDirectory();
        }

        @Override
		public InputStream getInputStream()
            throws IOException
        {
            return this.jarFile.getInputStream(this.entry);
        }
    }
}

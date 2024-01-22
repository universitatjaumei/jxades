package es.uji.crypto.xades.jxades.util;

import java.io.IOException;

/**
 *
 * @author miro
 */
public class ObjectId
    implements Comparable<ObjectId>
{
    protected final int[] components;
    private final int hashCode;
    private String toString;

    public ObjectId(final int[] components) {
        if(components == null || components.length <= 0) {
			throw new IllegalArgumentException("Components[] parameter can not be NULL or empty."); //$NON-NLS-1$
		}

        this.components = components.clone();

        final int componentLen = components.length;
        int hc = componentLen;
        for(int i = 0; i < componentLen; i++) {
			hc += components[i] * 37;
		}
        this.hashCode = hc;
    }

    public ObjectId(final String componentsString) throws IOException {
        this(parseObjectIdentifierString(componentsString));
    }

    @Override
	public boolean equals(final Object other) {
        if(this == other) {
			return true;
		}

        if(!(other instanceof ObjectId)) {
			return false;
		}

        return compareTo((ObjectId)other) == 0;
    }

    @Override
	public int compareTo(final ObjectId other)
    {
        int size;
        if(this.components.length < other.components.length) {
			size = this.components.length;
		} else {
			size = other.components.length;
		}

        int i = 0;
        while(i < size)
        {
            final int result = this.components[i] - other.components[i];
            if(result != 0) {
				return result;
			}
            i++;
        }

        return this.components.length - other.components.length;
    }

    public int[] getComponents()
    {
        return this.components.clone();
    }

    @Override
	public String toString()
    {
        if(this.toString == null)
        {
            final StringBuilder sb = new StringBuilder();
            for(int i = 0; i < this.components.length; i++)
            {
                if(i > 0) {
					sb.append('.');
				}
                sb.append(this.components[i]);
            }

            this.toString = sb.toString();
        }

        return this.toString;
    }

    @Override
	public int hashCode()
    {
        return this.hashCode;
    }

    private static int[] parseObjectIdentifierString(final String objId)
        throws IOException
    {
        try
        {
            final String[] strValues = objId.split("\\."); //$NON-NLS-1$
            final int[] intValues = new int[strValues.length];
            for(int i = 0; i < strValues.length; i++)
            {
                intValues[i] = Integer.parseInt(strValues[i].trim());
            }

            return intValues;
        }
        catch(final Exception ex)
        {
            throw new IOException("Invalid ObjectId format: " + objId + " - " + ex.toString()); //$NON-NLS-1$ //$NON-NLS-2$
        }
    }
}

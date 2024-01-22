package es.uji.crypto.xades.jxades.util;

import java.util.Collections;
import java.util.List;
import java.util.Vector;

/**
 *
 * @author miro
 */
public class UniversalIndexKey implements Comparable<UniversalIndexKey> {

    private final Vector<Comparable> indexKeys;

    public UniversalIndexKey(final Comparable ... comparableValues)
    {
        final int size = comparableValues.length;
        if(size < 1)
		 {
			throw new IllegalArgumentException("The minimum number of parameters for constructing of UniversalIndexKey is 1."); //$NON-NLS-1$
		}

        this.indexKeys = new Vector<>(size);
        Collections.addAll(this.indexKeys, comparableValues);
    }

    @Override
	public int compareTo(final UniversalIndexKey other)
    {
        if(other == null)
        {
            throw new NullPointerException();
        }

        final int thisSize = this.indexKeys.size();
        final int otherSize = other.indexKeys.size();

//System.out.println("compareTo: indexKeys.size(): " + indexKeys.size() + ", other.indexKeys.size(): " + other.indexKeys.size());

        final int size = thisSize <= otherSize ? thisSize : otherSize;
        for(int i = 0; i < size; i++)
        {
            final Comparable firstComparable = this.indexKeys.get(i);
            final Comparable secondComparable = other.indexKeys.get(i);

            if(firstComparable == null) {
				return Integer.MIN_VALUE;
			}

            if(secondComparable == null) {
				return Integer.MAX_VALUE;
			}

            try
            {
                final int compareResult = firstComparable.compareTo(secondComparable);
//                System.out.println((i + 1) + ". " + firstComparable + " ? " + secondComparable + " = " + compareResult);
                if(compareResult != 0) {
					return compareResult;
				}
            }
            catch(final ClassCastException ex)
            {
                final String s1 = String.valueOf(firstComparable);
                final String s2 = String.valueOf(secondComparable);
                System.out.println("s1: " + s1 + ", s2: " + s2); //$NON-NLS-1$ //$NON-NLS-2$
                return s1.compareTo(s2);
            }
        }

        if(thisSize < otherSize)
        {
            return -1;
        }

        if(thisSize > otherSize)
        {
            return 1;
        }

        return 0;
    }

    @Override
	public boolean equals(final Object otherObject)
    {
        if(otherObject == null || !(otherObject instanceof UniversalIndexKey)) {
            return false;
        }

        final UniversalIndexKey other = (UniversalIndexKey)otherObject;

        final int thisSize = this.indexKeys.size();
        final int otherSize = other.indexKeys.size();

//System.out.println("equals: indexKeys.size(): " + indexKeys.size() + ", other.indexKeys.size(): " + other.indexKeys.size());

        if(thisSize != otherSize) {
			return false;
		}

        for(int i = 0; i < thisSize; i++)
        {
            final Comparable firstComparable = this.indexKeys.get(i);
            final Comparable secondComparable = other.indexKeys.get(i);

            if(firstComparable == null && secondComparable == null) {
				return true;
			}

            if(firstComparable == null == (secondComparable != null)) {
				return false;
			}

            final boolean equalsResult = firstComparable.equals(secondComparable);
            if(!equalsResult) {
				return equalsResult;
			}
        }

        return true;
    }

    public List<Comparable> getKeys()
    {
        return this.indexKeys;
    }

    public Comparable getKey(final int keyIndex)
    {
        return this.indexKeys.get(keyIndex);
    }



    public static String getMinString(final int length)
    {
        return getMinString(null, length);
    }

    public static String getMinString(final String source)
    {
        return getMinString(source, 0);
    }

    public static String getMinString(final String source, final int length)
    {
        if(length < 1 && (source == null || source.length() <= 0))
		 {
			throw new IllegalArgumentException("The lenght can not be less or equal to 0."); //$NON-NLS-1$
		}

        int maxLength = length;
        if(source != null && source.length() > length) {
			maxLength = source.length();
		}

        final StringBuilder sb = new StringBuilder(maxLength);
        if(source != null)
        {
            sb.append(source.substring(0, source.length() - 1));
        }
        while(sb.length() < maxLength)
        {
            sb.append(Character.MIN_VALUE);
        }

        return sb.toString();
    }

    public static String getMaxString(final int length)
    {
        return getMaxString(null, length);
    }

    public static String getMaxString(final String source)
    {
        return getMaxString(source, 0);
    }

    public static String getMaxString(final String source, final int length)
    {
        if(length < 1 && (source == null || source.length() <= 0))
		 {
			throw new IllegalArgumentException("The lenght can not be less or equal to 0."); //$NON-NLS-1$
		}

        int maxLength = length;
        if(source != null && source.length() > length) {
			maxLength = source.length();
		}

        final StringBuilder sb = new StringBuilder(maxLength);
        if(source != null)
        {
            sb.append(source.substring(0, source.length() - 1));
        }
        while(sb.length() < maxLength)
        {
            sb.append(Character.MAX_VALUE);
        }

        return sb.toString();
    }


    public static void main(final String[] args)
    {
        System.out.println("getMaxString(\"123\", 3): " + getMaxString("123", 3)); //$NON-NLS-1$ //$NON-NLS-2$
        System.out.println("getMaxString(\"123\", 2): " + getMaxString("123", 2)); //$NON-NLS-1$ //$NON-NLS-2$
        System.out.println("getMaxString(\"123\", 5): " + getMaxString("123", 5)); //$NON-NLS-1$ //$NON-NLS-2$
        System.out.println("getMaxString(NULL, 5): " + getMaxString(null, 5)); //$NON-NLS-1$
        System.out.println("getMaxString(7): " + getMaxString(7)); //$NON-NLS-1$
        System.out.println("getMaxString(\"1234\"): " + getMaxString("1234")); //$NON-NLS-1$ //$NON-NLS-2$
    }
}

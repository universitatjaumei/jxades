package es.uji.crypto.xades.jxades.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * <p>
 * Title:
 * </p>
 *
 * <p>
 * Description:
 * </p>
 *
 * <p>
 * Copyright: Copyright (c) 2006
 * </p>
 *
 * <p>
 * Company:
 * </p>
 *
 * @author not attributable
 * @version 1.0
 */
public class SystemUtils
{
    private static final String KEY_PREFIX = "com.cosmos"; //$NON-NLS-1$
    public static final String KEY_APPLICATION_NAME = KEY_PREFIX + ".apps.name"; //$NON-NLS-1$
    public static final String KEY_CLIENT_CONFIG_FOLDER = KEY_PREFIX + ".apps.client.config.folder"; //$NON-NLS-1$
    public static final String KEY_KEYSTORE_FOLDER = KEY_PREFIX + ".key.store.folder"; //$NON-NLS-1$
    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray(); //$NON-NLS-1$
    private static final char[] EMPTY_CHAR_ARRAY = {};

    private static DateFormat dateFormat;
    private static DecimalFormat decimalFormat;

    private static DateFormat getDateFormatter()
    {
        if (dateFormat == null)
        {
            // String dateFormatString = ResourceBundleManager.getString("Default_Date_Formatter",
            // "yyyy-MM-dd'T'HH:mm:ssZ");
            // dateFormat = new SimpleDateFormat(dateFormatString);
            dateFormat = new ISO8601DateFormat();
        }
        return dateFormat;
    }

    public static String formatDate(final Object date)
    {
        return getDateFormatter().format(date);
    }

    public static String formatDate(final Date date)
    {
        return getDateFormatter().format(date);
    }

    public static Date parseDate(final String dateString) throws ParseException
    {
        DateFormat dateFormat = getDateFormatter();
        try
        {
            return dateFormat.parse(dateString);
        }
        catch (final ParseException ex)
        {
            dateFormat = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss z"); //$NON-NLS-1$
            return dateFormat.parse(dateString);
        }
    }

    public static DecimalFormat getDecimalFormatter()
    {
        if (decimalFormat == null)
        {
            decimalFormat = new DecimalFormat("#,##0.##"); //$NON-NLS-1$
        }
        return decimalFormat;
    }

    public static String getCauseMessages(final Throwable ex)
    {
        if (ex == null) {
			return null;
		}

        final StringBuilder sb = new StringBuilder();
        sb.append(getErrorMessage(ex)).append("; \n"); //$NON-NLS-1$

        Throwable cause = ex.getCause();
        while (cause != null)
        {
            final String message = getErrorMessage(cause);
            if (message != null)
            {
                sb.append(message).append("; \n"); //$NON-NLS-1$
            }
            cause = cause.getCause();
        }

        return sb.toString();
    }

    public static String getErrorMessage(final Throwable ex)
    {
        if (ex == null) {
			return null;
		}
		String message = ex.getMessage();
		if (message == null) {
			message = ex.getClass().getName();
		}
		return message;
    }

    public static byte[] toByteArray(final InputStream inStream) throws IOException
    {
        if (inStream == null) {
			return null;
		}

        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        copy(inStream, os);

        return os.toByteArray();
    }

    public static void copy(InputStream inStream, final OutputStream outStream) throws IOException
    {
        if (inStream == null) {
			throw new IllegalArgumentException("InputStream can not be NULL in copy method."); //$NON-NLS-1$
		}
        if (outStream == null) {
			throw new IllegalArgumentException("OutputStream can not be NULL in copy method."); //$NON-NLS-1$
		}

        byte[] buffer = new byte[1024];
        int read = 0;

        try
        {
            while ((read = inStream.read(buffer)) >= 0)
            {
                outStream.write(buffer, 0, read);
            }
            outStream.flush();
        }
        finally
        {
            buffer = null;
            inStream.close();
            inStream = null;
            outStream.close();
        }
    }

    public static String trimFileName(final String filePathName)
    {
        if (filePathName == null) {
			return filePathName;
		}

        final StringBuilder sb = new StringBuilder(filePathName);
        int size = sb.length();
        char ch;
        while (size > 0 && ((ch = sb.charAt(size - 1)) == '.' || ch == File.separatorChar))
        {
            size--;
            sb.setLength(size);
        }
        return sb.toString();
    }

    public static String getOSName()
    {
        return System.getProperty("os.name"); //$NON-NLS-1$
    }

    public static String getIOTempDir()
    {
        return System.getProperty("java.io.tmpdir"); //$NON-NLS-1$
    }

    public static String getUserHome()
    {
        return System.getProperty("user.home"); //$NON-NLS-1$
    }

    public static String toHexString(final byte[] data)
    {
        return new String(toHexChars(data));
    }

    public static char[] toHexChars(final byte[] data)
    {
        if (data == null || data.length <= 0) {
			return EMPTY_CHAR_ARRAY;
		}

        final int size = data.length;
        final char[] result = new char[size << 1];

        for (int i = 0, j = 0; i < size; i++)
        {
            final int ch = data[i];
            result[j++] = HEX_DIGITS[(ch & 0xF0) >>> 4];
            result[j++] = HEX_DIGITS[ch & 0x0F];
        }

        return result;
    }
}

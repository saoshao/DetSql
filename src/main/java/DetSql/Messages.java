/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql;

import java.util.Locale;
import java.util.ResourceBundle;

/**
 * Internationalization support for DetSql
 * Manages localized messages for UI and logging
 */
public class Messages {
    private static ResourceBundle bundle;
    // Resource bundle path: src/main/resources/DetSql/messages_*.properties
    private static final String BUNDLE_NAME = "DetSql/messages";

    static {
        try {
            // Try to load Chinese locale first
            bundle = ResourceBundle.getBundle(BUNDLE_NAME, Locale.SIMPLIFIED_CHINESE);
        } catch (Exception e) {
            // Fallback to default locale
            try {
                bundle = ResourceBundle.getBundle(BUNDLE_NAME, Locale.getDefault());
            } catch (Exception ex) {
                // Use English as last resort
                bundle = ResourceBundle.getBundle(BUNDLE_NAME, Locale.ENGLISH);
            }
        }
    }

    /**
     * Get localized message by key
     * @param key message key
     * @return localized message, or key itself if not found
     */
    public static String get(String key) {
        try {
            return bundle.getString(key);
        } catch (Exception e) {
            return key;
        }
    }

    /**
     * Get localized message with parameters
     * @param key message key
     * @param params parameters to format into message
     * @return formatted localized message
     */
    public static String get(String key, Object... params) {
        try {
            String message = bundle.getString(key);
            return String.format(message, params);
        } catch (Exception e) {
            return key;
        }
    }

    /**
     * Change locale at runtime
     * @param locale new locale to use
     */
    public static void setLocale(Locale locale) {
        try {
            bundle = ResourceBundle.getBundle(BUNDLE_NAME, locale);
        } catch (Exception e) {
            LogHelper.logError("Failed to load locale: " + locale, e);
        }
    }

    // Common message keys as constants
    public static final String MANUAL_STOP = "status.manual_stop";
    public static final String RUNNING = "status.running";
    public static final String COMPLETED = "status.completed";
    public static final String ERROR = "status.error";
}

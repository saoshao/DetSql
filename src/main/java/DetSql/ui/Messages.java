/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.ui;

import java.util.Locale;
import java.util.ResourceBundle;
import DetSql.logging.LogHelper;


/**
 * Internationalization support for DetSql
 * Manages localized messages for UI and logging
 */
public class Messages {
    private static ResourceBundle bundle;
    // Resource bundle path: src/main/resources/i18n/messages_*.properties
    private static final String BUNDLE_NAME = "i18n/messages";

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
     * 获取本地化消息
     * @param key 消息键
     * @return 本地化消息，如果未找到则返回键本身
     */
    public static String get(String key) {
        try {
            return bundle.getString(key);
        } catch (Exception e) {
            return key;
        }
    }
    
    /**
     * 获取本地化消息（别名方法）
     * @param key 消息键
     * @return 本地化消息
     */
    public static String getString(String key) {
        return get(key);
    }

    /**
     * 获取带参数的本地化消息
     * @param key 消息键
     * @param params 格式化参数
     * @return 格式化后的本地化消息
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
     * 获取带参数的本地化消息（别名方法）
     * @param key 消息键
     * @param params 格式化参数
     * @return 格式化后的本地化消息
     */
    public static String getString(String key, Object... params) {
        return get(key, params);
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

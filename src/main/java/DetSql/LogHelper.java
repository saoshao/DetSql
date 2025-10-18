/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql;

import burp.api.montoya.MontoyaApi;

/**
 * Centralized logging utility for DetSql
 * Replaces scattered printStackTrace() calls with proper logging
 */
public class LogHelper {
    private static MontoyaApi api;

    /**
     * Initialize the logger with Burp API
     * Must be called during extension initialization
     */
    public static void initialize(MontoyaApi montoyaApi) {
        api = montoyaApi;
    }

    /**
     * Log error message with exception details
     */
    public static void logError(String message, Throwable throwable) {
        if (api != null) {
            api.logging().logToError(message + ": " + throwable.getMessage());
            api.logging().logToError(getStackTraceString(throwable));
        } else {
            System.err.println(message + ": " + throwable.getMessage());
            throwable.printStackTrace();
        }
    }

    /**
     * Log error message
     */
    public static void logError(String message) {
        if (api != null) {
            api.logging().logToError(message);
        } else {
            System.err.println(message);
        }
    }

    /**
     * Log info message
     */
    public static void logInfo(String message) {
        if (api != null) {
            api.logging().logToOutput(message);
        } else {
            System.out.println(message);
        }
    }

    /**
     * Log debug message (only in verbose mode)
     */
    public static void logDebug(String message) {
        if (api != null) {
            // Only log debug in development
            // api.logging().logToOutput("[DEBUG] " + message);
        }
    }

    /**
     * Convert stack trace to string
     */
    private static String getStackTraceString(Throwable throwable) {
        StringBuilder sb = new StringBuilder();
        for (StackTraceElement element : throwable.getStackTrace()) {
            sb.append("\tat ").append(element.toString()).append("\n");
        }
        return sb.toString();
    }
}

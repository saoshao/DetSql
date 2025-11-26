/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.logging;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Centralized logging system for DetSql
 * Provides level-based logging with timestamps
 *
 * Usage:
 *   DetSqlLogger logger = new DetSqlLogger(api);
 *   logger.setLogLevel(LogLevel.INFO);  // Set minimum level
 *   logger.info("Request processed");
 *   logger.debug("Parameter value: " + value);  // Only logged if level <= DEBUG
 *   logger.error("Detection failed", exception);
 */
public class DetSqlLogger {
    private final MontoyaApi api;
    private final Logging logging;
    private volatile LogLevel currentLevel;

    private static final DateTimeFormatter TIME_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * Creates a new logger instance
     * Reads default log level from system property 'detsql.log.level'
     * Falls back to INFO if not set or invalid
     * @param api Burp Montoya API
     */
    public DetSqlLogger(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.currentLevel = getDefaultLogLevel();
    }

    /**
     * Reads default log level from configuration
     * Priority: System property > Config file > Hardcoded default (OFF)
     * Can be set via: mvn clean package -Ddetsql.log.level=DEBUG
     * @return configured log level or OFF (disabled) as default
     */
    private LogLevel getDefaultLogLevel() {
        // 1. Try system property (runtime override)
        String levelStr = System.getProperty("detsql.log.level");
        
        // 2. Try config file (compile-time setting)
        if (levelStr == null) {
            levelStr = readLogLevelFromConfig();
        }
        
        // 3. Fall back to OFF
        if (levelStr == null) {
            return LogLevel.OFF;
        }
        
        try {
            return LogLevel.valueOf(levelStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            // Invalid level, fall back to OFF (disabled)
            return LogLevel.OFF;
        }
    }

    /**
     * Reads log level from detsql.properties file
     * @return log level string or null if not found
     */
    private String readLogLevelFromConfig() {
        try {
            java.io.InputStream is = getClass().getClassLoader()
                .getResourceAsStream("detsql.properties");
            if (is != null) {
                java.util.Properties props = new java.util.Properties();
                props.load(is);
                is.close();
                return props.getProperty("log.level");
            }
        } catch (Exception e) {
            // Ignore, will use default
        }
        return null;
    }

    /**
     * Sets the minimum log level
     * Only messages at this level or higher will be logged
     * @param level minimum log level
     */
    public void setLogLevel(LogLevel level) {
        this.currentLevel = level;
    }

    /**
     * Gets the current log level
     * @return current minimum log level
     */
    public LogLevel getLogLevel() {
        return currentLevel;
    }

    /**
     * Logs a DEBUG message
     * Use for detailed diagnostic information
     * @param message the message to log
     */
    public void debug(String message) {
        log(LogLevel.DEBUG, message);
    }

    /**
     * Logs an INFO message
     * Use for general informational messages
     * @param message the message to log
     */
    public void info(String message) {
        log(LogLevel.INFO, message);
    }

    /**
     * Logs a message that always outputs regardless of log level
     * Use for critical startup information, version info, etc.
     * @param message the message to log
     */
    public void always(String message) {
        String timestamp = LocalDateTime.now().format(TIME_FORMATTER);
        String formattedMessage = String.format("[%s] [INFO] %s",
            timestamp, message);

        if (logging != null) {
            logging.logToOutput(formattedMessage);
        } else {
            System.out.println(formattedMessage);
        }
    }

    /**
     * Logs a WARN message
     * Use for potentially problematic situations
     * @param message the message to log
     */
    public void warn(String message) {
        log(LogLevel.WARN, message);
    }

    /**
     * Logs an ERROR message
     * Use for error conditions
     * @param message the message to log
     */
    public void error(String message) {
        log(LogLevel.ERROR, message);
    }

    /**
     * Logs an ERROR message with exception details
     * Includes full stack trace
     * @param message the message to log
     * @param throwable the exception to log
     */
    public void error(String message, Throwable throwable) {
        if (!LogLevel.ERROR.shouldLog(currentLevel)) {
            return;
        }

        String timestamp = LocalDateTime.now().format(TIME_FORMATTER);
        String fullMessage = String.format("[%s] [ERROR] %s: %s",
            timestamp, message, throwable.getMessage());

        if (logging != null) {
            logging.logToError(fullMessage);
            logging.logToError(getStackTraceString(throwable));
        } else {
            System.err.println(fullMessage);
            throwable.printStackTrace();
        }
    }

    /**
     * Internal log method
     * Formats and outputs log message if level is enabled
     */
    private void log(LogLevel level, String message) {
        if (!level.shouldLog(currentLevel)) {
            return;
        }

        String timestamp = LocalDateTime.now().format(TIME_FORMATTER);
        String formattedMessage = String.format("[%s] [%s] %s",
            timestamp, level.name(), message);

        if (logging != null) {
            // Only ERROR goes to error panel, WARN/INFO/DEBUG go to output panel
            if (level == LogLevel.ERROR) {
                logging.logToError(formattedMessage);
            } else {
                logging.logToOutput(formattedMessage);
            }
        } else {
            // Fallback if Burp API not available
            if (level == LogLevel.ERROR) {
                System.err.println(formattedMessage);
            } else {
                System.out.println(formattedMessage);
            }
        }
    }

    /**
     * Converts exception stack trace to string
     */
    private String getStackTraceString(Throwable throwable) {
        StringBuilder sb = new StringBuilder();
        for (StackTraceElement element : throwable.getStackTrace()) {
            sb.append("\tat ").append(element.toString()).append("\n");
        }
        return sb.toString();
    }
}

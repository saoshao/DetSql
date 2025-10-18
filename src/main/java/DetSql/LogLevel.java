/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql;

/**
 * Log levels for DetSql logger
 * Controls verbosity of logging output
 */
public enum LogLevel {
    /**
     * Detailed diagnostic information for debugging
     * Use for tracing parameter values, similarity scores, etc.
     */
    DEBUG(0),

    /**
     * General informational messages about normal operation
     * Use for request processing, detection start/complete, etc.
     */
    INFO(1),

    /**
     * Warning messages for potentially problematic situations
     * Use for large response bodies, filter warnings, etc.
     */
    WARN(2),

    /**
     * Error messages for failures and exceptions
     * Use for HTTP errors, detection failures, etc.
     */
    ERROR(3),

    /**
     * Logging disabled
     * No log messages will be output
     */
    OFF(999);

    private final int priority;

    LogLevel(int priority) {
        this.priority = priority;
    }

    /**
     * Checks if this level should be logged given the minimum level
     * @param minLevel the minimum level configured
     * @return true if this level >= minLevel
     */
    public boolean shouldLog(LogLevel minLevel) {
        return this.priority >= minLevel.priority;
    }
}

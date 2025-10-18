/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Default configuration constants for DetSql extension
 * Eliminates duplication of default suffix lists and error injection payloads
 */
public final class DefaultConfig {

    // Private constructor to prevent instantiation
    private DefaultConfig() {
        throw new AssertionError("Utility class should not be instantiated");
    }

    /**
     * Default file suffix list - used to filter out static resources
     * This list is repeated 3 times in original code (lines 176-180, 694-698, 626)
     */
    public static final String DEFAULT_SUFFIX_LIST =
        "wma|csv|mov|doc|3g2|mp4|7z|3gp|xbm|jar|avi|ogv|mpv2|tiff|pnm|jpg|" +
        "xpm|xul|epub|au|aac|midi|weba|tar|js|rtf|bin|woff|wmv|tif|css|gif|" +
        "flv|ttf|html|eot|ods|odt|webm|mpg|mjs|bz|ics|ras|aifc|mpa|ppt|mpeg|" +
        "pptx|oga|ra|aiff|asf|woff2|snd|xwd|csh|webp|xlsx|mpkg|vsd|mid|wav|" +
        "svg|mp3|bz2|ico|jpe|pbm|gz|pdf|log|jpeg|rmi|txt|arc|rm|ppm|cod|jfif|" +
        "ram|docx|mpe|odp|otf|pgm|cmx|m3u|mp2|cab|rar|bmp|rgb|png|azw|ogx|aif|" +
        "zip|ief|htm|xls|mpp|swf|rmvb|abw";

    /**
     * Default suffix set - pre-split for direct use
     */
    public static final Set<String> DEFAULT_SUFFIX_SET = new HashSet<>(
        Arrays.asList(DEFAULT_SUFFIX_LIST.split("\\|"))
    );

    /**
     * Default error injection payloads for URL/BODY/COOKIE parameters
     * Single quotes and double quotes with various encodings
     */
    public static final String[] DEFAULT_ERR_POCS = {
        "'", "%27", "%DF'", "%DF%27",
        "\"", "%22", "%DF\"", "%DF%22",
        "`"
    };

    /**
     * Default error injection payloads for JSON/XML parameters
     * Includes escaped quotes and Unicode-encoded quotes for JSON compatibility
     */
    public static final String[] DEFAULT_ERR_POCS_JSON = {
        "'", "%27", "%DF'", "%DF%27",
        "\\\"", "%22", "%DF\\\"", "%DF%22",
        "\\u0022", "%DF\\u0022", "\\u0027", "%DF\\u0027",
        "`"
    };

    /**
     * Default timing configuration (in milliseconds)
     */
    public static final int DEFAULT_DELAY_TIME_MS = 1_000_000;  // 1000 seconds
    public static final int DEFAULT_STATIC_TIME_MS = 100;        // 100ms fixed interval
    public static final int DEFAULT_START_TIME_MS = 0;           // Random range start
    public static final int DEFAULT_END_TIME_MS = 0;             // Random range end
}

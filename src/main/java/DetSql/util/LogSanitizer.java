package DetSql.util;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 日志脱敏工具类
 * 
 * <p>用于在日志输出前移除敏感信息，防止密码、令牌等敏感数据泄漏到日志文件中。
 * 
 * @author DetSql Team
 * @version 4.0.0
 * @since 4.0.0
 */
public class LogSanitizer {
    
    /**
     * 敏感参数名称列表（不区分大小写）
     */
    private static final Set<String> SENSITIVE_KEYS = Set.of(
        "password", "passwd", "pwd",
        "token", "auth", "authorization",
        "session", "sessionid", "jsessionid",
        "cookie", "api_key", "apikey",
        "secret", "private_key", "privatekey",
        "access_token", "refresh_token",
        "client_secret", "api_secret"
    );
    
    private static final String MASK = "***";
    
    /**
     * 脱敏参数 Map
     */
    public static String sanitizeParams(Map<String, String> params) {
        if (params == null || params.isEmpty()) {
            return "{}";
        }
        
        return params.entrySet().stream()
            .map(e -> e.getKey() + "=" + 
                (isSensitive(e.getKey()) ? MASK : truncateValue(e.getValue())))
            .collect(Collectors.joining(", ", "{", "}"));
    }
    
    /**
     * 判断键名是否敏感
     */
    private static boolean isSensitive(String key) {
        if (key == null) {
            return false;
        }
        String lowerKey = key.toLowerCase();
        return SENSITIVE_KEYS.stream()
            .anyMatch(lowerKey::contains);
    }
    
    /**
     * 截断过长的值
     */
    private static String truncateValue(String value) {
        if (value == null) {
            return "null";
        }
        if (value.length() > 100) {
            return value.substring(0, 100) + "...[truncated]";
        }
        return value;
    }
    
    /**
     * 脱敏 URL（隐藏查询参数值）
     */
    public static String sanitizeUrl(String url) {
        if (url == null || !url.contains("?")) {
            return url;
        }
        
        int queryStart = url.indexOf('?');
        String base = url.substring(0, queryStart);
        String query = url.substring(queryStart + 1);
        
        String sanitizedQuery = java.util.Arrays.stream(query.split("&"))
            .map(param -> {
                int eqPos = param.indexOf('=');
                if (eqPos > 0) {
                    String key = param.substring(0, eqPos);
                    return key + "=" + (isSensitive(key) ? MASK : "...");
                }
                return param;
            })
            .collect(Collectors.joining("&"));
        
        return base + "?" + sanitizedQuery;
    }
}

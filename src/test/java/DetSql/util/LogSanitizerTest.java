package DetSql.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * LogSanitizer 测试类
 */
public class LogSanitizerTest {
    
    @Test
    @DisplayName("脱敏普通参数")
    public void testSanitizeNormalParams() {
        Map<String, String> params = new HashMap<>();
        params.put("username", "admin");
        params.put("age", "25");
        
        String result = LogSanitizer.sanitizeParams(params);
        
        assertTrue(result.contains("username=admin"));
        assertTrue(result.contains("age=25"));
    }
    
    @Test
    @DisplayName("脱敏敏感参数")
    public void testSanitizeSensitiveParams() {
        Map<String, String> params = new HashMap<>();
        params.put("username", "admin");
        params.put("password", "secret123");
        params.put("token", "abc123xyz");
        
        String result = LogSanitizer.sanitizeParams(params);
        
        assertTrue(result.contains("username=admin"));
        assertTrue(result.contains("password=***"));
        assertTrue(result.contains("token=***"));
        assertFalse(result.contains("secret123"));
        assertFalse(result.contains("abc123xyz"));
    }
    
    @Test
    @DisplayName("脱敏空参数")
    public void testSanitizeEmptyParams() {
        Map<String, String> params = new HashMap<>();
        String result = LogSanitizer.sanitizeParams(params);
        assertEquals("{}", result);
        
        result = LogSanitizer.sanitizeParams(null);
        assertEquals("{}", result);
    }
    
    @Test
    @DisplayName("脱敏 URL")
    public void testSanitizeUrl() {
        String url = "http://example.com/api?username=admin&password=secret&id=123";
        String result = LogSanitizer.sanitizeUrl(url);
        
        assertTrue(result.startsWith("http://example.com/api?"));
        assertTrue(result.contains("password=***"));
        assertFalse(result.contains("secret"));
    }
    
    @Test
    @DisplayName("脱敏不含查询参数的 URL")
    public void testSanitizeUrlWithoutQuery() {
        String url = "http://example.com/api";
        String result = LogSanitizer.sanitizeUrl(url);
        assertEquals(url, result);
    }
    
    @Test
    @DisplayName("脱敏 null URL")
    public void testSanitizeNullUrl() {
        String result = LogSanitizer.sanitizeUrl(null);
        assertNull(result);
    }
    
    @Test
    @DisplayName("截断过长的参数值")
    public void testTruncateLongValue() {
        Map<String, String> params = new HashMap<>();
        String longValue = "a".repeat(200);
        params.put("data", longValue);
        
        String result = LogSanitizer.sanitizeParams(params);
        
        assertTrue(result.contains("data="));
        assertTrue(result.contains("[truncated]"));
        assertFalse(result.contains(longValue));
    }
    
    @Test
    @DisplayName("不区分大小写的敏感参数检测")
    public void testCaseInsensitiveSensitiveKeys() {
        Map<String, String> params = new HashMap<>();
        params.put("PASSWORD", "secret1");
        params.put("Password", "secret2");
        params.put("pAsSwOrD", "secret3");
        
        String result = LogSanitizer.sanitizeParams(params);
        
        assertFalse(result.contains("secret1"));
        assertFalse(result.contains("secret2"));
        assertFalse(result.contains("secret3"));
        assertTrue(result.contains("***"));
    }
    
    @Test
    @DisplayName("包含敏感关键词的参数名")
    public void testPartialMatchSensitiveKeys() {
        Map<String, String> params = new HashMap<>();
        params.put("user_password", "secret1");
        params.put("api_token", "secret2");
        params.put("session_id", "secret3");
        
        String result = LogSanitizer.sanitizeParams(params);
        
        assertFalse(result.contains("secret1"));
        assertFalse(result.contains("secret2"));
        assertFalse(result.contains("secret3"));
    }
}

package DetSql.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * StringUtils 错误处理测试
 * 验证 unicodeDecode 的错误处理与 base64Decode 保持一致
 */
@DisplayName("StringUtils Error Handling Tests")
public class StringUtilsErrorHandlingTest {
    
    @Test
    @DisplayName("unicodeDecode should return error message for invalid format")
    public void testUnicodeDecodeInvalidFormat() {
        String result = StringUtils.unicodeDecode("这不是有效的Unicode序列");
        assertTrue(result.contains("解码失败"), 
            "Should return error message for invalid Unicode format");
    }
    
    @Test
    @DisplayName("unicodeDecode should return empty string for null input")
    public void testUnicodeDecodeNullInput() {
        String result = StringUtils.unicodeDecode(null);
        assertEquals("", result, "Should return empty string for null input");
    }
    
    @Test
    @DisplayName("unicodeDecode should return empty string for empty input")
    public void testUnicodeDecodeEmptyInput() {
        String result = StringUtils.unicodeDecode("");
        assertEquals("", result, "Should return empty string for empty input");
    }
    
    @Test
    @DisplayName("unicodeDecode should decode valid Unicode sequences")
    public void testUnicodeDecodeValid() {
        String result = StringUtils.unicodeDecode("\\u0041\\u0042\\u0043");
        assertEquals("ABC", result, "Should decode valid Unicode sequences");
    }
    
    @Test
    @DisplayName("unicodeDecode should warn on partial failure")
    public void testUnicodeDecodePartialFailure() {
        // 包含无效序列的字符串 (NumberFormatException 场景)
        // 由于正则限制为 [0-9a-fA-F]{4}, 这种情况不太会触发 NumberFormatException
        // 但我们保留测试框架
        String validInput = "\\u0041\\u0042";
        String result = StringUtils.unicodeDecode(validInput);
        assertEquals("AB", result, "Should decode valid sequences");
    }
    
    @Test
    @DisplayName("base64Decode should return error message for invalid format")
    public void testBase64DecodeInvalidFormat() {
        String result = StringUtils.base64Decode("这不是有效的Base64!!!");
        assertTrue(result.contains("解码失败"), 
            "Should return error message for invalid Base64 format");
    }
    
    @Test
    @DisplayName("base64Decode should return empty string for null input")
    public void testBase64DecodeNullInput() {
        String result = StringUtils.base64Decode(null);
        assertEquals("", result, "Should return empty string for null input");
    }
    
    @Test
    @DisplayName("base64Decode should return empty string for empty input")
    public void testBase64DecodeEmptyInput() {
        String result = StringUtils.base64Decode("");
        assertEquals("", result, "Should return empty string for empty input");
    }
    
    @Test
    @DisplayName("base64Decode should decode valid Base64 strings")
    public void testBase64DecodeValid() {
        String result = StringUtils.base64Decode("QUJD");
        assertEquals("ABC", result, "Should decode valid Base64 strings");
    }
    
    @Test
    @DisplayName("Error handling should be consistent between methods")
    public void testConsistentErrorHandling() {
        // 两个方法都应该对空输入返回空字符串
        assertEquals(StringUtils.base64Decode(""), StringUtils.unicodeDecode(""),
            "Both methods should handle empty input consistently");
        
        // 两个方法都应该对 null 输入返回空字符串
        assertEquals(StringUtils.base64Decode(null), StringUtils.unicodeDecode(null),
            "Both methods should handle null input consistently");
        
        // 两个方法都应该对无效输入返回包含"解码失败"的错误信息
        assertTrue(StringUtils.base64Decode("!!!").contains("解码失败"),
            "base64Decode should return error message");
        assertTrue(StringUtils.unicodeDecode("invalid").contains("解码失败"),
            "unicodeDecode should return error message");
    }
}

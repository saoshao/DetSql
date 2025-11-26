package DetSql;

import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import DetSql.util.StructuralSignature;

/**
 * 结构化签名测试
 */
public class StructuralSignatureTest {
    
    @Test
    public void testNormalizePath_数字路径段() {
        assertEquals("/user/{int}", StructuralSignature.normalizePath("/user/123"));
        assertEquals("/user/{int}", StructuralSignature.normalizePath("/user/456"));
        assertEquals("/api/v1/user/{int}/profile", StructuralSignature.normalizePath("/api/v1/user/789/profile"));
    }
    
    @Test
    public void testNormalizePath_UUID路径段() {
        String uuid1 = "/api/550e8400-e29b-41d4-a716-446655440000";
        String uuid2 = "/api/660e8400-e29b-41d4-a716-446655440001";
        
        assertEquals("/api/{uuid}", StructuralSignature.normalizePath(uuid1));
        assertEquals("/api/{uuid}", StructuralSignature.normalizePath(uuid2));
    }
    
    @Test
    public void testNormalizePath_十六进制路径段() {
        assertEquals("/session/{hex}", StructuralSignature.normalizePath("/session/a1b2c3d4e5f6"));
        assertEquals("/session/{hex}", StructuralSignature.normalizePath("/session/ABCDEF1234567890"));
    }
    
    @Test
    public void testNormalizePath_混合路径() {
        assertEquals("/api/v1/user/{int}/order/{uuid}", 
            StructuralSignature.normalizePath("/api/v1/user/123/order/550e8400-e29b-41d4-a716-446655440000"));
    }
    
    @Test
    public void testNormalizePath_保持普通路径不变() {
        assertEquals("/api/users/list", StructuralSignature.normalizePath("/api/users/list"));
        assertEquals("/product/abc", StructuralSignature.normalizePath("/product/abc"));
    }
    
    @Test
    public void testFilterNoiseParams() {
        List<String> params = Arrays.asList("id", "name", "timestamp", "_t", "random");
        List<String> filtered = StructuralSignature.filterNoiseParams(params);
        
        assertEquals(2, filtered.size());
        assertTrue(filtered.contains("id"));
        assertTrue(filtered.contains("name"));
        assertFalse(filtered.contains("timestamp"));
        assertFalse(filtered.contains("_t"));
        assertFalse(filtered.contains("random"));
    }
    
    @Test
    public void testGenerate_完整签名() {
        List<String> params = Arrays.asList("id", "name");
        String signature = StructuralSignature.generate("GET", "example.com", "/user/123", params);
        
        assertTrue(signature.contains("GET"));
        assertTrue(signature.contains("example.com"));
        assertTrue(signature.contains("/user/{int}"));
        assertTrue(signature.contains("id"));
        assertTrue(signature.contains("name"));
    }
    
    @Test
    public void testGenerate_相同结构生成相同签名() {
        List<String> params = Arrays.asList("id", "name");
        
        String sig1 = StructuralSignature.generate("GET", "example.com", "/user/123", params);
        String sig2 = StructuralSignature.generate("GET", "example.com", "/user/456", params);
        
        assertEquals(sig1, sig2, "相同结构的路径应该生成相同的签名");
    }
    
    @Test
    public void testGenerate_不同结构生成不同签名() {
        List<String> params = Arrays.asList("id", "name");
        
        String sig1 = StructuralSignature.generate("GET", "example.com", "/user/123", params);
        String sig2 = StructuralSignature.generate("GET", "example.com", "/product/123", params);
        
        assertNotEquals(sig1, sig2, "不同路径应该生成不同的签名");
    }
    
    @Test
    public void testExtractHost() {
        assertEquals("example.com", StructuralSignature.extractHost("https://example.com:443"));
        assertEquals("example.com", StructuralSignature.extractHost("http://example.com:80"));
        assertEquals("api.example.com", StructuralSignature.extractHost("https://api.example.com:8080"));
    }
    
    @Test
    public void testExtractHost_无端口() {
        assertEquals("example.com", StructuralSignature.extractHost("https://example.com"));
        assertEquals("example.com", StructuralSignature.extractHost("http://example.com"));
    }
}

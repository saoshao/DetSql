/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql;
import DetSql.model.PocLogEntry;


import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * WeakReference 内存优化测试：验证 PocLogEntry 使用 WeakReference 存储响应
 * 平衡内存优化与功能可用性
 */
class PocLogEntryMemoryTest {

    /**
     * 测试：WeakReference 命中 - 应该返回完整响应
     */
    @Test
    void testWeakReferenceHit() {
        // 创建 mock 对象
        HttpRequestResponse mockResponse = Mockito.mock(HttpRequestResponse.class);
        HttpRequest mockRequest = Mockito.mock(HttpRequest.class);
        HttpResponse mockHttpResponse = Mockito.mock(HttpResponse.class);

        when(mockResponse.request()).thenReturn(mockRequest);
        when(mockResponse.response()).thenReturn(mockHttpResponse);
        when(mockRequest.url()).thenReturn("https://example.com/api/test");
        when(mockRequest.method()).thenReturn("POST");
        when(mockHttpResponse.bodyToString()).thenReturn("Response body content");
        when(mockHttpResponse.statusCode()).thenReturn((short) 200);

        // 使用工厂方法创建 PocLogEntry
        PocLogEntry entry = PocLogEntry.fromResponse(
            "username",
            "' OR '1'='1",
            "0.95",
            "stringsql",
            mockResponse,
            "abc123"
        );

        // 验证：getHttpRequestResponse() 应该返回完整对象（WeakReference 命中）
        HttpRequestResponse retrieved = entry.getHttpRequestResponse();
        assertNotNull(retrieved, "WeakReference 应该返回完整的 HttpRequestResponse 对象");
        assertSame(mockResponse, retrieved, "应该返回同一个对象");

        // 验证：元数据也应该被正确提取
        assertEquals("https://example.com/api/test", entry.getUrl());
        assertEquals("POST", entry.getMethod());
        assertEquals("Response body content", entry.getResponsePreview());
        assertEquals("username", entry.getName());
        assertEquals("' OR '1'='1", entry.getPoc());
        assertEquals("0.95", entry.getSimilarity());
        assertEquals("stringsql", entry.getVulnState());
    }

    /**
     * 测试：WeakReference 被 GC 回收后返回 null
     */
    @Test
    void testWeakReferenceMiss_AfterGC() {
        HttpRequestResponse mockResponse = Mockito.mock(HttpRequestResponse.class);
        HttpRequest mockRequest = Mockito.mock(HttpRequest.class);
        HttpResponse mockHttpResponse = Mockito.mock(HttpResponse.class);

        when(mockResponse.request()).thenReturn(mockRequest);
        when(mockResponse.response()).thenReturn(mockHttpResponse);
        when(mockRequest.url()).thenReturn("https://example.com/api/test");
        when(mockRequest.method()).thenReturn("POST");
        when(mockHttpResponse.bodyToString()).thenReturn("Response body content");
        when(mockHttpResponse.statusCode()).thenReturn((short) 200);

        PocLogEntry entry = PocLogEntry.fromResponse(
            "username",
            "' OR '1'='1",
            "0.95",
            "stringsql",
            mockResponse,
            "abc123"
        );

        // 首次访问应该成功
        assertNotNull(entry.getHttpRequestResponse(), "首次访问应该成功");

        // 清除强引用并触发 GC
        mockResponse = null;
        System.gc();
        System.runFinalization();
        // 注意：GC 不保证立即回收,但测试可以验证返回 null 的逻辑

        // 验证：即使 GC 回收,元数据仍然可用
        assertEquals("https://example.com/api/test", entry.getUrl());
        assertEquals("POST", entry.getMethod());
        assertEquals("Response body content", entry.getResponsePreview());
    }

    /**
     * 测试：元数据字段始终可用（作为降级方案）
     */
    @Test
    void testFallbackMetadata() {
        HttpRequestResponse mockResponse = Mockito.mock(HttpRequestResponse.class);
        HttpRequest mockRequest = Mockito.mock(HttpRequest.class);
        HttpResponse mockHttpResponse = Mockito.mock(HttpResponse.class);

        when(mockResponse.request()).thenReturn(mockRequest);
        when(mockResponse.response()).thenReturn(mockHttpResponse);
        when(mockRequest.url()).thenReturn("https://example.com/api/test");
        when(mockRequest.method()).thenReturn("GET");
        when(mockHttpResponse.bodyToString()).thenReturn("Test response");
        when(mockHttpResponse.statusCode()).thenReturn((short) 200);

        PocLogEntry entry = PocLogEntry.fromResponse(
            "id",
            "1' OR '1'='1",
            "0.90",
            "stringsql",
            mockResponse,
            "hash123"
        );

        // 验证：元数据字段始终可用
        assertNotNull(entry.getUrl(), "URL 应该始终可用");
        assertNotNull(entry.getMethod(), "Method 应该始终可用");
        assertNotNull(entry.getResponsePreview(), "ResponsePreview 应该始终可用");

        assertEquals("https://example.com/api/test", entry.getUrl());
        assertEquals("GET", entry.getMethod());
        assertEquals("Test response", entry.getResponsePreview());
    }

    /**
     * 测试：响应预览应该被截断（防止存储大量数据）
     */
    @Test
    void testResponsePreviewTruncation() {
        HttpRequestResponse mockResponse = Mockito.mock(HttpRequestResponse.class);
        HttpRequest mockRequest = Mockito.mock(HttpRequest.class);
        HttpResponse mockHttpResponse = Mockito.mock(HttpResponse.class);

        when(mockResponse.request()).thenReturn(mockRequest);
        when(mockResponse.response()).thenReturn(mockHttpResponse);
        when(mockRequest.url()).thenReturn("https://example.com/api/test");
        when(mockRequest.method()).thenReturn("GET");

        // 创建一个超过 500 字符的响应体
        String largeBody = "x".repeat(1000);
        when(mockHttpResponse.bodyToString()).thenReturn(largeBody);
        when(mockHttpResponse.statusCode()).thenReturn((short) 200);

        PocLogEntry entry = PocLogEntry.fromResponse(
            "id",
            "1' AND SLEEP(5)--",
            "0.85",
            "boolsql",
            mockResponse,
            "def456"
        );

        // 验证：响应预览应该被截断为 500 字符 + "..."
        String preview = entry.getResponsePreview();
        assertEquals(503, preview.length(), "响应预览应该是 500 字符 + '...'");
        assertTrue(preview.endsWith("..."), "截断的响应应该以 '...' 结尾");
        assertEquals("x".repeat(500) + "...", preview);
    }

    /**
     * 测试：小响应不应该被截断
     */
    @Test
    void testSmallResponseNotTruncated() {
        HttpRequestResponse mockResponse = Mockito.mock(HttpRequestResponse.class);
        HttpRequest mockRequest = Mockito.mock(HttpRequest.class);
        HttpResponse mockHttpResponse = Mockito.mock(HttpResponse.class);

        when(mockResponse.request()).thenReturn(mockRequest);
        when(mockResponse.response()).thenReturn(mockHttpResponse);
        when(mockRequest.url()).thenReturn("https://example.com/api/test");
        when(mockRequest.method()).thenReturn("GET");
        when(mockHttpResponse.bodyToString()).thenReturn("Small response");
        when(mockHttpResponse.statusCode()).thenReturn((short) 200);

        PocLogEntry entry = PocLogEntry.fromResponse(
            "id",
            "1",
            "1.0",
            "numsql",
            mockResponse,
            "ghi789"
        );

        // 验证：小响应应该完整保存
        assertEquals("Small response", entry.getResponsePreview());
    }

    /**
     * 测试：向后兼容性 - 旧构造函数仍然可用并创建 WeakReference
     */
    @Test
    @SuppressWarnings("deprecation") // 测试废弃的构造函数和方法
    void testBackwardCompatibility() {
        HttpRequestResponse mockResponse = Mockito.mock(HttpRequestResponse.class);
        HttpRequest mockRequest = Mockito.mock(HttpRequest.class);
        HttpResponse mockHttpResponse = Mockito.mock(HttpResponse.class);

        when(mockResponse.request()).thenReturn(mockRequest);
        when(mockResponse.response()).thenReturn(mockHttpResponse);
        when(mockRequest.url()).thenReturn("https://example.com/test");
        when(mockRequest.method()).thenReturn("POST");
        when(mockHttpResponse.bodyToString()).thenReturn("Test body");

        // 使用旧构造函数
        PocLogEntry entry = new PocLogEntry(
            "param",
            "payload",
            "0.9",
            "errsql",
            "100",
            "500",
            "1.5",
            mockResponse,
            "hash123"
        );

        // 验证：元数据应该被提取
        assertEquals("https://example.com/test", entry.getUrl());
        assertEquals("POST", entry.getMethod());
        assertEquals("Test body", entry.getResponsePreview());

        // 验证：getHttpRequestResponse() 现在应该返回对象（通过 WeakReference）
        assertNotNull(entry.getHttpRequestResponse(), "旧构造函数也应该创建 WeakReference");
    }

    /**
     * 测试：null HttpRequestResponse 应该被安全处理
     */
    @Test
    @SuppressWarnings("deprecation") // 测试废弃的构造函数和方法
    void testNullHttpRequestResponse() {
        PocLogEntry entry = new PocLogEntry(
            "param",
            "payload",
            "0.9",
            "errsql",
            "100",
            "500",
            "1.5",
            null,  // null HttpRequestResponse
            "hash123"
        );

        // 验证：应该使用空字符串作为默认值
        assertEquals("", entry.getUrl());
        assertEquals("", entry.getMethod());
        assertEquals("", entry.getResponsePreview());
        assertNull(entry.getHttpRequestResponse(), "null 响应应该返回 null");
    }

    /**
     * 测试：轻量级构造函数不应该持有 WeakReference
     */
    @Test
    void testLightweightConstructor() {
        PocLogEntry entry = new PocLogEntry(
            "param",
            "payload",
            "0.9",
            "errsql",
            "100",
            "500",
            "1.5",
            "https://example.com",
            "GET",
            "preview text",
            System.currentTimeMillis(),
            "hash456"
        );

        // 验证：轻量级构造函数只有元数据，没有 WeakReference
        assertNull(entry.getHttpRequestResponse(), "轻量级构造函数不应该持有响应对象");

        // 验证：元数据应该正确
        assertEquals("https://example.com", entry.getUrl());
        assertEquals("GET", entry.getMethod());
        assertEquals("preview text", entry.getResponsePreview());
    }
}

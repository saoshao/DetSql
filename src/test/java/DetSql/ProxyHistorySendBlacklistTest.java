package DetSql;

import DetSql.ui.MyFilterRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * 测试用户报告的问题: Proxy History 多选发送到 DetSQL 时域名黑名单不生效
 *
 * 用户配置的黑名单: datasink.baidu.com,s.union.360.cn,weixin.qq.com,www.google.com
 *
 * 预期行为:
 * 1. 被动监听 (Proxy) 时黑名单生效 ✅
 * 2. 主动发送 (Send to DetSQL) 时黑名单也应该生效 ✅
 */
public class ProxyHistorySendBlacklistTest {

    // 用户报告的黑名单域名
    private static final String[] USER_REPORTED_DOMAINS = {
        "datasink.baidu.com",
        "s.union.360.cn",
        "weixin.qq.com",
        "www.google.com"
    };

    @BeforeEach
    public void setUp() {
        // 重置过滤规则
        MyFilterRequest.whiteListSet = new HashSet<>();
        MyFilterRequest.blackListSet = new HashSet<>();
        MyFilterRequest.blackPathSet = new HashSet<>();
        MyFilterRequest.blackParamsSet = new HashSet<>();
        MyFilterRequest.unLegalExtensionSet = new HashSet<>();

        // 配置用户报告的黑名单
        MyFilterRequest.blackListSet = Set.of(USER_REPORTED_DOMAINS);
    }

    /**
     * 测试1: 验证黑名单配置已正确加载
     */
    @Test
    public void testBlacklistConfiguration() {
        assertEquals(4, MyFilterRequest.blackListSet.size(), "黑名单应包含4个域名");

        for (String domain : USER_REPORTED_DOMAINS) {
            assertTrue(MyFilterRequest.blackListSet.contains(domain),
                "黑名单应包含 " + domain);
        }
    }

    /**
     * 测试2: 从 Proxy History 发送黑名单域名的请求应该被过滤
     */
    @Test
    public void testProxyHistorySend_BlacklistDomain_ShouldBeFiltered() {
        for (String domain : USER_REPORTED_DOMAINS) {
            HttpRequestResponse request = createMockRequest(domain, "/api/test?id=1");

            boolean shouldProcess = MyFilterRequest.filterOneRequest(request);

            assertFalse(shouldProcess, "域名 " + domain + " 应该被黑名单过滤");

            // 同时验证 matchesBlackList 返回 true
            assertTrue(MyFilterRequest.matchesBlackList(request),
                "matchesBlackList 应该对 " + domain + " 返回 true");
        }
    }

    /**
     * 测试3: 黑名单域名的子域名也应该被过滤
     */
    @Test
    public void testProxyHistorySend_BlacklistSubdomain_ShouldBeFiltered() {
        // 测试子域名匹配
        String[][] testCases = {
            {"api.datasink.baidu.com", "datasink.baidu.com"},
            {"cdn.s.union.360.cn", "s.union.360.cn"},
            {"api.weixin.qq.com", "weixin.qq.com"},
            {"mail.google.com", "www.google.com"}  // 注意: 这个可能不匹配
        };

        for (String[] testCase : testCases) {
            String subdomain = testCase[0];
            String parentDomain = testCase[1];

            HttpRequestResponse request = createMockRequest(subdomain, "/api/test?id=1");

            // 检查域名匹配逻辑
            boolean domainMatches = MyFilterRequest.blackListSet.stream()
                .anyMatch(pattern -> {
                    String hostLower = subdomain.toLowerCase();
                    String patternLower = pattern.toLowerCase();
                    return hostLower.equals(patternLower) ||
                           hostLower.endsWith("." + patternLower);
                });

            if (domainMatches) {
                assertFalse(MyFilterRequest.filterOneRequest(request),
                    "子域名 " + subdomain + " 应该被黑名单过滤");
            }
        }
    }

    /**
     * 测试4: 非黑名单域名应该通过过滤
     */
    @Test
    public void testProxyHistorySend_NonBlacklistDomain_ShouldPass() {
        String[] allowedDomains = {
            "example.com",
            "test.example.com",
            "api.github.com"
        };

        for (String domain : allowedDomains) {
            HttpRequestResponse request = createMockRequest(domain, "/api/test?id=1");

            boolean shouldProcess = MyFilterRequest.filterOneRequest(request);

            assertTrue(shouldProcess, "域名 " + domain + " 不在黑名单中,应该通过过滤");

            // 同时验证 matchesBlackList 返回 false
            assertFalse(MyFilterRequest.matchesBlackList(request),
                "matchesBlackList 应该对 " + domain + " 返回 false");
        }
    }

    /**
     * 测试5: 精确匹配 - www.google.com vs google.com
     */
    @Test
    public void testExactDomainMatching() {
        // 黑名单中是 www.google.com
        HttpRequestResponse wwwRequest = createMockRequest("www.google.com", "/search?q=test");
        HttpRequestResponse rootRequest = createMockRequest("google.com", "/search?q=test");

        // www.google.com 应该被过滤
        assertFalse(MyFilterRequest.filterOneRequest(wwwRequest),
            "www.google.com 应该被黑名单过滤");

        // google.com 不应该被过滤 (因为黑名单是 www.google.com)
        assertTrue(MyFilterRequest.filterOneRequest(rootRequest),
            "google.com 不在黑名单中,应该通过过滤");
    }

    /**
     * 测试6: 大小写不敏感
     */
    @Test
    public void testCaseInsensitiveMatching() {
        String[][] testCases = {
            {"datasink.baidu.com", "datasink.baidu.com"},
            {"datasink.baidu.com", "datasink.baidu.com"},
            {"Weixin.QQ.com", "weixin.qq.com"}
        };

        for (String[] testCase : testCases) {
            String upperDomain = testCase[0];
            HttpRequestResponse request = createMockRequest(upperDomain, "/api/test?id=1");

            assertFalse(MyFilterRequest.filterOneRequest(request),
                "域名匹配应该不区分大小写: " + upperDomain);
        }
    }

    /**
     * 测试7: 批量请求场景 - 模拟用户从 Proxy History 多选发送
     */
    @Test
    public void testBatchSend_MixedDomains() {
        HttpRequestResponse[] requests = {
            createMockRequest("datasink.baidu.com", "/track?id=1"),      // 黑名单
            createMockRequest("example.com", "/api/users?id=1"),        // 允许
            createMockRequest("s.union.360.cn", "/ad?id=1"),           // 黑名单
            createMockRequest("api.github.com", "/repos?id=1"),         // 允许
            createMockRequest("weixin.qq.com", "/msg?id=1"),           // 黑名单
        };

        int filtered = 0;
        int passed = 0;

        for (HttpRequestResponse request : requests) {
            if (MyFilterRequest.filterOneRequest(request)) {
                passed++;
            } else {
                filtered++;
            }
        }

        assertEquals(3, filtered, "应该有3个请求被过滤 (黑名单)");
        assertEquals(2, passed, "应该有2个请求通过过滤");
    }

    /**
     * 测试8: 验证 volatile 可见性 - 黑名单更新后立即生效
     */
    @Test
    public void testBlacklistUpdate_ImmediatelyEffective() {
        // 初始黑名单为空
        MyFilterRequest.blackListSet = new HashSet<>();

        HttpRequestResponse request = createMockRequest("new-blocked.com", "/api?id=1");

        // 应该通过过滤
        assertTrue(MyFilterRequest.filterOneRequest(request),
            "黑名单为空时应该通过");

        // 更新黑名单
        MyFilterRequest.blackListSet = Set.of("new-blocked.com");

        // 应该立即被过滤
        assertFalse(MyFilterRequest.filterOneRequest(request),
            "更新黑名单后应该立即生效");
    }

    // ==================== Helper Methods ====================

    /**
     * 创建模拟的 HttpRequestResponse 对象
     */
    private HttpRequestResponse createMockRequest(String host, String path) {
        HttpService httpService = Mockito.mock(HttpService.class);
        Mockito.when(httpService.host()).thenReturn(host);
        Mockito.when(httpService.port()).thenReturn(443);
        Mockito.when(httpService.secure()).thenReturn(true);

        HttpRequest httpRequest = Mockito.mock(HttpRequest.class);
        Mockito.when(httpRequest.httpService()).thenReturn(httpService);
        Mockito.when(httpRequest.method()).thenReturn("GET");
        Mockito.when(httpRequest.path()).thenReturn(path);
        Mockito.when(httpRequest.pathWithoutQuery()).thenReturn(path.split("\\?")[0]);
        Mockito.when(httpRequest.url()).thenReturn("https://" + host + path);
        Mockito.when(httpRequest.hasParameters()).thenReturn(path.contains("?"));
        Mockito.when(httpRequest.fileExtension()).thenReturn("");
        Mockito.when(httpRequest.bodyToString()).thenReturn("");

        // Mock parameters - 参考 ManualRequestFilterTest 的正确做法
        if (path.contains("?")) {
            ParsedHttpParameter mockParam = Mockito.mock(ParsedHttpParameter.class);
            Mockito.when(mockParam.name()).thenReturn("id");
            Mockito.when(httpRequest.parameters(HttpParameterType.URL)).thenReturn(List.of(mockParam));
        } else {
            Mockito.when(httpRequest.parameters(HttpParameterType.URL)).thenReturn(List.of());
        }
        Mockito.when(httpRequest.parameters(HttpParameterType.BODY)).thenReturn(List.of());
        Mockito.when(httpRequest.parameters(HttpParameterType.JSON)).thenReturn(List.of());
        Mockito.when(httpRequest.parameters(HttpParameterType.XML)).thenReturn(List.of());

        HttpResponse httpResponse = Mockito.mock(HttpResponse.class);
        Mockito.when(httpResponse.bodyToString()).thenReturn("{\"success\":true}");

        HttpRequestResponse requestResponse = Mockito.mock(HttpRequestResponse.class);
        Mockito.when(requestResponse.request()).thenReturn(httpRequest);
        Mockito.when(requestResponse.response()).thenReturn(httpResponse);

        return requestResponse;
    }
}

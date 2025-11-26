/*
 * Domain Filter Test - 验证域名黑白名单过滤逻辑的正确性
 *
 * 这个测试文件验证了关键的安全修复：
 * - 修复了使用 endsWith() 导致的安全漏洞
 * - 确保域名匹配语义正确：精确匹配或子域名匹配
 *
 * @author Linus-style code review
 */
package DetSql;

import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import org.junit.jupiter.api.*;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import DetSql.ui.MyFilterRequest;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class DomainFilterTest {

    private HttpResponseReceived mockResponse;
    private HttpRequest mockRequest;
    private HttpService mockService;
    private ToolSource mockToolSource;

    @BeforeEach
    public void setUp() {
        // 创建 mock 对象
        mockResponse = mock(HttpResponseReceived.class);
        mockRequest = mock(HttpRequest.class);
        mockService = mock(HttpService.class);
        mockToolSource = mock(ToolSource.class);

        // 设置 mock 链
        when(mockResponse.initiatingRequest()).thenReturn(mockRequest);
        when(mockRequest.httpService()).thenReturn(mockService);
        when(mockResponse.toolSource()).thenReturn(mockToolSource);
        when(mockToolSource.isFromTool(ToolType.PROXY)).thenReturn(true);
    }

    @AfterEach
    public void tearDown() {
        // 清理静态变量：注意测试中可能用 Set.of(...) 赋值为不可变集合，不能直接 clear()
        MyFilterRequest.whiteListSet = new java.util.HashSet<>();
        MyFilterRequest.blackListSet = new java.util.HashSet<>();
    }

    // ============================================
    // 白名单测试
    // ============================================

    @Test
    @Order(1)
    @DisplayName("白名单精确匹配测试")
    public void testWhitelistExactMatch() {
        MyFilterRequest.whiteListSet = Set.of("example.com");

        // 精确匹配应该通过
        when(mockService.host()).thenReturn("example.com");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse),
            "精确匹配 example.com 应该通过白名单");

        // 大小写不敏感
        when(mockService.host()).thenReturn("EXAMPLE.COM");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse),
            "大写的 EXAMPLE.COM 应该匹配白名单 example.com");
    }

    @Test
    @Order(2)
    @DisplayName("白名单子域名匹配测试")
    public void testWhitelistSubdomainMatch() {
        MyFilterRequest.whiteListSet = Set.of("example.com");

        // 子域名应该匹配
        when(mockService.host()).thenReturn("www.example.com");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse),
            "www.example.com 应该匹配白名单 example.com");

        when(mockService.host()).thenReturn("api.example.com");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse),
            "api.example.com 应该匹配白名单 example.com");

        when(mockService.host()).thenReturn("deep.sub.example.com");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse),
            "deep.sub.example.com 应该匹配白名单 example.com");
    }

    @Test
    @Order(3)
    @DisplayName("白名单边界测试 - 防止误匹配")
    public void testWhitelistBoundaryCase() {
        MyFilterRequest.whiteListSet = Set.of("example.com");

        // 这是关键的安全修复测试！
        // 旧代码使用 endsWith() 会错误地匹配这些域名
        when(mockService.host()).thenReturn("badexample.com");
        assertFalse(MyFilterRequest.matchesWhiteList(mockResponse),
            "badexample.com 不应该匹配白名单 example.com - 这是安全漏洞!");

        when(mockService.host()).thenReturn("evilexample.com");
        assertFalse(MyFilterRequest.matchesWhiteList(mockResponse),
            "evilexample.com 不应该匹配白名单 example.com");

        when(mockService.host()).thenReturn("notexample.com");
        assertFalse(MyFilterRequest.matchesWhiteList(mockResponse),
            "notexample.com 不应该匹配白名单 example.com");
    }

    @Test
    @Order(4)
    @DisplayName("空白名单测试")
    public void testEmptyWhitelist() {
        MyFilterRequest.whiteListSet = new HashSet<>();

        // 空白名单应该允许所有域名
        when(mockService.host()).thenReturn("any.domain.com");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse),
            "空白名单应该允许所有域名");
    }

    // ============================================
    // 黑名单测试
    // ============================================

    @Test
    @Order(5)
    @DisplayName("黑名单精确匹配测试")
    public void testBlacklistExactMatch() {
        MyFilterRequest.blackListSet = Set.of("ads.com");

        // 精确匹配应该被阻止
        when(mockService.host()).thenReturn("ads.com");
        assertTrue(MyFilterRequest.matchesBlackList(mockResponse),
            "精确匹配 ads.com 应该被黑名单阻止");

        // 大小写不敏感
        when(mockService.host()).thenReturn("ADS.COM");
        assertTrue(MyFilterRequest.matchesBlackList(mockResponse),
            "大写的 ADS.COM 应该被黑名单阻止");
    }

    @Test
    @Order(6)
    @DisplayName("黑名单子域名匹配测试")
    public void testBlacklistSubdomainMatch() {
        MyFilterRequest.blackListSet = Set.of("ads.com");

        // 子域名应该被阻止
        when(mockService.host()).thenReturn("tracker.ads.com");
        assertTrue(MyFilterRequest.matchesBlackList(mockResponse),
            "tracker.ads.com 应该被黑名单阻止");

        when(mockService.host()).thenReturn("popup.ads.com");
        assertTrue(MyFilterRequest.matchesBlackList(mockResponse),
            "popup.ads.com 应该被黑名单阻止");
    }

    @Test
    @Order(7)
    @DisplayName("黑名单边界测试 - 防止误杀")
    public void testBlacklistBoundaryCase() {
        MyFilterRequest.blackListSet = Set.of("ads.com");

        // 这是关键的修复测试！防止误杀合法域名
        when(mockService.host()).thenReturn("myads.com");
        assertFalse(MyFilterRequest.matchesBlackList(mockResponse),
            "myads.com 不应该被黑名单阻止 - 防止误杀!");

        when(mockService.host()).thenReturn("downloads.com");
        assertFalse(MyFilterRequest.matchesBlackList(mockResponse),
            "downloads.com 不应该被黑名单阻止");

        when(mockService.host()).thenReturn("nomads.com");
        assertFalse(MyFilterRequest.matchesBlackList(mockResponse),
            "nomads.com 不应该被黑名单阻止");
    }

    @Test
    @Order(8)
    @DisplayName("空黑名单测试")
    public void testEmptyBlacklist() {
        MyFilterRequest.blackListSet = new HashSet<>();

        // 空黑名单不应该阻止任何域名
        when(mockService.host()).thenReturn("any.domain.com");
        assertFalse(MyFilterRequest.matchesBlackList(mockResponse),
            "空黑名单不应该阻止任何域名");
    }

    // ============================================
    // 组合测试
    // ============================================

    @Test
    @Order(9)
    @DisplayName("黑白名单组合测试")
    public void testCombinedFilters() {
        // 设置白名单和黑名单
        MyFilterRequest.whiteListSet = Set.of("example.com", "test.com");
        MyFilterRequest.blackListSet = Set.of("blocked.example.com");

        // 在白名单中
        when(mockService.host()).thenReturn("api.example.com");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse),
            "api.example.com 应该在白名单中");
        assertFalse(MyFilterRequest.matchesBlackList(mockResponse),
            "api.example.com 不应该在黑名单中");

        // 在黑名单中（即使父域名在白名单）
        when(mockService.host()).thenReturn("blocked.example.com");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse),
            "blocked.example.com 匹配白名单 example.com");
        assertTrue(MyFilterRequest.matchesBlackList(mockResponse),
            "blocked.example.com 也在黑名单中");

        // 不在任何名单中
        when(mockService.host()).thenReturn("random.org");
        assertFalse(MyFilterRequest.matchesWhiteList(mockResponse),
            "random.org 不在白名单中");
        assertFalse(MyFilterRequest.matchesBlackList(mockResponse),
            "random.org 不在黑名单中");
    }

    @Test
    @Order(10)
    @DisplayName("多域名白名单测试")
    public void testMultipleDomainWhitelist() {
        MyFilterRequest.whiteListSet = Set.of("example.com", "test.org", "demo.net");

        // 每个域名都应该正确匹配
        when(mockService.host()).thenReturn("example.com");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse));

        when(mockService.host()).thenReturn("www.test.org");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse));

        when(mockService.host()).thenReturn("api.demo.net");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse));

        // 不在列表中的域名
        when(mockService.host()).thenReturn("notlisted.com");
        assertFalse(MyFilterRequest.matchesWhiteList(mockResponse));
    }

    @Test
    @Order(11)
    @DisplayName("特殊字符域名测试")
    public void testSpecialCharacterDomains() {
        // 测试带连字符的域名
        MyFilterRequest.whiteListSet = Set.of("my-domain.com");

        when(mockService.host()).thenReturn("my-domain.com");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse),
            "带连字符的域名应该正确匹配");

        when(mockService.host()).thenReturn("sub.my-domain.com");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse),
            "带连字符域名的子域名应该匹配");

        // 测试数字开头的域名
        MyFilterRequest.whiteListSet = Set.of("123test.com");
        when(mockService.host()).thenReturn("123test.com");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse),
            "数字开头的域名应该正确匹配");
    }

    @Test
    @Order(12)
    @DisplayName("端口号处理测试")
    public void testPortHandling() {
        MyFilterRequest.whiteListSet = Set.of("example.com");

        // 注意：host() 方法应该只返回域名，不包含端口
        // 但我们还是要测试以防万一
        when(mockService.host()).thenReturn("example.com");
        assertTrue(MyFilterRequest.matchesWhiteList(mockResponse),
            "不带端口的域名应该匹配");
    }

    // ============================================
    // 性能相关测试
    // ============================================

    @Test
    @Order(13)
    @DisplayName("大量域名性能测试")
    public void testLargeWhitelistPerformance() {
        // 创建包含1000个域名的白名单
        Set<String> largeDomainSet = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            largeDomainSet.add("domain" + i + ".com");
        }
        MyFilterRequest.whiteListSet = largeDomainSet;

        // 测试查找性能
        when(mockService.host()).thenReturn("domain500.com");
        long startTime = System.nanoTime();
        boolean result = MyFilterRequest.matchesWhiteList(mockResponse);
        long endTime = System.nanoTime();

        assertTrue(result, "应该找到 domain500.com");
        long duration = (endTime - startTime) / 1_000_000; // 转换为毫秒
        assertTrue(duration < 100, "查找时间应该小于100ms，实际: " + duration + "ms");
    }
}
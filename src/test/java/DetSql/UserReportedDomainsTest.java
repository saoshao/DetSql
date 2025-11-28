/*
 * User Reported Domains Test - 验证用户报告的域名黑名单问题
 *
 * 用户报告: 域名黑名单 datasink.baidu.com,s.union.360.cn,weixin.qq.com,www.google.com 不生效
 * 测试目标: 验证这些域名在当前实现中是否能被正确过滤
 *
 * 测试场景:
 * 1. HttpResponseReceived (被动监听 Proxy/Repeater 流量)
 * 2. HttpRequestResponse (主动发送到 DetSql)
 *
 * @author DetSql Team
 */
package DetSql;

import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import org.junit.jupiter.api.*;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import DetSql.ui.MyFilterRequest;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class UserReportedDomainsTest {

    // 用户报告的4个域名
    private static final String[] USER_REPORTED_DOMAINS = {
        "datasink.baidu.com",
        "s.union.360.cn",
        "weixin.qq.com",
        "www.google.com"
    };

    // HttpResponseReceived 场景的 mock 对象
    private HttpResponseReceived mockHttpResponseReceived;
    private HttpRequest mockRequestForReceived;
    private HttpService mockServiceForReceived;
    private ToolSource mockToolSource;

    // HttpRequestResponse 场景的 mock 对象
    private HttpRequestResponse mockRequestResponse;
    private HttpRequest mockRequestForRR;
    private HttpResponse mockResponse;
    private HttpService mockServiceForRR;

    @BeforeEach
    public void setUp() {
        // 场景1: HttpResponseReceived (被动监听)
        mockHttpResponseReceived = mock(HttpResponseReceived.class);
        mockRequestForReceived = mock(HttpRequest.class);
        mockServiceForReceived = mock(HttpService.class);
        mockToolSource = mock(ToolSource.class);

        when(mockHttpResponseReceived.initiatingRequest()).thenReturn(mockRequestForReceived);
        when(mockRequestForReceived.httpService()).thenReturn(mockServiceForReceived);
        when(mockHttpResponseReceived.toolSource()).thenReturn(mockToolSource);
        when(mockToolSource.isFromTool(ToolType.PROXY)).thenReturn(true);

        // 场景2: HttpRequestResponse (主动发送)
        mockRequestResponse = mock(HttpRequestResponse.class);
        mockRequestForRR = mock(HttpRequest.class);
        mockResponse = mock(HttpResponse.class);
        mockServiceForRR = mock(HttpService.class);

        when(mockRequestResponse.request()).thenReturn(mockRequestForRR);
        when(mockRequestResponse.response()).thenReturn(mockResponse);
        when(mockRequestForRR.httpService()).thenReturn(mockServiceForRR);

        // 设置默认值使其通过其他过滤规则
        setupDefaultRequestForFiltering(mockRequestForRR);
    }

    private void setupDefaultRequestForFiltering(HttpRequest mockRequest) {
        when(mockRequest.method()).thenReturn("GET");
        when(mockRequest.fileExtension()).thenReturn("");
        when(mockRequest.pathWithoutQuery()).thenReturn("/api/test");
        when(mockRequest.bodyToString()).thenReturn("");

        // 模拟有参数
        ParsedHttpParameter mockParam = mock(ParsedHttpParameter.class);
        when(mockParam.name()).thenReturn("id");
        when(mockRequest.parameters(HttpParameterType.URL)).thenReturn(List.of(mockParam));
        when(mockRequest.parameters(HttpParameterType.BODY)).thenReturn(List.of());
        when(mockRequest.parameters(HttpParameterType.JSON)).thenReturn(List.of());
        when(mockRequest.parameters(HttpParameterType.XML)).thenReturn(List.of());

        // 设置响应
        when(mockResponse.bodyToString()).thenReturn("test response");
    }

    @AfterEach
    public void tearDown() {
        MyFilterRequest.whiteListSet = new java.util.HashSet<>();
        MyFilterRequest.blackListSet = new java.util.HashSet<>();
        MyFilterRequest.blackPathSet = new java.util.HashSet<>();
        MyFilterRequest.unLegalExtensionSet = new java.util.HashSet<>();
        MyFilterRequest.blackParamsSet = new java.util.HashSet<>();
    }

    // ============================================
    // 场景1: HttpResponseReceived (被动监听)
    // ============================================

    @Test
    @Order(1)
    @DisplayName("场景1 - matchesBlackList() 应识别用户报告的域名")
    public void testPassiveScenario_MatchesBlackList() {
        // 配置黑名单
        MyFilterRequest.blackListSet = Set.of(USER_REPORTED_DOMAINS);

        // 测试每个域名是否被 matchesBlackList() 识别
        for (String domain : USER_REPORTED_DOMAINS) {
            when(mockServiceForReceived.host()).thenReturn(domain);

            boolean isBlocked = MyFilterRequest.matchesBlackList(mockHttpResponseReceived);

            assertTrue(isBlocked,
                String.format("[被动监听] matchesBlackList() 应该返回 true 阻止域名: %s", domain));

            System.out.println(String.format("[测试] 被动监听场景 - 域名 %s 被 matchesBlackList() 正确识别", domain));
        }
    }

    @Test
    @Order(2)
    @DisplayName("场景1 - filterOneRequest() 应过滤用户报告的域名")
    public void testPassiveScenario_FilterOneRequest() {
        // 配置黑名单
        MyFilterRequest.blackListSet = Set.of(USER_REPORTED_DOMAINS);

        // 设置其他过滤条件为通过
        setupDefaultRequestForFiltering(mockRequestForReceived);

        // 测试每个域名是否被 filterOneRequest() 过滤
        for (String domain : USER_REPORTED_DOMAINS) {
            when(mockServiceForReceived.host()).thenReturn(domain);

            boolean shouldProcess = MyFilterRequest.filterOneRequest(mockHttpResponseReceived);

            assertFalse(shouldProcess,
                String.format("[被动监听] filterOneRequest() 应该返回 false 过滤域名: %s", domain));

            System.out.println(String.format("[测试] 被动监听场景 - 域名 %s 被 filterOneRequest() 正确过滤", domain));
        }
    }

    // ============================================
    // 场景2: HttpRequestResponse (主动发送)
    // ============================================

    @Test
    @Order(3)
    @DisplayName("场景2 - matchesBlackList() 应识别用户报告的域名")
    public void testActiveScenario_MatchesBlackList() {
        // 配置黑名单
        MyFilterRequest.blackListSet = Set.of(USER_REPORTED_DOMAINS);

        // 测试每个域名是否被 matchesBlackList() 识别
        for (String domain : USER_REPORTED_DOMAINS) {
            when(mockServiceForRR.host()).thenReturn(domain);

            boolean isBlocked = MyFilterRequest.matchesBlackList(mockRequestResponse);

            assertTrue(isBlocked,
                String.format("[主动发送] matchesBlackList() 应该返回 true 阻止域名: %s", domain));

            System.out.println(String.format("[测试] 主动发送场景 - 域名 %s 被 matchesBlackList() 正确识别", domain));
        }
    }

    @Test
    @Order(4)
    @DisplayName("场景2 - filterOneRequest() 应过滤用户报告的域名")
    public void testActiveScenario_FilterOneRequest() {
        // 配置黑名单
        MyFilterRequest.blackListSet = Set.of(USER_REPORTED_DOMAINS);

        // 测试每个域名是否被 filterOneRequest() 过滤
        for (String domain : USER_REPORTED_DOMAINS) {
            when(mockServiceForRR.host()).thenReturn(domain);

            boolean shouldProcess = MyFilterRequest.filterOneRequest(mockRequestResponse);

            assertFalse(shouldProcess,
                String.format("[主动发送] filterOneRequest() 应该返回 false 过滤域名: %s", domain));

            System.out.println(String.format("[测试] 主动发送场景 - 域名 %s 被 filterOneRequest() 正确过滤", domain));
        }
    }

    // ============================================
    // 回归测试: 验证空响应不会绕过黑名单
    // ============================================

    @Test
    @Order(5)
    @DisplayName("回归测试 - 空响应不应绕过黑名单 (commit d16dec4)")
    public void testEmptyResponseDoesNotBypassBlacklist() {
        // 这是 commit d16dec4 修复的问题
        // 验证空响应不会让黑名单被绕过
        MyFilterRequest.blackListSet = Set.of(USER_REPORTED_DOMAINS);

        // 模拟空响应
        when(mockResponse.bodyToString()).thenReturn("");

        for (String domain : USER_REPORTED_DOMAINS) {
            when(mockServiceForRR.host()).thenReturn(domain);

            boolean shouldProcess = MyFilterRequest.filterOneRequest(mockRequestResponse);

            assertFalse(shouldProcess,
                String.format("[回归测试] 即使响应为空,域名 %s 也应该被过滤", domain));
        }
    }

    // ============================================
    // 子域名测试
    // ============================================

    @Test
    @Order(6)
    @DisplayName("子域名测试 - 黑名单域名的子域名也应被过滤")
    public void testSubdomainFiltering() {
        MyFilterRequest.blackListSet = Set.of(USER_REPORTED_DOMAINS);

        // 测试子域名是否也被过滤
        String[] subdomains = {
            "api.datasink.baidu.com",
            "test.s.union.360.cn",
            "mp.weixin.qq.com",
            "mail.google.com"  // www.google.com 的兄弟域名不应被过滤
        };

        // api.datasink.baidu.com 应该被过滤
        when(mockServiceForRR.host()).thenReturn(subdomains[0]);
        assertTrue(MyFilterRequest.matchesBlackList(mockRequestResponse),
            subdomains[0] + " 应该被黑名单 datasink.baidu.com 过滤");

        // test.s.union.360.cn 应该被过滤
        when(mockServiceForRR.host()).thenReturn(subdomains[1]);
        assertTrue(MyFilterRequest.matchesBlackList(mockRequestResponse),
            subdomains[1] + " 应该被黑名单 s.union.360.cn 过滤");

        // mp.weixin.qq.com 应该被过滤
        when(mockServiceForRR.host()).thenReturn(subdomains[2]);
        assertTrue(MyFilterRequest.matchesBlackList(mockRequestResponse),
            subdomains[2] + " 应该被黑名单 weixin.qq.com 过滤");

        // mail.google.com 不应该被 www.google.com 过滤 (不是子域名关系)
        when(mockServiceForRR.host()).thenReturn(subdomains[3]);
        assertFalse(MyFilterRequest.matchesBlackList(mockRequestResponse),
            subdomains[3] + " 不应该被黑名单 www.google.com 过滤 (不是子域名关系)");
    }

    // ============================================
    // 边界测试: 防止误杀
    // ============================================

    @Test
    @Order(7)
    @DisplayName("边界测试 - 防止误杀相似域名")
    public void testBoundaryCase_NoFalsePositives() {
        MyFilterRequest.blackListSet = Set.of(USER_REPORTED_DOMAINS);

        // 这些域名看起来相似但不应该被过滤
        String[] similarDomains = {
            "baidu.com",           // datasink.baidu.com 的父域名
            "union.360.cn",        // s.union.360.cn 的父域名  
            "qq.com",              // weixin.qq.com 的父域名
            "google.com",          // www.google.com 的父域名
            "mydatasink.baidu.com" // 错误的前缀（不是子域名）
        };

        for (String domain : similarDomains) {
            when(mockServiceForRR.host()).thenReturn(domain);
            boolean isBlocked = MyFilterRequest.matchesBlackList(mockRequestResponse);

            // 这些域名不应该被过滤
            assertFalse(isBlocked,
                String.format("域名 %s 不应该被黑名单过滤 (防止误杀)", domain));
        }
    }

    // ============================================
    // 大小写不敏感测试
    // ============================================

    @Test
    @Order(8)
    @DisplayName("大小写不敏感 - 黑名单应不区分大小写")
    public void testCaseInsensitiveBlacklist() {
        MyFilterRequest.blackListSet = Set.of(USER_REPORTED_DOMAINS);

        String[][] caseVariations = {
            {"datasink.baidu.com", "datasink.baidu.com"},
            {"S.UNION.360.CN", "s.union.360.cn"},
            {"WEIXIN.QQ.COM", "weixin.qq.com"},
            {"WWW.GOOGLE.COM", "www.google.com"},
            {"datasink.baidu.com", "datasink.baidu.com"}
        };

        for (String[] variation : caseVariations) {
            String uppercaseDomain = variation[0];
            String originalDomain = variation[1];

            when(mockServiceForRR.host()).thenReturn(uppercaseDomain);
            boolean isBlocked = MyFilterRequest.matchesBlackList(mockRequestResponse);

            assertTrue(isBlocked,
                String.format("大写形式 %s 应该匹配黑名单 %s", uppercaseDomain, originalDomain));
        }
    }
}

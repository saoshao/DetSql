/*
 * Manual Request Filter Test - 验证主动发送请求的过滤逻辑
 *
 * 测试场景：从 Burp Proxy 历史中多选数据包，右键发送到 DetSql
 * 验证域名黑白名单、路径黑名单等过滤规则是否正确应用
 *
 * @author DetSql Team
 */
package DetSql;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import org.junit.jupiter.api.*;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import DetSql.ui.MyFilterRequest;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ManualRequestFilterTest {

    private HttpRequestResponse mockRequestResponse;
    private HttpRequest mockRequest;
    private HttpResponse mockResponse;
    private HttpService mockService;

    @BeforeEach
    public void setUp() {
        // 创建 mock 对象
        mockRequestResponse = mock(HttpRequestResponse.class);
        mockRequest = mock(HttpRequest.class);
        mockResponse = mock(HttpResponse.class);
        mockService = mock(HttpService.class);

        // 设置 mock 链
        when(mockRequestResponse.request()).thenReturn(mockRequest);
        when(mockRequestResponse.response()).thenReturn(mockResponse);
        when(mockRequest.httpService()).thenReturn(mockService);
        
        // 默认设置：GET 请求，有参数，正常响应
        when(mockRequest.method()).thenReturn("GET");
        when(mockRequest.fileExtension()).thenReturn("");
        when(mockRequest.pathWithoutQuery()).thenReturn("/api/test");
        when(mockRequest.bodyToString()).thenReturn(""); // 修复：返回空字符串而不是 null
        when(mockResponse.bodyToString()).thenReturn("test response");
        
        // 模拟 URL 参数
        ParsedHttpParameter mockParam = mock(ParsedHttpParameter.class);
        when(mockParam.name()).thenReturn("id");
        when(mockRequest.parameters(HttpParameterType.URL)).thenReturn(List.of(mockParam));
        when(mockRequest.parameters(HttpParameterType.BODY)).thenReturn(List.of());
        when(mockRequest.parameters(HttpParameterType.JSON)).thenReturn(List.of());
        when(mockRequest.parameters(HttpParameterType.XML)).thenReturn(List.of());
    }

    @AfterEach
    public void tearDown() {
        // 清理静态变量
        MyFilterRequest.whiteListSet = new java.util.HashSet<>();
        MyFilterRequest.blackListSet = new java.util.HashSet<>();
        MyFilterRequest.blackPathSet = new java.util.HashSet<>();
        MyFilterRequest.unLegalExtensionSet = new java.util.HashSet<>();
        MyFilterRequest.blackParamsSet = new java.util.HashSet<>();
    }

    @Test
    @Order(1)
    @DisplayName("主动发送 - 域名白名单过滤测试")
    public void testManualRequestWhitelistFilter() {
        MyFilterRequest.whiteListSet = Set.of("example.com");

        // 在白名单中的域名应该通过
        when(mockService.host()).thenReturn("api.example.com");
        assertTrue(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "白名单域名应该通过过滤");

        // 不在白名单中的域名应该被过滤
        when(mockService.host()).thenReturn("evil.com");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "非白名单域名应该被过滤");
    }

    @Test
    @Order(2)
    @DisplayName("主动发送 - 域名黑名单过滤测试")
    public void testManualRequestBlacklistFilter() {
        MyFilterRequest.blackListSet = Set.of("datasink.baidu.com", "s.union.360.cn", 
                                               "weixin.qq.com", "www.google.com");

        // 黑名单域名应该被过滤
        when(mockService.host()).thenReturn("datasink.baidu.com");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "黑名单域名 datasink.baidu.com 应该被过滤");

        when(mockService.host()).thenReturn("s.union.360.cn");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "黑名单域名 s.union.360.cn 应该被过滤");

        when(mockService.host()).thenReturn("weixin.qq.com");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "黑名单域名 weixin.qq.com 应该被过滤");

        when(mockService.host()).thenReturn("www.google.com");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "黑名单域名 www.google.com 应该被过滤");

        // 非黑名单域名应该通过
        when(mockService.host()).thenReturn("example.com");
        assertTrue(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "非黑名单域名应该通过过滤");
    }

    @Test
    @Order(3)
    @DisplayName("主动发送 - 黑名单子域名过滤测试")
    public void testManualRequestBlacklistSubdomain() {
        MyFilterRequest.blackListSet = Set.of("ads.com");

        // 黑名单域名的子域名也应该被过滤
        when(mockService.host()).thenReturn("tracker.ads.com");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "黑名单子域名 tracker.ads.com 应该被过滤");

        when(mockService.host()).thenReturn("popup.ads.com");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "黑名单子域名 popup.ads.com 应该被过滤");
    }

    @Test
    @Order(4)
    @DisplayName("主动发送 - 路径黑名单过滤测试（精确匹配）")
    public void testManualRequestPathBlacklist() {
        // 精确匹配：需要完整路径
        MyFilterRequest.blackPathSet = Set.of("/logout", "/admin/users");

        // 精确匹配的路径应该被过滤
        when(mockRequest.pathWithoutQuery()).thenReturn("/logout");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "黑名单路径 /logout 应该被过滤");

        // 精确匹配的路径应该被过滤
        when(mockRequest.pathWithoutQuery()).thenReturn("/admin/users");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "黑名单路径 /admin/users 应该被过滤");

        // 类似但不完全匹配的路径不应该被过滤
        when(mockRequest.pathWithoutQuery()).thenReturn("/admin/users/edit");
        assertTrue(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "路径 /admin/users/edit 与 /admin/users 不完全匹配，应该通过");

        // 非黑名单路径应该通过
        when(mockRequest.pathWithoutQuery()).thenReturn("/api/test");
        assertTrue(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "非黑名单路径应该通过过滤");
    }

    @Test
    @Order(5)
    @DisplayName("主动发送 - 文件扩展名过滤测试")
    public void testManualRequestExtensionFilter() {
        MyFilterRequest.unLegalExtensionSet = Set.of("jpg", "png", "css", "js");

        // 非法扩展名应该被过滤
        when(mockRequest.fileExtension()).thenReturn("jpg");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "非法扩展名 .jpg 应该被过滤");

        when(mockRequest.fileExtension()).thenReturn("css");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "非法扩展名 .css 应该被过滤");

        // 合法扩展名应该通过
        when(mockRequest.fileExtension()).thenReturn("");
        assertTrue(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "无扩展名应该通过过滤");

        when(mockRequest.fileExtension()).thenReturn("php");
        assertTrue(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "合法扩展名 .php 应该通过过滤");
    }

    @Test
    @Order(6)
    @DisplayName("主动发送 - 请求方法过滤测试")
    public void testManualRequestMethodFilter() {
        // GET 请求应该通过
        when(mockRequest.method()).thenReturn("GET");
        assertTrue(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "GET 请求应该通过过滤");

        // POST 请求应该通过
        when(mockRequest.method()).thenReturn("POST");
        when(mockRequest.parameters(HttpParameterType.BODY)).thenReturn(
            List.of(mock(ParsedHttpParameter.class)));
        assertTrue(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "POST 请求应该通过过滤");

        // PUT 请求应该通过
        when(mockRequest.method()).thenReturn("PUT");
        assertTrue(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "PUT 请求应该通过过滤");

        // DELETE 请求应该被过滤
        when(mockRequest.method()).thenReturn("DELETE");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "DELETE 请求应该被过滤");
    }

    @Test
    @Order(7)
    @DisplayName("主动发送 - 参数存在性检查")
    public void testManualRequestParameterCheck() {
        // 有参数的请求应该通过
        ParsedHttpParameter mockParam = mock(ParsedHttpParameter.class);
        when(mockParam.name()).thenReturn("id");
        when(mockRequest.parameters(HttpParameterType.URL)).thenReturn(List.of(mockParam));
        assertTrue(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "有参数的请求应该通过过滤");

        // 无参数的请求应该被过滤
        when(mockRequest.parameters(HttpParameterType.URL)).thenReturn(List.of());
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "无参数的请求应该被过滤");
    }

    @Test
    @Order(8)
    @DisplayName("主动发送 - 空响应不应绕过黑名单过滤")
    public void testEmptyResponseDoesNotBypassBlacklist() {
        // 回归测试: 验证空响应不会绕过域名黑名单检查
        // 问题场景: submitManualRequest()先检查响应大小,导致黑名单被跳过
        MyFilterRequest.blackListSet = Set.of("datasink.baidu.com", "s.union.360.cn");

        // 模拟空响应
        when(mockResponse.bodyToString()).thenReturn("");

        // 黑名单域名即使响应为空也应该被过滤
        when(mockService.host()).thenReturn("datasink.baidu.com");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "空响应的黑名单域名也应该被过滤");

        when(mockService.host()).thenReturn("s.union.360.cn");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "空响应的黑名单域名也应该被过滤");

        // 非黑名单域名即使响应为空也应该通过过滤规则检查
        when(mockService.host()).thenReturn("example.com");
        assertTrue(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "非黑名单域名应该通过过滤规则");
    }

    @Test
    @Order(9)
    @DisplayName("主动发送 - 组合过滤测试")
    public void testManualRequestCombinedFilters() {
        // 设置多个过滤规则
        MyFilterRequest.blackListSet = Set.of("ads.com");
        MyFilterRequest.blackPathSet = Set.of("/logout");
        MyFilterRequest.unLegalExtensionSet = Set.of("jpg", "png");

        // 正常请求应该通过
        when(mockService.host()).thenReturn("example.com");
        when(mockRequest.pathWithoutQuery()).thenReturn("/api/test");
        when(mockRequest.fileExtension()).thenReturn("");
        assertTrue(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "正常请求应该通过所有过滤");

        // 触发黑名单域名
        when(mockService.host()).thenReturn("ads.com");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "黑名单域名应该被过滤");

        // 恢复正常域名，触发路径黑名单
        when(mockService.host()).thenReturn("example.com");
        when(mockRequest.pathWithoutQuery()).thenReturn("/logout");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "黑名单路径应该被过滤");

        // 恢复正常路径，触发扩展名过滤
        when(mockRequest.pathWithoutQuery()).thenReturn("/api/test");
        when(mockRequest.fileExtension()).thenReturn("jpg");
        assertFalse(MyFilterRequest.filterOneRequest(mockRequestResponse),
            "非法扩展名应该被过滤");
    }

}

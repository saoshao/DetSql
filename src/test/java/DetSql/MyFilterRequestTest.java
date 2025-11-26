package DetSql;

import DetSql.ui.MyFilterRequest;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * 测试 MyFilterRequest 的过滤逻辑
 * 包括无效请求过滤和空 JSON/Array 检测
 */
public class MyFilterRequestTest {

    @BeforeEach
    void setUp() {
        // 清空所有配置集合,避免测试间相互影响
        MyFilterRequest.whiteListSet.clear();
        MyFilterRequest.blackListSet.clear();
        MyFilterRequest.blackPathSet.clear();
        MyFilterRequest.unLegalExtensionSet.clear();
        MyFilterRequest.blackParamsSet.clear();
    }

    /**
     * 测试无效请求过滤 - GET /?xxx=xxx 应该被过滤
     */
    @Test
    void testUselessRequest_SingleParamNameEqualsValue_ShouldFilter() {
        // 创建 mock 对象
        HttpResponseReceived response = mock(HttpResponseReceived.class);
        HttpRequest request = mock(HttpRequest.class);
        ParsedHttpParameter param = mock(ParsedHttpParameter.class);

        // 设置行为: GET /?xxx=xxx
        when(response.initiatingRequest()).thenReturn(request);
        when(request.method()).thenReturn("GET");
        when(param.name()).thenReturn("xxx");
        when(param.value()).thenReturn("xxx");
        when(request.parameters(HttpParameterType.URL)).thenReturn(Collections.singletonList(param));
        when(request.fileExtension()).thenReturn("");

        // 验证: hasParameters 应返回 false (因为是无效请求)
        assertFalse(MyFilterRequest.hasParameters(response),
            "单参数且 name==value 的请求应该被过滤");
    }

    /**
     * 测试正常请求 - GET /?id=1 应该通过
     */
    @Test
    void testNormalRequest_SingleParamNameNotEqualsValue_ShouldPass() {
        HttpResponseReceived response = mock(HttpResponseReceived.class);
        HttpRequest request = mock(HttpRequest.class);
        ParsedHttpParameter param = mock(ParsedHttpParameter.class);

        // 设置行为: GET /?id=1
        when(response.initiatingRequest()).thenReturn(request);
        when(request.method()).thenReturn("GET");
        when(param.name()).thenReturn("id");
        when(param.value()).thenReturn("1");
        when(request.parameters(HttpParameterType.URL)).thenReturn(Collections.singletonList(param));
        when(request.fileExtension()).thenReturn("");

        // 验证: hasParameters 应返回 true
        assertTrue(MyFilterRequest.hasParameters(response),
            "正常的单参数请求应该通过");
    }

    /**
     * 测试多参数请求 - GET /?a=a&b=b 应该通过（不处理多参数情况）
     */
    @Test
    void testMultipleParams_NameEqualsValue_ShouldPass() {
        HttpResponseReceived response = mock(HttpResponseReceived.class);
        HttpRequest request = mock(HttpRequest.class);
        ParsedHttpParameter param1 = mock(ParsedHttpParameter.class);
        ParsedHttpParameter param2 = mock(ParsedHttpParameter.class);

        // 设置行为: GET /?a=a&b=b
        when(response.initiatingRequest()).thenReturn(request);
        when(request.method()).thenReturn("GET");
        when(param1.name()).thenReturn("a");
        when(param1.value()).thenReturn("a");
        when(param2.name()).thenReturn("b");
        when(param2.value()).thenReturn("b");
        when(request.parameters(HttpParameterType.URL)).thenReturn(List.of(param1, param2));
        when(request.fileExtension()).thenReturn("");

        // 验证: hasParameters 应返回 true (多参数不处理)
        assertTrue(MyFilterRequest.hasParameters(response),
            "多参数请求即使 name==value 也应该通过");
    }

    /**
     * 测试空 JSON 对象 - POST {} 应该被过滤
     */
    @Test
    void testEmptyJson_ShouldFilter() {
        HttpResponseReceived response = mock(HttpResponseReceived.class);
        HttpRequest request = mock(HttpRequest.class);

        // 设置行为: POST with body "{}"
        when(response.initiatingRequest()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn("{}");
        when(request.parameters(HttpParameterType.BODY)).thenReturn(Collections.emptyList());
        when(request.parameters(HttpParameterType.JSON)).thenReturn(Collections.emptyList());
        when(request.parameters(HttpParameterType.XML)).thenReturn(Collections.emptyList());

        // 验证: hasParameters 应返回 false
        assertFalse(MyFilterRequest.hasParameters(response),
            "空 JSON 对象应该被过滤");
    }

    /**
     * 测试包含换行的空 JSON 对象 - POST {\n} 应该被过滤
     */
    @Test
    void testEmptyJsonWithNewline_ShouldFilter() {
        HttpResponseReceived response = mock(HttpResponseReceived.class);
        HttpRequest request = mock(HttpRequest.class);

        // 设置行为: POST with body "{\n  \n}"
        when(response.initiatingRequest()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn("{\n  \n}");
        when(request.parameters(HttpParameterType.BODY)).thenReturn(Collections.emptyList());
        when(request.parameters(HttpParameterType.JSON)).thenReturn(Collections.emptyList());
        when(request.parameters(HttpParameterType.XML)).thenReturn(Collections.emptyList());

        // 验证: hasParameters 应返回 false
        assertFalse(MyFilterRequest.hasParameters(response),
            "包含换行的空 JSON 对象应该被过滤");
    }

    /**
     * 测试空数组 - POST [] 应该被过滤
     */
    @Test
    void testEmptyArray_ShouldFilter() {
        HttpResponseReceived response = mock(HttpResponseReceived.class);
        HttpRequest request = mock(HttpRequest.class);

        // 设置行为: POST with body "[]"
        when(response.initiatingRequest()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn("[]");
        when(request.parameters(HttpParameterType.BODY)).thenReturn(Collections.emptyList());
        when(request.parameters(HttpParameterType.JSON)).thenReturn(Collections.emptyList());
        when(request.parameters(HttpParameterType.XML)).thenReturn(Collections.emptyList());

        // 验证: hasParameters 应返回 false
        assertFalse(MyFilterRequest.hasParameters(response),
            "空数组应该被过滤");
    }

    /**
     * 测试包含换行的空数组 - POST [\n] 应该被过滤
     */
    @Test
    void testEmptyArrayWithNewline_ShouldFilter() {
        HttpResponseReceived response = mock(HttpResponseReceived.class);
        HttpRequest request = mock(HttpRequest.class);

        // 设置行为: POST with body "[\n]"
        when(response.initiatingRequest()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn("[\n]");
        when(request.parameters(HttpParameterType.BODY)).thenReturn(Collections.emptyList());
        when(request.parameters(HttpParameterType.JSON)).thenReturn(Collections.emptyList());
        when(request.parameters(HttpParameterType.XML)).thenReturn(Collections.emptyList());

        // 验证: hasParameters 应返回 false
        assertFalse(MyFilterRequest.hasParameters(response),
            "包含换行的空数组应该被过滤");
    }

    /**
     * 测试 HttpRequestResponse 版本 - 无效请求过滤
     */
    @Test
    void testUselessRequest_HttpRequestResponse_ShouldFilter() {
        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        HttpRequest request = mock(HttpRequest.class);
        ParsedHttpParameter param = mock(ParsedHttpParameter.class);

        // 设置行为: GET /?test=test
        when(requestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("GET");
        when(param.name()).thenReturn("test");
        when(param.value()).thenReturn("test");
        when(request.parameters(HttpParameterType.URL)).thenReturn(Collections.singletonList(param));

        // 验证
        assertFalse(MyFilterRequest.hasParameters(requestResponse),
            "HttpRequestResponse: 单参数且 name==value 的请求应该被过滤");
    }

    /**
     * 测试 HttpRequestResponse 版本 - 空 JSON 过滤
     */
    @Test
    void testEmptyJson_HttpRequestResponse_ShouldFilter() {
        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        HttpRequest request = mock(HttpRequest.class);

        // 设置行为: POST with body "{\n  \n}"
        when(requestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn("{\n  \n}");
        when(request.parameters(HttpParameterType.BODY)).thenReturn(Collections.emptyList());
        when(request.parameters(HttpParameterType.JSON)).thenReturn(Collections.emptyList());
        when(request.parameters(HttpParameterType.XML)).thenReturn(Collections.emptyList());

        // 验证
        assertFalse(MyFilterRequest.hasParameters(requestResponse),
            "HttpRequestResponse: 包含换行的空 JSON 应该被过滤");
    }
}

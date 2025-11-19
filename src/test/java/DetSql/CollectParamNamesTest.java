package DetSql;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 测试 MyFilterRequest.collectParamNames 方法
 * 
 * 验证修复后的代码能够：
 * 1. 使用分隔符防止参数名碰撞
 * 2. 对参数名排序确保一致性
 */
public class CollectParamNamesTest {

    /**
     * 使用反射调用私有的 collectParamNames 方法
     */
    private String callCollectParamNames(List<ParsedHttpParameter> params) throws Exception {
        Method method = MyFilterRequest.class.getDeclaredMethod("collectParamNames", List.class);
        method.setAccessible(true);
        return (String) method.invoke(null, params);
    }

    /**
     * 创建模拟的 ParsedHttpParameter
     */
    private ParsedHttpParameter createMockParam(String name, String value) {
        return new ParsedHttpParameter() {
            @Override
            public HttpParameterType type() {
                return HttpParameterType.URL;
            }

            @Override
            public String name() {
                return name;
            }

            @Override
            public String value() {
                return value;
            }

            @Override
            public burp.api.montoya.core.Range valueOffsets() {
                return burp.api.montoya.core.Range.range(0, value.length());
            }

            @Override
            public burp.api.montoya.core.Range nameOffsets() {
                return burp.api.montoya.core.Range.range(0, name.length());
            }
        };
    }

    @Test
    void testBasicParameterNames() throws Exception {
        List<ParsedHttpParameter> params = Arrays.asList(
            createMockParam("id", "1"),
            createMockParam("name", "test")
        );

        String result = callCollectParamNames(params);
        
        // 参数名应该排序并用 | 分隔
        assertEquals("id|name", result);
    }

    @Test
    void testParameterNameCollisionPrevention() throws Exception {
        // 测试修复前会碰撞的情况
        List<ParsedHttpParameter> params1 = Arrays.asList(
            createMockParam("id", "1"),
            createMockParam("name", "test")
        );
        
        List<ParsedHttpParameter> params2 = Arrays.asList(
            createMockParam("idn", "1"),
            createMockParam("ame", "test")
        );

        String result1 = callCollectParamNames(params1);
        String result2 = callCollectParamNames(params2);

        // 修复前：result1 = "idname", result2 = "idname" (碰撞！)
        // 修复后：result1 = "id|name", result2 = "ame|idn" (不同)
        assertNotEquals(result1, result2, "不同的参数组合不应该产生相同的 hash");
        assertEquals("id|name", result1);
        assertEquals("ame|idn", result2);
    }

    @Test
    void testParameterOrderConsistency() throws Exception {
        // 测试参数顺序不影响结果
        List<ParsedHttpParameter> params1 = Arrays.asList(
            createMockParam("id", "1"),
            createMockParam("name", "test"),
            createMockParam("age", "20")
        );
        
        List<ParsedHttpParameter> params2 = Arrays.asList(
            createMockParam("name", "test"),
            createMockParam("age", "20"),
            createMockParam("id", "1")
        );
        
        List<ParsedHttpParameter> params3 = Arrays.asList(
            createMockParam("age", "20"),
            createMockParam("id", "1"),
            createMockParam("name", "test")
        );

        String result1 = callCollectParamNames(params1);
        String result2 = callCollectParamNames(params2);
        String result3 = callCollectParamNames(params3);

        // 所有结果应该相同（排序后）
        assertEquals(result1, result2);
        assertEquals(result2, result3);
        assertEquals("age|id|name", result1);
    }

    @Test
    void testSingleParameter() throws Exception {
        List<ParsedHttpParameter> params = Arrays.asList(
            createMockParam("id", "1")
        );

        String result = callCollectParamNames(params);
        assertEquals("id", result);
    }

    @Test
    void testEmptyParameterList() throws Exception {
        List<ParsedHttpParameter> params = Arrays.asList();

        String result = callCollectParamNames(params);
        assertEquals("", result);
    }

    @Test
    void testParameterValueIgnored() throws Exception {
        // 验证参数值不影响结果（只使用参数名）
        List<ParsedHttpParameter> params1 = Arrays.asList(
            createMockParam("id", "1"),
            createMockParam("name", "alice")
        );
        
        List<ParsedHttpParameter> params2 = Arrays.asList(
            createMockParam("id", "999"),
            createMockParam("name", "bob")
        );

        String result1 = callCollectParamNames(params1);
        String result2 = callCollectParamNames(params2);

        // 参数值不同，但参数名相同，结果应该相同
        assertEquals(result1, result2);
        assertEquals("id|name", result1);
    }

    @Test
    void testSpecialCharactersInParameterNames() throws Exception {
        List<ParsedHttpParameter> params = Arrays.asList(
            createMockParam("user_id", "1"),
            createMockParam("session-token", "abc"),
            createMockParam("__csrf", "xyz")
        );

        String result = callCollectParamNames(params);
        
        // 特殊字符应该被保留，排序后用 | 分隔
        assertEquals("__csrf|session-token|user_id", result);
    }

    @Test
    void testManyParameters() throws Exception {
        List<ParsedHttpParameter> params = Arrays.asList(
            createMockParam("z", "1"),
            createMockParam("a", "2"),
            createMockParam("m", "3"),
            createMockParam("b", "4"),
            createMockParam("y", "5")
        );

        String result = callCollectParamNames(params);
        
        // 应该按字母顺序排序
        assertEquals("a|b|m|y|z", result);
    }

    @Test
    void testRealWorldScenario_LoginForm() throws Exception {
        // 模拟真实场景：登录表单
        List<ParsedHttpParameter> params = Arrays.asList(
            createMockParam("username", "admin"),
            createMockParam("password", "secret"),
            createMockParam("remember_me", "true"),
            createMockParam("csrf_token", "abc123")
        );

        String result = callCollectParamNames(params);
        assertEquals("csrf_token|password|remember_me|username", result);
    }

    @Test
    void testRealWorldScenario_SearchQuery() throws Exception {
        // 模拟真实场景：搜索查询
        List<ParsedHttpParameter> params1 = Arrays.asList(
            createMockParam("q", "sql injection"),
            createMockParam("page", "1"),
            createMockParam("sort", "relevance")
        );
        
        List<ParsedHttpParameter> params2 = Arrays.asList(
            createMockParam("sort", "date"),
            createMockParam("q", "xss attack"),
            createMockParam("page", "2")
        );

        String result1 = callCollectParamNames(params1);
        String result2 = callCollectParamNames(params2);

        // 参数名相同，顺序不同，结果应该相同
        assertEquals(result1, result2);
        assertEquals("page|q|sort", result1);
    }

    @Test
    void testCaseSensitivity() throws Exception {
        // 验证参数名是大小写敏感的
        List<ParsedHttpParameter> params = Arrays.asList(
            createMockParam("ID", "1"),
            createMockParam("id", "2"),
            createMockParam("Id", "3")
        );

        String result = callCollectParamNames(params);
        
        // 大小写不同的参数名应该被视为不同的参数
        // 排序：ID < Id < id (按 ASCII 码)
        assertEquals("ID|Id|id", result);
    }

    @Test
    void testChineseParameterNames() throws Exception {
        // 验证对中文参数名的支持
        List<ParsedHttpParameter> params = Arrays.asList(
            createMockParam("用户名", "张三"),
            createMockParam("密码", "123456"),
            createMockParam("验证码", "abcd")
        );

        String result = callCollectParamNames(params);
        
        // 中文参数名应该被正确处理
        assertNotNull(result);
        assertTrue(result.contains("|"));
        // 注意：中文排序可能依赖于 JVM 的 locale 设置
    }
}

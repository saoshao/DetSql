package DetSql;

import org.junit.jupiter.api.Test;
import java.lang.reflect.Method;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 集成测试：验证 DetSql.parseDelimitedString 方法的安全性
 *
 * 这个测试验证了修复后的代码能够正确处理带空格的输入，
 * 防止后缀过滤和参数黑名单绕过漏洞。
 */
public class ParseDelimitedStringIntegrationTest {

    /**
     * 使用反射调用私有的 parseDelimitedString 方法
     */
    @SuppressWarnings("unchecked")
    private Set<String> callParseDelimitedString(String input) throws Exception {
        Method method = DetSql.class.getDeclaredMethod("parseDelimitedString", String.class);
        method.setAccessible(true);
        return (Set<String>) method.invoke(null, input);
    }

    @Test
    void testNormalInput() throws Exception {
        Set<String> result = callParseDelimitedString("jpg|png|gif");
        assertEquals(3, result.size());
        assertTrue(result.contains("jpg"));
        assertTrue(result.contains("png"));
        assertTrue(result.contains("gif"));
    }

    @Test
    void testInputWithSpaces() throws Exception {
        // 这是最关键的测试：验证空格被正确处理
        Set<String> result = callParseDelimitedString("jpg | png | gif");
        assertEquals(3, result.size());
        assertTrue(result.contains("jpg"));
        assertTrue(result.contains("png"));
        assertTrue(result.contains("gif"));

        // 确保不包含带空格的版本
        assertFalse(result.contains("jpg "));
        assertFalse(result.contains(" png"));
        assertFalse(result.contains(" png "));
    }

    @Test
    void testInputWithExtraSpaces() throws Exception {
        Set<String> result = callParseDelimitedString("  jpg  |  png  |  gif  ");
        assertEquals(3, result.size());
        assertTrue(result.contains("jpg"));
        assertTrue(result.contains("png"));
        assertTrue(result.contains("gif"));
    }

    @Test
    void testEmptyElements() throws Exception {
        // 空元素应该被过滤掉
        Set<String> result = callParseDelimitedString("jpg||png|||gif");
        assertEquals(3, result.size());
        assertTrue(result.contains("jpg"));
        assertTrue(result.contains("png"));
        assertTrue(result.contains("gif"));
    }

    @Test
    void testMixedSpacesAndEmptyElements() throws Exception {
        Set<String> result = callParseDelimitedString("jpg | | png |  | gif");
        assertEquals(3, result.size());
        assertTrue(result.contains("jpg"));
        assertTrue(result.contains("png"));
        assertTrue(result.contains("gif"));
    }

    @Test
    void testNullInput() throws Exception {
        Set<String> result = callParseDelimitedString(null);
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testEmptyInput() throws Exception {
        Set<String> result = callParseDelimitedString("");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testBlankInput() throws Exception {
        Set<String> result = callParseDelimitedString("   ");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testSecurityScenario_SuffixFilter() throws Exception {
        // 模拟真实场景：用户配置了禁止后缀
        String userConfig = "jsp | jspx | php | asp";
        Set<String> suffixBlacklist = callParseDelimitedString(userConfig);

        // 验证所有后缀都能被正确匹配
        assertTrue(suffixBlacklist.contains("jsp"), "jsp后缀应该被阻止");
        assertTrue(suffixBlacklist.contains("jspx"), "jspx后缀应该被阻止");
        assertTrue(suffixBlacklist.contains("php"), "php后缀应该被阻止");
        assertTrue(suffixBlacklist.contains("asp"), "asp后缀应该被阻止");

        // 模拟文件上传检查
        String uploadedFile = "shell.jsp";
        String extension = uploadedFile.substring(uploadedFile.lastIndexOf('.') + 1);
        assertTrue(suffixBlacklist.contains(extension),
                "恶意文件 " + uploadedFile + " 应该被阻止");
    }

    @Test
    void testSecurityScenario_ParamsBlacklist() throws Exception {
        // 模拟真实场景：配置参数黑名单
        String userConfig = "csrf_token | session_id | __viewstate | authenticity_token";
        Set<String> paramsBlacklist = callParseDelimitedString(userConfig);

        // 验证所有参数都能被正确匹配
        assertTrue(paramsBlacklist.contains("csrf_token"));
        assertTrue(paramsBlacklist.contains("session_id"));
        assertTrue(paramsBlacklist.contains("__viewstate"));
        assertTrue(paramsBlacklist.contains("authenticity_token"));

        // 模拟参数过滤
        String[] requestParams = {"username", "password", "csrf_token", "remember_me"};
        for (String param : requestParams) {
            if (paramsBlacklist.contains(param)) {
                // csrf_token应该被跳过，不进行SQL注入测试
                assertEquals("csrf_token", param);
            }
        }
    }

    @Test
    void testRealWorldExample_DefaultSuffix() throws Exception {
        // 使用项目默认配置
        String defaultConfig = "js|css|jpg|png|gif|bmp|svg|woff|woff2|ttf|eot|ico|mp3|mp4|avi|flv|swf|zip|rar|7z|tar|gz|bz2|pdf|doc|docx|xls|xlsx|ppt|pptx";
        Set<String> result = callParseDelimitedString(defaultConfig);

        // 验证常见的静态资源后缀
        assertTrue(result.contains("js"));
        assertTrue(result.contains("css"));
        assertTrue(result.contains("jpg"));
        assertTrue(result.contains("png"));
        assertTrue(result.contains("pdf"));
        assertTrue(result.contains("zip"));

        // 验证总数正确（实际是30个后缀）
        assertEquals(30, result.size());
    }

    @Test
    void testChineseCharacters() throws Exception {
        // 验证对中文字符的支持
        Set<String> result = callParseDelimitedString("测试 | 参数 | 黑名单");
        assertEquals(3, result.size());
        assertTrue(result.contains("测试"));
        assertTrue(result.contains("参数"));
        assertTrue(result.contains("黑名单"));
    }

    @Test
    void testSpecialCharacters() throws Exception {
        // 验证对特殊字符的支持
        Set<String> result = callParseDelimitedString("_csrf | __viewstate | X-Auth-Token");
        assertEquals(3, result.size());
        assertTrue(result.contains("_csrf"));
        assertTrue(result.contains("__viewstate"));
        assertTrue(result.contains("X-Auth-Token"));
    }
}

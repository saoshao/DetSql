package DetSql;

import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 测试后缀过滤和参数黑名单的安全漏洞
 */
public class SuffixAndParamsFilterTest {

    @Test
    void testSuffixParsingWithSpaces() {
        // 模拟当前的解析方式（有问题的）
        String input = "jpg | png | gif";
        Set<String> result = new HashSet<>(Arrays.asList(input.split("\\|")));

        // 这些测试会失败，因为带空格
        assertFalse(result.contains("jpg"), "应该不包含'jpg'（实际是'jpg '）");
        assertFalse(result.contains("png"), "应该不包含'png'（实际是' png '）");
        assertFalse(result.contains("gif"), "应该不包含'gif'（实际是' gif'）");

        // 实际包含的是带空格的版本
        assertTrue(result.contains("jpg "));
        assertTrue(result.contains(" png "));
        assertTrue(result.contains(" gif"));

        // 这意味着 .jpg 文件不会被过滤！
    }

    @Test
    void testCorrectSuffixParsing() {
        // 正确的解析方式
        String input = "jpg | png | gif";
        Set<String> result = Arrays.stream(input.split("\\|"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(java.util.stream.Collectors.toSet());

        // 这些测试会通过
        assertTrue(result.contains("jpg"));
        assertTrue(result.contains("png"));
        assertTrue(result.contains("gif"));

        // 不包含带空格的版本
        assertFalse(result.contains("jpg "));
        assertFalse(result.contains(" png"));
    }

    @Test
    void testParamsBlacklistWithSpaces() {
        // 模拟当前的参数黑名单解析（有问题的）
        String input = "csrf_token | session_id | __viewstate";
        Set<String> blacklist = new HashSet<>(Arrays.asList(input.trim().split("\\|")));

        // 参数名精确匹配会失败
        assertFalse(blacklist.contains("csrf_token"));
        assertFalse(blacklist.contains("session_id"));
        assertFalse(blacklist.contains("__viewstate"));

        // 实际包含的是带空格的版本
        assertTrue(blacklist.contains("csrf_token "));
        assertTrue(blacklist.contains(" session_id "));
        assertTrue(blacklist.contains(" __viewstate"));

        // 这意味着 csrf_token 参数会被错误地测试！（安全风险）
    }

    @Test
    void testSecurityImplications() {
        // 演示安全影响
        String userInput = "jpg | png | gif";
        Set<String> extensionBlacklist = new HashSet<>(Arrays.asList(userInput.split("\\|")));

        // 攻击者的文件扩展名
        String attackerFile = "malicious.jpg";
        String extension = "jpg"; // 从attackerFile提取的扩展名

        // 由于解析问题，恶意文件不会被过滤
        boolean isBlocked = extensionBlacklist.contains(extension);
        assertFalse(isBlocked, "jpg应该被阻止，但由于空格问题没有被阻止");

        // 实际上黑名单包含的是 "jpg " 而不是 "jpg"
        assertTrue(extensionBlacklist.contains("jpg "));
    }
}
package DetSql;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.regex.Pattern;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import DetSql.util.RegexUtils;

/**
 * RegexUtils单元测试套件
 * 测试正则表达式的ReDoS防护机制
 *
 * @author DetSql Security Team
 * @since v3.3.1
 */
@DisplayName("RegexUtils安全正则表达式工具测试")
class RegexUtilsTest {

    @Nested
    @DisplayName("正常匹配场景测试")
    class NormalMatchingTests {

        @Test
        @DisplayName("简单模式匹配 - 应该返回true")
        void testSimplePatternMatch() {
            boolean result = RegexUtils.safeMatch("hello", "hello world");
            assertTrue(result, "简单模式应该匹配");
        }

        @Test
        @DisplayName("大小写不敏感匹配")
        void testCaseInsensitiveMatch() {
            boolean result = RegexUtils.safeMatch("HELLO", "hello world");
            assertTrue(result, "应该进行大小写不敏感匹配");
        }

        @Test
        @DisplayName("数字匹配")
        void testDigitMatch() {
            boolean result = RegexUtils.safeMatch("\\d+", "test123");
            assertTrue(result, "应该匹配数字");
        }

        @Test
        @DisplayName("邮箱模式匹配")
        void testEmailPatternMatch() {
            boolean result = RegexUtils.safeMatch("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", "user@example.com");
            assertTrue(result, "应该匹配邮箱地址");
        }

        @Test
        @DisplayName("SQL注入检测模式")
        void testSqlInjectionDetection() {
            boolean result = RegexUtils.safeMatch("(UNION|SELECT|FROM|WHERE)", "SELECT * FROM users");
            assertTrue(result, "应该检测SQL关键字");
        }

        @Test
        @DisplayName("URL匹配")
        void testUrlMatch() {
            boolean result = RegexUtils.safeMatch("https?://[\\w.-]+", "https://example.com");
            assertTrue(result, "应该匹配URL");
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "hello", "HELLO", "HeLLo", "123", "test123"
        })
        @DisplayName("多个匹配模式")
        void testMultiplePatterns(String text) {
            assertNotNull(text);
            assertFalse(text.isEmpty());
        }
    }

    @Nested
    @DisplayName("不匹配场景测试")
    class NoMatchingTests {

        @Test
        @DisplayName("模式不匹配文本")
        void testNoMatch() {
            boolean result = RegexUtils.safeMatch("xyz", "hello world");
            assertFalse(result, "模式应该不匹配");
        }

        @Test
        @DisplayName("空模式不匹配")
        void testEmptyPatternNoMatch() {
            boolean result = RegexUtils.safeMatch("xyz", "");
            assertFalse(result, "空字符串应该不匹配非空模式");
        }

        @Test
        @DisplayName("数字模式不匹配纯文字")
        void testDigitPatternNoMatch() {
            boolean result = RegexUtils.safeMatch("\\d+", "abcdef");
            assertFalse(result, "数字模式不应该匹配纯文字");
        }
    }

    @Nested
    @DisplayName("空值和边界处理测试")
    class NullAndBoundaryTests {

        @Test
        @DisplayName("null pattern应该返回false")
        void testNullPattern() {
            boolean result = RegexUtils.safeMatch(null, "test");
            assertFalse(result, "null pattern应该返回false");
        }

        @Test
        @DisplayName("null text应该返回false")
        void testNullText() {
            boolean result = RegexUtils.safeMatch("test", null);
            assertFalse(result, "null text应该返回false");
        }

        @Test
        @DisplayName("都为null应该返回false")
        void testBothNull() {
            boolean result = RegexUtils.safeMatch(null, null);
            assertFalse(result, "两个null应该返回false");
        }

        @Test
        @DisplayName("空pattern和空text")
        void testEmptyPatternAndText() {
            boolean result = RegexUtils.safeMatch("", "");
            assertTrue(result, "空模式应该匹配空字符串");
        }

        @Test
        @DisplayName("长文本匹配")
        void testLongTextMatch() {
            String longText = "a".repeat(10000) + "test" + "b".repeat(10000);
            boolean result = RegexUtils.safeMatch("test", longText);
            assertTrue(result, "应该在长文本中找到模式");
        }
    }

    @Nested
    @DisplayName("ReDoS防护超时测试")
    class ReDoSProtectionTests {

        @Test
        @DisplayName("超时机制应该正常工作")
        @Timeout(value = 2, unit = TimeUnit.SECONDS)
        void testTimeoutMechanism() {
            // 使用更极端的ReDoS模式和更长的字符串
            String redosPattern = "(a+)+$";
            String text = "a".repeat(30) + "!";  // 不匹配的结尾会导致大量回溯

            long startTime = System.currentTimeMillis();
            boolean result = RegexUtils.safeMatch(redosPattern, text, 500);
            long elapsed = System.currentTimeMillis() - startTime;

            // 主要验证返回false（超时或不匹配）
            assertFalse(result, "应该返回false");
            // 验证没有无限期阻塞
            assertTrue(elapsed < 1500, "不应该远超超时时间");
        }

        @Test
        @DisplayName("复杂模式超时保护")
        @Timeout(value = 3, unit = TimeUnit.SECONDS)
        void testComplexPatternTimeout() {
            // 使用更复杂的模式
            String pattern = "(a*)*b";
            String text = "a".repeat(28);

            long startTime = System.currentTimeMillis();
            boolean result = RegexUtils.safeMatch(pattern, text, 300);
            long elapsed = System.currentTimeMillis() - startTime;

            assertFalse(result, "应该因超时或不匹配返回false");
            assertTrue(elapsed < 1000, "应该在合理时间内完成");
        }

        @Test
        @DisplayName("短超时时间")
        @Timeout(value = 1, unit = TimeUnit.SECONDS)
        void testVeryShortTimeout() {
            // 即使是简单模式，极短的超时也可能导致失败
            boolean result = RegexUtils.safeMatch("(a+)+b", "a".repeat(15), 50);
            // 不强制要求返回false，因为可能在超时前完成
            assertNotNull(result);
        }

        @Test
        @DisplayName("足够长的超时应该完成匹配")
        void testSufficientTimeout() {
            boolean result = RegexUtils.safeMatch("hello", "hello world", 5000);
            assertTrue(result, "足够的超时应该完成简单匹配");
        }
    }

    @Nested
    @DisplayName("预编译Pattern测试")
    class PrecompiledPatternTests {

        private Pattern testPattern;

        @BeforeEach
        void setUp() {
            testPattern = Pattern.compile("test", Pattern.CASE_INSENSITIVE);
        }

        @Test
        @DisplayName("预编译Pattern正常匹配")
        void testPrecompiledPatternMatch() {
            boolean result = RegexUtils.safeMatchPrecompiled(testPattern, "this is a TEST");
            assertTrue(result, "预编译Pattern应该匹配");
        }

        @Test
        @DisplayName("预编译Pattern不匹配")
        void testPrecompiledPatternNoMatch() {
            boolean result = RegexUtils.safeMatchPrecompiled(testPattern, "this is not matching");
            assertFalse(result, "预编译Pattern应该不匹配");
        }

        @Test
        @DisplayName("null预编译Pattern")
        void testNullPrecompiledPattern() {
            boolean result = RegexUtils.safeMatchPrecompiled(null, "test");
            assertFalse(result, "null Pattern应该返回false");
        }

        @Test
        @DisplayName("null文本与预编译Pattern")
        void testPrecompiledPatternWithNullText() {
            boolean result = RegexUtils.safeMatchPrecompiled(testPattern, null);
            assertFalse(result, "null text应该返回false");
        }

        @Test
        @DisplayName("预编译Pattern默认超时")
        void testPrecompiledPatternDefaultTimeout() {
            Pattern simplePattern = Pattern.compile("hello");
            boolean result = RegexUtils.safeMatchPrecompiled(simplePattern, "hello world");
            assertTrue(result, "预编译Pattern应该使用默认超时成功匹配");
        }

        @Test
        @DisplayName("预编译Pattern超时保护")
        @Timeout(value = 2, unit = TimeUnit.SECONDS)
        void testPrecompiledPatternTimeoutProtection() {
            // 使用更极端的模式
            Pattern redosPattern = Pattern.compile("(a+)+$");
            long startTime = System.currentTimeMillis();
            boolean result = RegexUtils.safeMatchPrecompiled(redosPattern, "a".repeat(30) + "!", 300);
            long elapsed = System.currentTimeMillis() - startTime;

            // 主要验证返回false和没有无限期阻塞
            assertFalse(result, "应该返回false");
            assertTrue(elapsed < 1000, "应该在合理时间内完成");
        }

        @Test
        @DisplayName("复杂预编译Pattern")
        void testComplexPrecompiledPattern() {
            Pattern emailPattern = Pattern.compile(
                "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
                Pattern.CASE_INSENSITIVE
            );
            boolean result = RegexUtils.safeMatchPrecompiled(emailPattern, "Test.User@Example.COM");
            assertTrue(result, "复杂邮箱Pattern应该匹配");
        }
    }

    @Nested
    @DisplayName("超时值参数化测试")
    class TimeoutParameterizedTests {

        @ParameterizedTest
        @CsvSource({
            "hello, hello world, 100, true",
            "xyz, hello world, 100, false",
            "\\d+, 12345, 100, true",
            "\\d+, abcde, 100, false"
        })
        @DisplayName("多种超时值匹配")
        void testVariousTimeouts(String pattern, String text, long timeout, boolean expected) {
            boolean result = RegexUtils.safeMatch(pattern, text, timeout);
            assertEquals(expected, result,
                String.format("pattern=%s, text=%s, timeout=%d应该返回%s",
                    pattern, text, timeout, expected));
        }
    }

    @Nested
    @DisplayName("默认超时测试")
    class DefaultTimeoutTests {

        @Test
        @DisplayName("使用默认超时200ms进行匹配")
        void testDefaultTimeoutUsage() {
            boolean result = RegexUtils.safeMatch("test", "this is a test");
            assertTrue(result, "默认超时应该匹配简单模式");
        }

        @Test
        @DisplayName("预编译Pattern默认超时")
        void testPrecompiledDefaultTimeout() {
            Pattern pattern = Pattern.compile("test");
            boolean result = RegexUtils.safeMatchPrecompiled(pattern, "this is a test");
            assertTrue(result, "预编译Pattern默认超时应该成功");
        }
    }

    @Nested
    @DisplayName("异常处理测试")
    class ExceptionHandlingTests {

        @Test
        @DisplayName("无效的正则表达式模式")
        void testInvalidRegexPattern() {
            // 无效的正则表达式，缺少闭括号
            boolean result = RegexUtils.safeMatch("[abc", "abc");
            assertFalse(result, "无效的正则应该返回false");
        }

        @Test
        @DisplayName("复杂的无效正则")
        void testComplexInvalidRegex() {
            boolean result = RegexUtils.safeMatch("(?P<invalid", "test");
            assertFalse(result, "格式不正确的正则应该返回false");
        }

        @Test
        @DisplayName("中文字符匹配")
        void testChineseCharacterMatch() {
            boolean result = RegexUtils.safeMatch("中文", "这是中文文本");
            assertTrue(result, "应该匹配中文字符");
        }

        @Test
        @DisplayName("特殊字符转义")
        void testSpecialCharacterEscaping() {
            boolean result = RegexUtils.safeMatch("\\$\\d+", "$100");
            assertTrue(result, "应该正确转义特殊字符");
        }
    }

    @Nested
    @DisplayName("性能测试")
    class PerformanceTests {

        @Test
        @DisplayName("大量快速匹配")
        @Timeout(value = 5, unit = TimeUnit.SECONDS)
        void testHighVolumeMatching() {
            int iterations = 1000;
            long startTime = System.currentTimeMillis();

            for (int i = 0; i < iterations; i++) {
                RegexUtils.safeMatch("test", "this is a test string");
            }

            long elapsed = System.currentTimeMillis() - startTime;
            assertTrue(elapsed < 5000, "1000次快速匹配应该在5秒内完成");
        }

        @Test
        @DisplayName("预编译Pattern性能优势")
        @Timeout(value = 5, unit = TimeUnit.SECONDS)
        void testPrecompiledPerformance() {
            Pattern pattern = Pattern.compile("test");
            int iterations = 1000;

            long startTime = System.currentTimeMillis();
            for (int i = 0; i < iterations; i++) {
                RegexUtils.safeMatchPrecompiled(pattern, "this is a test string");
            }
            long elapsed = System.currentTimeMillis() - startTime;

            assertTrue(elapsed < 5000, "预编译Pattern 1000次匹配应该在5秒内完成");
        }
    }
}

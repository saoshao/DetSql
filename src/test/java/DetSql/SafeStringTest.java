package DetSql;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SafeString单元测试套件
 * 测试安全的字符串操作，防止索引越界
 *
 * @author DetSql Security Team
 * @since v3.3.1
 */
@DisplayName("SafeString安全字符串操作测试")
class SafeStringTest {

    private static final String TEST_STRING = "hello";
    private static final String EMPTY_STRING = "";
    private static final char DEFAULT_CHAR = '\0';

    @Nested
    @DisplayName("charAt边界测试")
    class CharAtBoundaryTests {

        @Test
        @DisplayName("charAt正常索引")
        void testCharAtValidIndex() {
            assertEquals('h', SafeString.charAt(TEST_STRING, 0));
            assertEquals('e', SafeString.charAt(TEST_STRING, 1));
            assertEquals('l', SafeString.charAt(TEST_STRING, 2));
            assertEquals('o', SafeString.charAt(TEST_STRING, 4));
        }

        @Test
        @DisplayName("charAt最后一个字符")
        void testCharAtLastIndex() {
            assertEquals('o', SafeString.charAt(TEST_STRING, 4));
        }

        @Test
        @DisplayName("charAt负索引应该返回默认值")
        void testCharAtNegativeIndex() {
            char result = SafeString.charAt(TEST_STRING, -1);
            assertEquals(DEFAULT_CHAR, result, "负索引应该返回空字符");
        }

        @Test
        @DisplayName("charAt索引等于长度应该返回默认值")
        void testCharAtIndexEqualsLength() {
            char result = SafeString.charAt(TEST_STRING, 5);
            assertEquals(DEFAULT_CHAR, result, "索引等于字符串长度应该返回默认值");
        }

        @Test
        @DisplayName("charAt超出范围")
        void testCharAtOutOfBounds() {
            char result = SafeString.charAt(TEST_STRING, 10);
            assertEquals(DEFAULT_CHAR, result, "超出范围索引应该返回默认值");
        }

        @Test
        @DisplayName("charAt大幅超出范围")
        void testCharAtFarOutOfBounds() {
            char result = SafeString.charAt(TEST_STRING, Integer.MAX_VALUE);
            assertEquals(DEFAULT_CHAR, result, "极端超出范围应该返回默认值");
        }

        @Test
        @DisplayName("charAt null字符串")
        void testCharAtNullString() {
            char result = SafeString.charAt(null, 0);
            assertEquals(DEFAULT_CHAR, result, "null字符串应该返回默认值");
        }

        @Test
        @DisplayName("charAt空字符串")
        void testCharAtEmptyString() {
            char result = SafeString.charAt(EMPTY_STRING, 0);
            assertEquals(DEFAULT_CHAR, result, "空字符串的任何索引应该返回默认值");
        }

        @Test
        @DisplayName("charAt使用自定义默认值")
        void testCharAtWithCustomDefaultValue() {
            char customDefault = 'X';
            char result = SafeString.charAt(TEST_STRING, -1, customDefault);
            assertEquals(customDefault, result, "应该返回自定义默认值");
        }

        @Test
        @DisplayName("charAt自定义默认值正常索引")
        void testCharAtCustomDefaultValidIndex() {
            char result = SafeString.charAt(TEST_STRING, 0, 'X');
            assertEquals('h', result, "正常索引应该返回字符，忽略默认值");
        }

        @ParameterizedTest
        @CsvSource({
            "0,h",
            "1,e",
            "2,l",
            "3,l",
            "4,o"
        })
        @DisplayName("多个charAt测试")
        void testCharAtMultiple(int index, char expected) {
            assertEquals(expected, SafeString.charAt(TEST_STRING, index));
        }

        @Test
        @DisplayName("charAt特殊字符")
        void testCharAtSpecialCharacters() {
            String specialString = "!@#$%^&*()";
            assertEquals('!', SafeString.charAt(specialString, 0));
            assertEquals('&', SafeString.charAt(specialString, 6));
        }
    }

    @Nested
    @DisplayName("isValidIndex验证测试")
    class IsValidIndexTests {

        @Test
        @DisplayName("isValidIndex有效索引")
        void testIsValidIndexValid() {
            assertTrue(SafeString.isValidIndex(TEST_STRING, 0));
            assertTrue(SafeString.isValidIndex(TEST_STRING, 2));
            assertTrue(SafeString.isValidIndex(TEST_STRING, 4));
        }

        @Test
        @DisplayName("isValidIndex无效索引-负数")
        void testIsValidIndexNegative() {
            assertFalse(SafeString.isValidIndex(TEST_STRING, -1));
            assertFalse(SafeString.isValidIndex(TEST_STRING, -100));
        }

        @Test
        @DisplayName("isValidIndex无效索引-超出范围")
        void testIsValidIndexOutOfRange() {
            assertFalse(SafeString.isValidIndex(TEST_STRING, 5));
            assertFalse(SafeString.isValidIndex(TEST_STRING, 10));
            assertFalse(SafeString.isValidIndex(TEST_STRING, Integer.MAX_VALUE));
        }

        @Test
        @DisplayName("isValidIndex null字符串")
        void testIsValidIndexNullString() {
            assertFalse(SafeString.isValidIndex(null, 0));
            assertFalse(SafeString.isValidIndex(null, -1));
        }

        @Test
        @DisplayName("isValidIndex空字符串")
        void testIsValidIndexEmptyString() {
            assertFalse(SafeString.isValidIndex(EMPTY_STRING, 0));
            assertFalse(SafeString.isValidIndex(EMPTY_STRING, -1));
        }

        @Test
        @DisplayName("isValidIndex单字符字符串")
        void testIsValidIndexSingleChar() {
            assertTrue(SafeString.isValidIndex("a", 0));
            assertFalse(SafeString.isValidIndex("a", 1));
            assertFalse(SafeString.isValidIndex("a", -1));
        }
    }

    @Nested
    @DisplayName("substring边界修正测试")
    class SubstringBoundaryTests {

        @Test
        @DisplayName("substring正常范围")
        void testSubstringValidRange() {
            assertEquals("ell", SafeString.substring(TEST_STRING, 1, 4));
            assertEquals("hello", SafeString.substring(TEST_STRING, 0, 5));
        }

        @Test
        @DisplayName("substring单一参数")
        void testSubstringSingleParameter() {
            assertEquals("llo", SafeString.substring(TEST_STRING, 2));
            assertEquals("hello", SafeString.substring(TEST_STRING, 0));
        }

        @Test
        @DisplayName("substring负起始位置修正")
        void testSubstringNegativeStart() {
            assertEquals("hello", SafeString.substring(TEST_STRING, -1, 5));
            assertEquals("hello", SafeString.substring(TEST_STRING, -100, 5));
        }

        @Test
        @DisplayName("substring负结束位置修正")
        void testSubstringNegativeEnd() {
            assertEquals("", SafeString.substring(TEST_STRING, 0, -1));
        }

        @Test
        @DisplayName("substring超出范围的起始位置")
        void testSubstringStartOutOfRange() {
            assertEquals("", SafeString.substring(TEST_STRING, 10, 20));
        }

        @Test
        @DisplayName("substring超出范围的结束位置修正")
        void testSubstringEndOutOfRange() {
            assertEquals("hello", SafeString.substring(TEST_STRING, 0, 100));
        }

        @Test
        @DisplayName("substring起始大于结束的修正")
        void testSubstringStartGreaterThanEnd() {
            String result = SafeString.substring(TEST_STRING, 4, 1);
            assertEquals("", result, "起始大于结束应该修正为空字符串");
        }

        @Test
        @DisplayName("substring null字符串")
        void testSubstringNullString() {
            assertEquals("", SafeString.substring(null, 0, 5));
            assertEquals("", SafeString.substring(null, -1, -1));
        }

        @Test
        @DisplayName("substring空字符串")
        void testSubstringEmptyString() {
            assertEquals("", SafeString.substring(EMPTY_STRING, 0, 0));
            assertEquals("", SafeString.substring(EMPTY_STRING, -1, 1));
        }

        @Test
        @DisplayName("substring单参数空字符串")
        void testSubstringSingleParamEmptyString() {
            assertEquals("", SafeString.substring(EMPTY_STRING, 0));
            assertEquals("", SafeString.substring(EMPTY_STRING, 10));
        }

        @Test
        @DisplayName("substring边界相等")
        void testSubstringEqualBoundaries() {
            assertEquals("", SafeString.substring(TEST_STRING, 2, 2));
        }

        @ParameterizedTest
        @CsvSource(textBlock = """
            0,5,hello
            1,4,ell
            0,0,''
            5,5,''
            -1,5,hello
            0,100,hello
            """)
        @DisplayName("substring参数化测试")
        void testSubstringParameterized(int start, int end, String expected) {
            assertEquals(expected, SafeString.substring(TEST_STRING, start, end));
        }
    }

    @Nested
    @DisplayName("isCharAt检查测试")
    class IsCharAtTests {

        @Test
        @DisplayName("isCharAt正常匹配")
        void testIsCharAtMatch() {
            assertTrue(SafeString.isCharAt(TEST_STRING, 0, 'h'));
            assertTrue(SafeString.isCharAt(TEST_STRING, 1, 'e'));
            assertTrue(SafeString.isCharAt(TEST_STRING, 4, 'o'));
        }

        @Test
        @DisplayName("isCharAt不匹配")
        void testIsCharAtNoMatch() {
            assertFalse(SafeString.isCharAt(TEST_STRING, 0, 'x'));
            assertFalse(SafeString.isCharAt(TEST_STRING, 1, 'a'));
        }

        @Test
        @DisplayName("isCharAt负索引")
        void testIsCharAtNegativeIndex() {
            assertFalse(SafeString.isCharAt(TEST_STRING, -1, 'h'));
        }

        @Test
        @DisplayName("isCharAt超出范围")
        void testIsCharAtOutOfBounds() {
            assertFalse(SafeString.isCharAt(TEST_STRING, 10, 'h'));
        }

        @Test
        @DisplayName("isCharAt null字符串")
        void testIsCharAtNullString() {
            assertFalse(SafeString.isCharAt(null, 0, 'h'));
        }

        @Test
        @DisplayName("isCharAt空字符串")
        void testIsCharAtEmptyString() {
            assertFalse(SafeString.isCharAt(EMPTY_STRING, 0, 'h'));
        }

        @Test
        @DisplayName("isCharAt特殊字符")
        void testIsCharAtSpecialCharacter() {
            String special = "!@#";
            assertTrue(SafeString.isCharAt(special, 0, '!'));
            assertTrue(SafeString.isCharAt(special, 1, '@'));
            assertTrue(SafeString.isCharAt(special, 2, '#'));
        }

        @ParameterizedTest
        @ValueSource(ints = {0, 1, 2, 3, 4})
        @DisplayName("isCharAt验证所有索引")
        void testIsCharAtAllValidIndices(int index) {
            boolean result = SafeString.isCharAt(TEST_STRING, index, SafeString.charAt(TEST_STRING, index));
            assertTrue(result, "有效索引应该匹配相应字符");
        }
    }

    @Nested
    @DisplayName("isSurroundedBy包围检查测试")
    class IsSurroundedByTests {

        private static final String JSON_STRING = "\"value\"";

        @Test
        @DisplayName("isSurroundedBy引号包围")
        void testIsSurroundedByQuotes() {
            // JSON字符串: "value"
            // startIndex=1 (v), endIndex=6 (e)
            // startIndex-1=0 ("), endIndex=7 (")
            boolean result = SafeString.isSurroundedBy(JSON_STRING, 1, 6, '"', '"');
            assertTrue(result, "应该检测到引号包围");
        }

        @Test
        @DisplayName("isSurroundedBy括号包围")
        void testIsSurroundedByParentheses() {
            String text = "(content)";
            // startIndex=1 (c), endIndex=8 (t)
            boolean result = SafeString.isSurroundedBy(text, 1, 8, '(', ')');
            assertTrue(result, "应该检测到括号包围");
        }

        @Test
        @DisplayName("isSurroundedBy开始位置无效")
        void testIsSurroundedByInvalidStart() {
            boolean result = SafeString.isSurroundedBy(JSON_STRING, 0, 6, '"', '"');
            assertFalse(result, "开始位置无效应该返回false");
        }

        @Test
        @DisplayName("isSurroundedBy结束位置无效")
        void testIsSurroundedByInvalidEnd() {
            boolean result = SafeString.isSurroundedBy(JSON_STRING, 1, 7, '"', '"');
            assertFalse(result, "结束位置无效应该返回false");
        }

        @Test
        @DisplayName("isSurroundedBy null字符串")
        void testIsSurroundedByNullString() {
            boolean result = SafeString.isSurroundedBy(null, 0, 1, '"', '"');
            assertFalse(result, "null字符串应该返回false");
        }

        @Test
        @DisplayName("isSurroundedBy负索引")
        void testIsSurroundedByNegativeIndex() {
            boolean result = SafeString.isSurroundedBy(JSON_STRING, -1, 6, '"', '"');
            assertFalse(result, "负索引应该返回false");
        }

        @Test
        @DisplayName("isSurroundedBy超出范围")
        void testIsSurroundedByOutOfRange() {
            boolean result = SafeString.isSurroundedBy(JSON_STRING, 1, 100, '"', '"');
            assertFalse(result, "超出范围应该返回false");
        }

        @Test
        @DisplayName("isSurroundedBy不匹配的字符")
        void testIsSurroundedByMismatchedCharacters() {
            boolean result = SafeString.isSurroundedBy(JSON_STRING, 1, 6, '[', ']');
            assertFalse(result, "不匹配的字符应该返回false");
        }

        @Test
        @DisplayName("isSurroundedBy方括号")
        void testIsSurroundedBySquareBrackets() {
            String text = "[array]";
            boolean result = SafeString.isSurroundedBy(text, 1, 6, '[', ']');
            assertTrue(result, "应该检测到方括号包围");
        }

        @Test
        @DisplayName("isSurroundedBy花括号")
        void testIsSurroundedByCurlyBraces() {
            String text = "{object}";
            boolean result = SafeString.isSurroundedBy(text, 1, 7, '{', '}');
            assertTrue(result, "应该检测到花括号包围");
        }
    }

    @Nested
    @DisplayName("substringOrDefault默认值测试")
    class SubstringOrDefaultTests {

        @Test
        @DisplayName("substringOrDefault有效范围返回子字符串")
        void testSubstringOrDefaultValidRange() {
            String result = SafeString.substringOrDefault(TEST_STRING, 1, 4, "DEFAULT");
            assertEquals("ell", result);
        }

        @Test
        @DisplayName("substringOrDefault无效起始返回默认值")
        void testSubstringOrDefaultInvalidStart() {
            String result = SafeString.substringOrDefault(TEST_STRING, -1, 4, "DEFAULT");
            assertEquals("DEFAULT", result);
        }

        @Test
        @DisplayName("substringOrDefault起始超出返回默认值")
        void testSubstringOrDefaultStartOutOfRange() {
            String result = SafeString.substringOrDefault(TEST_STRING, 10, 15, "DEFAULT");
            assertEquals("DEFAULT", result);
        }

        @Test
        @DisplayName("substringOrDefault结束小于起始返回默认值")
        void testSubstringOrDefaultEndLessThanStart() {
            String result = SafeString.substringOrDefault(TEST_STRING, 4, 1, "DEFAULT");
            assertEquals("DEFAULT", result);
        }

        @Test
        @DisplayName("substringOrDefault null字符串")
        void testSubstringOrDefaultNullString() {
            String result = SafeString.substringOrDefault(null, 0, 3, "DEFAULT");
            assertEquals("DEFAULT", result);
        }

        @Test
        @DisplayName("substringOrDefault null字符串和null默认值")
        void testSubstringOrDefaultNullBoth() {
            String result = SafeString.substringOrDefault(null, 0, 3, null);
            assertNull(result);
        }

        @Test
        @DisplayName("substringOrDefault空字符串")
        void testSubstringOrDefaultEmptyString() {
            String result = SafeString.substringOrDefault(EMPTY_STRING, 0, 1, "DEFAULT");
            assertEquals("DEFAULT", result);
        }

        @Test
        @DisplayName("substringOrDefault自定义默认值")
        void testSubstringOrDefaultCustomDefault() {
            String customDefault = "CUSTOM";
            String result = SafeString.substringOrDefault(TEST_STRING, -1, 2, customDefault);
            assertEquals(customDefault, result);
        }
    }

    @Nested
    @DisplayName("复合场景测试")
    class ComplexScenarioTests {

        @Test
        @DisplayName("JSON值提取场景")
        void testJsonValueExtraction() {
            String jsonValue = "\"user_name\"";
            // 验证包围引号
            assertTrue(SafeString.isSurroundedBy(jsonValue, 1, 10, '"', '"'));
            // 提取中间内容
            String content = SafeString.substring(jsonValue, 1, 10);
            assertEquals("user_name", content);
        }

        @Test
        @DisplayName("URL参数检查")
        void testUrlParameterCheck() {
            String url = "?param=value&";
            assertTrue(SafeString.isCharAt(url, 0, '?'));
            assertTrue(SafeString.isCharAt(url, 12, '&'));
        }

        @Test
        @DisplayName("SQL字符串边界检查")
        void testSqlStringBoundaryCheck() {
            String sqlString = "'O'Reilly'";
            assertTrue(SafeString.isCharAt(sqlString, 0, '\''));
            assertTrue(SafeString.isCharAt(sqlString, 1, 'O'));
        }

        @Test
        @DisplayName("多层嵌套结构")
        void testNestedStructure() {
            String nested = "[[inner]]";
            // 外层括号
            assertTrue(SafeString.isSurroundedBy(nested, 1, 8, '[', ']'));
            // 内层括号
            assertTrue(SafeString.isSurroundedBy(nested, 2, 7, '[', ']'));
        }

        @Test
        @DisplayName("中文字符串操作")
        void testChineseCharacterOperations() {
            String chinese = "你好世界";
            assertEquals('你', SafeString.charAt(chinese, 0));
            assertEquals('好', SafeString.charAt(chinese, 1));
            assertEquals("世界", SafeString.substring(chinese, 2, 4));
        }

        @Test
        @DisplayName("emoji字符串操作")
        void testEmojiStringOperations() {
            String emoji = "😀😁😂";
            // Note: Java String uses char-based indexing, each emoji = 2 chars (surrogate pair)
            assertEquals(6, emoji.length());  // 3 emojis = 6 chars
            assertTrue(SafeString.isValidIndex(emoji, 0));
            assertEquals("😀", SafeString.substring(emoji, 0, 2));  // First emoji
            assertEquals("😀😁", SafeString.substring(emoji, 0, 4));  // First two emojis
            assertEquals("😀😁😂", SafeString.substring(emoji, 0, 6));  // All three emojis
        }

        @Test
        @DisplayName("混合特殊字符")
        void testMixedSpecialCharacters() {
            String mixed = "test@#$%";
            assertTrue(SafeString.isCharAt(mixed, 4, '@'));
            assertTrue(SafeString.isCharAt(mixed, 5, '#'));
            assertTrue(SafeString.isCharAt(mixed, 6, '$'));
        }
    }

    @Nested
    @DisplayName("边界压力测试")
    class BoundaryStressTests {

        @Test
        @DisplayName("超大字符串操作")
        void testVeryLargeString() {
            String largeString = "a".repeat(100000);
            assertEquals('a', SafeString.charAt(largeString, 0));
            assertEquals('a', SafeString.charAt(largeString, 99999));
            assertEquals(DEFAULT_CHAR, SafeString.charAt(largeString, 100000));
        }

        @Test
        @DisplayName("超大索引值")
        void testVeryLargeIndex() {
            char result = SafeString.charAt(TEST_STRING, Integer.MAX_VALUE);
            assertEquals(DEFAULT_CHAR, result);
        }

        @Test
        @DisplayName("超大负索引值")
        void testVeryLargeNegativeIndex() {
            char result = SafeString.charAt(TEST_STRING, Integer.MIN_VALUE);
            assertEquals(DEFAULT_CHAR, result);
        }

        @Test
        @DisplayName("连续的substring操作")
        void testChainedSubstringOperations() {
            String result = SafeString.substring(TEST_STRING, 0, 5);
            result = SafeString.substring(result, 1, 4);
            result = SafeString.substring(result, 0, 2);
            assertEquals("el", result);
        }
    }
}

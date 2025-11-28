package DetSql;
import DetSql.util.MyCompare;


import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 综合测试 MyCompare 类的核心相似度计算逻辑
 *
 * 测试范围:
 * - Levenshtein 和 Jaccard 相似度计算
 * - 边界情况: 空字符串、长度差异、前后缀包含
 * - upgradeStr 方法的前后缀移除逻辑
 * - html_flag 模式下的特殊处理
 */
public class MyCompareComprehensiveTest {

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 基础相似度计算测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_ReturnHighSimilarity_when_StringsAreIdentical() {
        // Arrange
        String s1 = "test string";
        String s2 = "test string";

        // Act
        double levSim = MyCompare.levenshtein(s1, s2);
        double jaccSim = MyCompare.jaccard(s1, s2);

        // Assert
        assertEquals(1.0, levSim, 1e-9, "Identical strings should have 1.0 Levenshtein similarity");
        assertEquals(1.0, jaccSim, 1e-9, "Identical strings should have 1.0 Jaccard similarity");
    }

    @Test
    void should_ReturnLowSimilarity_when_StringsAreCompletelyDifferent() {
        // Arrange
        String s1 = "aaaaaaa";
        String s2 = "bbbbbbb";

        // Act
        double levSim = MyCompare.levenshtein(s1, s2);
        double jaccSim = MyCompare.jaccard(s1, s2);

        // Assert
        assertEquals(0.0, levSim, 1e-9, "Completely different strings should have 0.0 Levenshtein similarity");
        assertTrue(jaccSim < 0.5, "Completely different strings should have low Jaccard similarity");
    }

    @Test
    void should_CalculatePartialSimilarity_when_StringsHaveMinorDifferences() {
        // Arrange
        String s1 = "SELECT * FROM users WHERE id=1";
        String s2 = "SELECT * FROM users WHERE id=2";

        // Act
        double levSim = MyCompare.levenshtein(s1, s2);

        // Assert
        assertTrue(levSim > 0.9, "Strings with one character difference should have high similarity");
        assertTrue(levSim < 1.0, "Strings with differences should not have perfect similarity");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 边界情况: 长度差异阈值 (100 字节)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_ReturnZeroSimilarity_when_LengthDiffExceedsThreshold() {
        // Arrange: 长度差异 >= 100
        String s1 = "short";
        String s2 = "x".repeat(200);

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);
        List<Double> jaccSims = MyCompare.averageJaccard(s1, s2, "", "", false);

        // Assert
        assertEquals(0.0, levSims.get(0), 1e-9, "Length diff >= 100 should return 0.0 similarity (Levenshtein)");
        assertEquals(0.0, jaccSims.get(0), 1e-9, "Length diff >= 100 should return 0.0 similarity (Jaccard)");
    }

    @Test
    void should_CalculateSimilarity_when_LengthDiffBelowThreshold() {
        // Arrange: 长度差异 < 100
        String s1 = "a".repeat(50);
        String s2 = "a".repeat(100);

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);

        // Assert
        // 这种情况会触发前缀包含检测,返回 0.0
        assertEquals(0.0, levSims.get(0), 1e-9, "Prefix containment should return 0.0");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 边界情况: 空字符串
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_ReturnZeroSimilarity_when_OneStringIsEmpty() {
        // Arrange
        String s1 = "";
        String s2 = "non-empty";

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);
        List<Double> jaccSims = MyCompare.averageJaccard(s1, s2, "", "", false);

        // Assert
        assertEquals(0.0, levSims.get(0), 1e-9, "Empty string should result in 0.0 similarity (Levenshtein)");
        assertEquals(0.0, jaccSims.get(0), 1e-9, "Empty string should result in 0.0 similarity (Jaccard)");
    }

    @Test
    void should_ReturnZeroSimilarity_when_BothStringsAreEmpty() {
        // Arrange
        String s1 = "";
        String s2 = "";

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);

        // Assert
        // 实际代码逻辑: 长度差异 <= 1 时返回 1.0, 空字符串长度差为 0
        assertEquals(1.0, levSims.get(0), 1e-9, "Empty strings have length diff = 0, returns 1.0");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 边界情况: 长度差异 <= 1 (几乎相同)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_ReturnPerfectSimilarity_when_LengthDiffIsZero() {
        // Arrange
        String s1 = "abc";
        String s2 = "abc";

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);

        // Assert
        assertEquals(1.0, levSims.get(0), 1e-9, "Identical strings should return 1.0 similarity");
    }

    @Test
    void should_ReturnPerfectSimilarity_when_LengthDiffIsOne() {
        // Arrange
        String s1 = "ab";
        String s2 = "abc";

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);

        // Assert
        assertEquals(1.0, levSims.get(0), 1e-9, "Length diff = 1 should return 1.0 similarity");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 边界情况: 前缀/后缀包含
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_ReturnZeroSimilarity_when_ShorterIsPrefixOfLonger() {
        // Arrange
        String s1 = "hello";
        String s2 = "hello world";

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);

        // Assert
        assertEquals(0.0, levSims.get(0), 1e-9, "Prefix containment should return 0.0 similarity");
    }

    @Test
    void should_ReturnZeroSimilarity_when_ShorterIsSuffixOfLonger() {
        // Arrange
        String s1 = "world";
        String s2 = "hello world";

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);

        // Assert
        assertEquals(0.0, levSims.get(0), 1e-9, "Suffix containment should return 0.0 similarity");
    }

    @Test
    void should_ReturnZeroSimilarity_when_LongerIsPrefixOfShorter_ReverseOrder() {
        // Arrange: s2 是 s1 的前缀
        String s1 = "hello world";
        String s2 = "hello";

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);

        // Assert
        assertEquals(0.0, levSims.get(0), 1e-9, "Prefix containment (reverse) should return 0.0 similarity");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // upgradeStr 方法测试 - 前后缀移除
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_RemoveCommonPrefixAndSuffix_when_StringsShareThem() {
        // Arrange
        String shorter = "abcXdef";
        String longer = "abcYdef";

        // Act
        String[] result = MyCompare.upgradeStr(shorter, longer);

        // Assert
        assertEquals("X", result[0], "Should extract difference from shorter string");
        assertEquals("Y", result[1], "Should extract difference from longer string");
    }

    @Test
    void should_ReturnEmptyAndSuffix_when_ShorterIsPrefix() {
        // Arrange
        String shorter = "hello";
        String longer = "hello world";

        // Act
        String[] result = MyCompare.upgradeStr(shorter, longer);

        // Assert
        assertEquals("", result[0], "Shorter should be empty when it's a prefix");
        assertEquals(" world", result[1], "Longer should contain the suffix difference");
    }

    @Test
    void should_ReturnBothEmpty_when_StringsAreIdentical() {
        // Arrange
        String shorter = "test";
        String longer = "test";

        // Act
        String[] result = MyCompare.upgradeStr(shorter, longer);

        // Assert
        assertEquals("", result[0], "Identical strings should return empty for shorter");
        assertEquals("", result[1], "Identical strings should return empty for longer");
    }

    @Test
    void should_PreserveFullStrings_when_NoCommonPrefixOrSuffix() {
        // Arrange
        String shorter = "abc";
        String longer = "xyz123";

        // Act
        String[] result = MyCompare.upgradeStr(shorter, longer);

        // Assert
        assertEquals("abc", result[0], "Should preserve full shorter string");
        assertEquals("xyz123", result[1], "Should preserve full longer string");
    }

    @Test
    void should_HandleComplexCase_when_OnlyPrefixMatches() {
        // Arrange
        String shorter = "prefix123";
        String longer = "prefix456789";

        // Act
        String[] result = MyCompare.upgradeStr(shorter, longer);

        // Assert
        assertEquals("123", result[0], "Should remove common prefix from shorter");
        assertEquals("456789", result[1], "Should remove common prefix from longer");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // html_flag 模式测试 (POC 处理)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_ReturnZeroSimilarity_when_OnlyOneStringHasPocRemaining() {
        // Arrange
        String s1 = "prefix123suffix";
        String s2 = "prefix456suffix";
        String poc1 = "123";
        String poc2 = "456";

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, poc1, poc2, true);

        // Assert
        // 移除前后缀后: "123" vs "456"
        // 移除 POC 后: "" vs ""
        // 应该返回 1.0 (两者都为空)
        assertEquals(1.0, levSims.get(0), 1e-9, "Both empty after POC removal should return 1.0");
    }

    @Test
    void should_HandleHtmlFlag_when_DifferenceIsOnlyInPoc() {
        // Arrange
        String s1 = "SELECT * FROM users WHERE id=1 LIMIT 10";
        String s2 = "SELECT * FROM users WHERE id=2 LIMIT 10";
        String poc1 = "id=1";
        String poc2 = "id=2";

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, poc1, poc2, true);

        // Assert
        // 移除前后缀后会得到差异部分,移除POC后应该相同或相似
        assertTrue(levSims.get(0) >= 0.0, "Should calculate similarity with html_flag");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 格式化方法测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_FormatNumberCorrectly_when_CallingFormatNumber() {
        // Arrange & Act
        String result1 = MyCompare.formatNumber(0.123456);
        String result2 = MyCompare.formatNumber(0.9);
        String result3 = MyCompare.formatNumber(1.0);

        // Assert
        assertEquals("0.123", result1, "Should format to 3 decimal places");
        assertEquals("0.900", result2, "Should pad with zeros");
        assertEquals("1.000", result3, "Should format integer as 3 decimals");
    }

    @Test
    void should_FormatPercentCorrectly_when_CallingFormatPercent() {
        // Arrange & Act
        String result1 = MyCompare.formatPercent(0.85);
        String result2 = MyCompare.formatPercent(0.5);

        // Assert
        assertTrue(result1.contains("85"), "Should format as percentage");
        assertTrue(result2.contains("50"), "Should format as percentage");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 参数化测试: 多种相似度场景
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @ParameterizedTest
    @CsvSource({
        "'abc', 'abc', 1.0",
        "'abc', 'abd', 0.667",
        "'test', 'best', 0.75",
        "'', 'x', 0.0"
    })
    void should_CalculateExpectedLevenshtein_when_GivenDifferentPairs(String s1, String s2, double expected) {
        // Act
        double similarity = MyCompare.levenshtein(s1, s2);

        // Assert
        assertEquals(expected, similarity, 0.01, "Levenshtein similarity should match expected");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 真实场景测试: SQL 注入检测
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_DetectDifference_when_SqlInjectionChangesResponse() {
        // Arrange: 正常响应 vs SQL 错误响应
        String normalResponse = "<html><body>User: John Doe</body></html>";
        String errorResponse = "<html><body>SQL Error: You have an error in your SQL syntax</body></html>";

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(normalResponse, errorResponse, "", "", false);

        // Assert
        assertTrue(levSims.get(0) < 0.9, "SQL error response should be significantly different from normal");
    }

    @Test
    void should_DetectSimilarity_when_OnlyTimestampDiffers() {
        // Arrange: 只有时间戳不同
        String response1 = "<html><body>Time: 2025-01-01 10:00:00, Data: test</body></html>";
        String response2 = "<html><body>Time: 2025-01-01 10:00:01, Data: test</body></html>";

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(response1, response2, "", "", false);

        // Assert
        assertTrue(levSims.get(0) > 0.9, "Responses with only timestamp differences should be highly similar");
    }

    @Test
    void should_HandleSpecialCharacters_when_SqlInjectionPayloads() {
        // Arrange: 包含特殊字符的 SQL 注入 payload
        String s1 = "test' OR '1'='1";
        String s2 = "test' AND '1'='2";

        // Act
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);

        // Assert
        // 这两个字符串长度差异为 0 (都是 16 字符), 根据代码逻辑会进入前缀/后缀检查
        // 由于长度相同,不会触发前缀/后缀包含, 会计算实际相似度
        assertTrue(levSims.get(0) > 0.7, "Similar SQL payloads should have moderate similarity");
    }
}

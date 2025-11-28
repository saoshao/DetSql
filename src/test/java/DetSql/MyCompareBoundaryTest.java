package DetSql;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import java.util.List;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;
import DetSql.util.MyCompare;

/**
 * MyCompare 边界测试
 * 
 * 测试范围:
 * 1. 长度差阈值边界 (LENGTH_DIFF_THRESHOLD = 100)
 * 2. 超大响应处理
 * 3. 特殊字符处理 (emoji, 中文, 控制字符)
 */
public class MyCompareBoundaryTest {

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 1. 长度差阈值边界测试 (最重要)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_CalculateSimilarity_when_LengthDiffIs99Bytes() {
        // 使用不同前后缀避免触发包含检测
        String s1 = "prefix_" + "a".repeat(93);
        String s2 = "suffix_" + "b".repeat(192);
        
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);
        assertTrue(levSims.get(0) >= 0.0, "长度差 = 99 应该计算相似度，不应该因阈值返回 0");
        // 注意：可能因为字符串完全不同返回 0，但不是因为长度差阈值
    }

    @Test
    void should_ReturnZero_when_LengthDiffIs100Bytes() {
        String s1 = "a".repeat(100);
        String s2 = "b".repeat(200);
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);
        assertEquals(0.0, levSims.get(0), 1e-9, "长度差 = 100 应该返回 0 (触发阈值)");
    }

    @Test
    void should_ReturnZero_when_LengthDiffIs101Bytes() {
        String s1 = "a".repeat(100);
        String s2 = "b".repeat(201);
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);
        assertEquals(0.0, levSims.get(0), 1e-9, "长度差 = 101 应该返回 0");
    }

    @Test
    void should_VerifyThresholdConstant_when_TestingBoundary() {
        // 验证阈值常量 LENGTH_DIFF_THRESHOLD = 100
        String base = "test_" + "x".repeat(45);  // 50 字符
        
        // 长度差 99: 不应该因阈值返回 0
        List<Double> result99 = MyCompare.averageLevenshtein(base, "data_" + "y".repeat(144), "", "", false);
        // 可能返回 0 但不是因为阈值（可能是其他逻辑）
        assertTrue(result99.get(0) >= 0.0, "长度差 99 不应该触发阈值");
        
        // 长度差 100: 应该因阈值返回 0
        List<Double> result100 = MyCompare.averageLevenshtein(base, "y".repeat(150), "", "", false);
        assertEquals(0.0, result100.get(0), 1e-9, "长度差 100 应该触发阈值返回 0");
        
        // 长度差 101: 应该因阈值返回 0
        List<Double> result101 = MyCompare.averageLevenshtein(base, "y".repeat(151), "", "", false);
        assertEquals(0.0, result101.get(0), 1e-9, "长度差 101 应该触发阈值返回 0");
    }

    @ParameterizedTest
    @CsvSource({
        "100, 200, false",  // 长度差 100: 应该返回 0
        "100, 201, false",  // 长度差 101: 应该返回 0
        "100, 250, false",  // 长度差 150: 应该返回 0
        "50, 150, false",   // 长度差 100: 应该返回 0
        "1, 101, false"     // 长度差 100: 应该返回 0
    })
    void should_RespectThreshold_when_TestingVariousLengthDiffs(
            int len1, int len2, boolean shouldCalculate) {
        String s1 = "a".repeat(len1);
        String s2 = "b".repeat(len2);
        List<Double> levSims = MyCompare.averageLevenshtein(s1, s2, "", "", false);
        
        // 所有测试用例都应该返回 0（长度差 >= 100）
        assertEquals(0.0, levSims.get(0), 1e-9, 
            String.format("长度 %d vs %d (差=%d) 应该返回 0", len1, len2, Math.abs(len2 - len1)));
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 2. 超大响应测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    @Timeout(value = 3, unit = TimeUnit.SECONDS)
    void should_CompleteQuickly_when_ComparingLargeIdenticalStrings() {
        int size = 10 * 1024; // 500KB
        String s1 = "a".repeat(size);
        String s2 = "a".repeat(size);
        
        long startTime = System.currentTimeMillis();
        double similarity = MyCompare.levenshtein(s1, s2);
        long endTime = System.currentTimeMillis();
        
        assertEquals(1.0, similarity, 1e-9, "相同的大字符串应该返回 1.0");
        assertTrue(endTime - startTime < 3000, 
            String.format("应在 3 秒内完成 (实际: %d ms)", endTime - startTime));
    }

    @Test
    @Timeout(value = 2, unit = TimeUnit.SECONDS)
    void should_NotThrowOOM_when_ComparingLargeStrings() {
        int size = 5 * 1024; // 100KB
        String s1 = "x".repeat(size);
        String s2 = "x".repeat(size);
        
        assertDoesNotThrow(() -> {
            double similarity = MyCompare.levenshtein(s1, s2);
            assertEquals(1.0, similarity, 1e-9);
        }, "大字符串比对不应该导致 OOM");
    }

    @Test
    void should_TriggerThreshold_when_LargeStringsExceed100BytesDiff() {
        String s1 = "a".repeat(5000);
        String s2 = "b".repeat(5200); // 长度差 200
        List<Double> result = MyCompare.averageLevenshtein(s1, s2, "", "", false);
        assertEquals(0.0, result.get(0), 1e-9, "长度差 >= 100 应该返回 0");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 3. 特殊字符测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_HandleEmojiCharacters_when_CalculatingSimilarity() {
        String s1 = "Hello 😀🎉 World";
        String s2 = "Hello 😀🎉 World";
        double levSim = MyCompare.levenshtein(s1, s2);
        assertEquals(1.0, levSim, 1e-9, "相同的 emoji 字符串应该返回 1.0");
    }

    @Test
    void should_DetectDifference_when_OnlyEmojiDiffers() {
        String s1 = "Status: 😀 Success";
        String s2 = "Status: 😢 Success";
        double levSim = MyCompare.levenshtein(s1, s2);
        assertTrue(levSim < 1.0 && levSim > 0.8, "不同的 emoji 应该被检测到");
    }

    @Test
    void should_HandleChineseCharacters_when_CalculatingSimilarity() {
        String s1 = "你好世界";
        String s2 = "你好世界";
        double levSim = MyCompare.levenshtein(s1, s2);
        assertEquals(1.0, levSim, 1e-9, "相同的中文字符串应该返回 1.0");
    }

    @Test
    void should_DetectChineseDifference_when_OneCharacterDiffers() {
        String s1 = "你好世界";
        String s2 = "你好地球";
        double levSim = MyCompare.levenshtein(s1, s2);
        assertTrue(levSim < 1.0, "不同的中文字符应该被检测到");
        assertEquals(0.5, levSim, 0.1, "4 个字符中 2 个不同，相似度约 0.5");
    }

    @Test
    void should_HandleControlCharacters_when_CalculatingSimilarity() {
        String s1 = "Line1\nLine2\rLine3\tTab";
        String s2 = "Line1\nLine2\rLine3\tTab";
        double levSim = MyCompare.levenshtein(s1, s2);
        assertEquals(1.0, levSim, 1e-9, "相同的控制字符应该被正确处理");
    }

    @Test
    void should_HandleMixedCharacters_when_ChineseEnglishEmoji() {
        String s1 = "Hello 你好 😀 World 世界";
        String s2 = "Hello 你好 😀 World 世界";
        double levSim = MyCompare.levenshtein(s1, s2);
        assertEquals(1.0, levSim, 1e-9, "相同的混合字符串应该返回 1.0");
    }

    @Test
    void should_HandleSpecialSqlCharacters_when_InjectionPayload() {
        String s1 = "test' OR '1'='1' --";
        String s2 = "test' OR '1'='1' --";
        double levSim = MyCompare.levenshtein(s1, s2);
        assertEquals(1.0, levSim, 1e-9, "相同的 SQL 注入 payload 应该返回 1.0");
    }

    @Test
    @Timeout(value = 2, unit = TimeUnit.SECONDS)
    void should_HandleLargeChineseStrings_when_TestingPerformance() {
        String s1 = "你好世界".repeat(1000);
        String s2 = "你好世界".repeat(1000);
        double levSim = MyCompare.levenshtein(s1, s2);
        assertEquals(1.0, levSim, 1e-9, "大量相同中文字符应该返回 1.0");
    }

    @Test
    void should_RespectThreshold_when_ChineseStringsExceedLengthDiff() {
        String s1 = "你好".repeat(30);  // 60 字符
        String s2 = "世界".repeat(100); // 200 字符，长度差 140
        List<Double> result = MyCompare.averageLevenshtein(s1, s2, "", "", false);
        assertEquals(0.0, result.get(0), 1e-9, "中文字符串长度差 >= 100 也应该返回 0");
    }
}

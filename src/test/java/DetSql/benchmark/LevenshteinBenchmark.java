package DetSql.benchmark;

import DetSql.util.MyCompare;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 性能基准测试：验证 Levenshtein 距离计算优化效果
 */
public class LevenshteinBenchmark {
    
    /**
     * 生成指定长度的随机字符串
     */
    private String generateRandomString(int length) {
        Random random = new Random(42); // 固定种子，保证可重复
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) ('a' + random.nextInt(26)));
        }
        return sb.toString();
    }
    
    /**
     * 生成指定长度的随机字符串（不同种子）
     */
    private String generateRandomString(int length, int seed) {
        Random random = new Random(seed);
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) ('a' + random.nextInt(26)));
        }
        return sb.toString();
    }
    
    @Test
    @DisplayName("小字符串性能测试 (100 字符)")
    public void benchmarkSmallStrings() {
        String s1 = generateRandomString(100);
        String s2 = generateRandomString(100, 43);
        
        // 预热
        for (int i = 0; i < 100; i++) {
            MyCompare.levenshtein(s1, s2);
        }
        
        // 正式测试
        long start = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            MyCompare.levenshtein(s1, s2);
        }
        long duration = System.nanoTime() - start;
        
        double avgMs = duration / 1_000_000.0 / 1000;
        System.out.println("小字符串 (100 字符) x 1000 次: " + 
            duration / 1_000_000 + " ms (平均: " + 
            String.format("%.3f", avgMs) + " ms/次)");
        
        // 应该在 100ms 内完成
        assertTrue(duration < 100_000_000, 
            "小字符串计算应该很快，实际耗时: " + duration / 1_000_000 + " ms");
    }
    
    @Test
    @DisplayName("中等字符串性能测试 (1000 字符)")
    public void benchmarkMediumStrings() {
        String s1 = generateRandomString(1000);
        String s2 = generateRandomString(1000, 43);
        
        // 预热
        for (int i = 0; i < 10; i++) {
            MyCompare.levenshtein(s1, s2);
        }
        
        // 正式测试
        long start = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            MyCompare.levenshtein(s1, s2);
        }
        long duration = System.nanoTime() - start;
        
        double avgMs = duration / 1_000_000.0 / 100;
        System.out.println("中等字符串 (1000 字符) x 100 次: " + 
            duration / 1_000_000 + " ms (平均: " + 
            String.format("%.3f", avgMs) + " ms/次)");
        
        // 应该在 500ms 内完成
        assertTrue(duration < 500_000_000, 
            "中等字符串计算应该较快，实际耗时: " + duration / 1_000_000 + " ms");
    }
    
    @Test
    @DisplayName("大字符串快速失败测试 (10KB)")
    public void benchmarkLargeStrings() {
        String s1 = generateRandomString(10_000);
        String s2 = generateRandomString(10_000, 43);
        
        long start = System.nanoTime();
        double similarity = MyCompare.levenshtein(s1, s2);
        long duration = System.nanoTime() - start;
        
        System.out.println("大字符串 (10KB): " + 
            duration / 1_000_000 + " ms, 相似度: " + 
            String.format("%.4f", similarity));
        
        // 应该在 100ms 内完成（快速失败机制）
        assertTrue(duration < 100_000_000, 
            "大字符串应该有快速失败机制，实际耗时: " + duration / 1_000_000 + " ms");
    }
    
    @Test
    @DisplayName("超大字符串快速失败测试 (50KB)")
    public void benchmarkVeryLargeStrings() {
        String s1 = generateRandomString(50_000);
        String s2 = generateRandomString(50_000, 43);
        
        long start = System.nanoTime();
        double similarity = MyCompare.levenshtein(s1, s2);
        long duration = System.nanoTime() - start;
        
        System.out.println("超大字符串 (50KB): " + 
            duration / 1_000_000 + " ms, 相似度: " + 
            String.format("%.4f", similarity));
        
        // 应该在 200ms 内完成（快速失败机制）
        assertTrue(duration < 200_000_000, 
            "超大字符串应该有快速失败机制，实际耗时: " + duration / 1_000_000 + " ms");
    }
    
    @Test
    @DisplayName("响应相似度计算性能测试")
    public void benchmarkResponseSimilarity() {
        String response1 = generateRandomString(50_000);
        String response2 = generateRandomString(50_000, 43);
        
        long start = System.nanoTime();
        double similarity = MyCompare.responseSimilarity(
            response1, response2, 0.9
        );
        long duration = System.nanoTime() - start;
        
        System.out.println("超大响应 (50KB): " + 
            duration / 1_000_000 + " ms, 相似度: " + 
            String.format("%.4f", similarity));
        
        // 应该在 200ms 内完成
        assertTrue(duration < 200_000_000, 
            "超大响应应该只比较关键部分，实际耗时: " + duration / 1_000_000 + " ms");
    }
    
    @Test
    @DisplayName("相同字符串性能测试（最优情况）")
    public void benchmarkIdenticalStrings() {
        String s1 = generateRandomString(10_000);
        String s2 = s1; // 完全相同
        
        long start = System.nanoTime();
        for (int i = 0; i < 10000; i++) {
            double similarity = MyCompare.levenshtein(s1, s2);
            assertEquals(1.0, similarity, 0.0001);
        }
        long duration = System.nanoTime() - start;
        
        System.out.println("相同字符串 (10KB) x 10000 次: " + 
            duration / 1_000_000 + " ms");
        
        // 相同字符串应该立即返回
        assertTrue(duration < 10_000_000, 
            "相同字符串应该立即返回，实际耗时: " + duration / 1_000_000 + " ms");
    }
    
    @Test
    @DisplayName("长度差异过大快速失败测试")
    public void benchmarkLengthDifferenceFailFast() {
        String s1 = generateRandomString(1000);
        String s2 = generateRandomString(100);
        
        long start = System.nanoTime();
        for (int i = 0; i < 10000; i++) {
            MyCompare.levenshteinWithThreshold(s1, s2, 0.9);
        }
        long duration = System.nanoTime() - start;
        
        System.out.println("长度差异过大 (1000 vs 100) x 10000 次: " + 
            duration / 1_000_000 + " ms");
        
        // 长度差异过大应该快速失败（使用阈值版本）
        assertTrue(duration < 50_000_000, 
            "长度差异过大应该快速失败，实际耗时: " + duration / 1_000_000 + " ms");
    }
    
    @Test
    @DisplayName("前缀差异过大快速失败测试")
    public void benchmarkPrefixDifferenceFailFast() {
        // 创建前 100 字符完全不同的字符串
        String s1 = "a".repeat(100) + generateRandomString(9900);
        String s2 = "z".repeat(100) + generateRandomString(9900);
        
        long start = System.nanoTime();
        double similarity = MyCompare.levenshtein(s1, s2);
        long duration = System.nanoTime() - start;
        
        System.out.println("前缀差异过大 (10KB): " + 
            duration / 1_000_000 + " ms, 相似度: " + 
            String.format("%.4f", similarity));
        
        // 前缀差异过大应该快速失败
        assertTrue(duration < 100_000_000, 
            "前缀差异过大应该快速失败，实际耗时: " + duration / 1_000_000 + " ms");
    }
    
    @Test
    @DisplayName("Jaccard 相似度性能测试")
    public void benchmarkJaccardSimilarity() {
        String s1 = generateRandomString(10_000);
        String s2 = generateRandomString(10_000, 43);
        
        long start = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            MyCompare.jaccard(s1, s2);
        }
        long duration = System.nanoTime() - start;
        
        double avgMs = duration / 1_000_000.0 / 100;
        System.out.println("Jaccard 相似度 (10KB) x 100 次: " + 
            duration / 1_000_000 + " ms (平均: " + 
            String.format("%.3f", avgMs) + " ms/次)");
        
        // Jaccard 应该比 Levenshtein 更快
        assertTrue(duration < 100_000_000, 
            "Jaccard 相似度应该很快，实际耗时: " + duration / 1_000_000 + " ms");
    }
}

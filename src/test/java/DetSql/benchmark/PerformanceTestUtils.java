package DetSql.benchmark;

import DetSql.PocLogEntry;

/**
 * 性能测试工具类
 *
 * 为JMH和单元测试提供测试数据生成
 */
public class PerformanceTestUtils {

    /**
     * 创建测试用的PocLogEntry
     * （简化版本，用于性能测试）
     */
    public static PocLogEntry createTestPocEntry(String name, String poc, String severity) {
        // PocLogEntry完整构造函数需要更多参数
        // 我们通过反射或其他方式创建一个最小化的实例
        return new PocLogEntry(
            name,              // name
            poc,               // poc
            "0.5",             // similarity (50%)
            "potential",       // vulnState
            "1024",            // bodyLength
            "200",             // statusCode
            "100ms",           // time
            null,              // httpRequestResponse (测试中不需要)
            "test_hash_" + System.nanoTime()  // myHash
        );
    }

    /**
     * 创建测试用的简单PocLogEntry
     */
    public static PocLogEntry createSimplePocEntry() {
        return createTestPocEntry(
            "test_poc",
            "SELECT.*FROM",
            "high"
        );
    }

    /**
     * 批量创建PocLogEntry
     */
    public static java.util.List<PocLogEntry> createPocEntries(int count) {
        java.util.List<PocLogEntry> entries = new java.util.ArrayList<>();
        for (int i = 0; i < count; i++) {
            entries.add(createTestPocEntry(
                "poc_" + i,
                "pattern_" + i,
                (i % 3 == 0) ? "high" : (i % 3 == 1) ? "medium" : "low"
            ));
        }
        return entries;
    }
}

package DetSql.benchmark;

import org.openjdk.jmh.annotations.*;
import DetSql.util.RegexUtils;

import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * ReDoS防护性能测试
 *
 * 测试场景：
 * 1. 正常SQL注入模式识别
 * 2. 安全边界的复杂正则
 * 3. 验证200ms超时机制
 * 4. 预编译vs动态编译性能对比
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Thread)
@Fork(value = 1, jvmArgs = {"-Xms256m", "-Xmx256m"})
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
public class ReDoSBenchmark {

    // 常见的SQL注入检测模式
    private static final String SQL_INJECTION_PATTERN =
        "(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|DECLARE|CAST|CONVERT|CHAR|SUBSTR|SUBSTRING|UNION|WHERE|FROM|ORDER|GROUP|HAVING|INTO|VALUES|SET|CASE|WHEN|THEN|ELSE|END|OR|AND|NOT|IN|EXISTS|LIKE|BETWEEN)";

    // 预编译Pattern（优化方案）
    private static final Pattern SQL_PATTERN_PRECOMPILED =
        Pattern.compile(SQL_INJECTION_PATTERN, Pattern.CASE_INSENSITIVE);

    // 测试用例
    private static final String SAFE_SQL = "SELECT * FROM users WHERE id = 123";
    private static final String INJECTION_ATTEMPT = "SELECT * FROM users WHERE id = 1 OR 1=1";
    private static final String LONG_PAYLOAD = "SELECT * FROM users WHERE username = 'admin' AND password = '"
        + "a".repeat(1000) + "'";

    // 复杂但安全的正则（多个嵌套组）
    private static final String COMPLEX_PATTERN =
        "^((SELECT|INSERT|UPDATE|DELETE)\\s+(FROM|INTO|TABLE)\\s+[a-zA-Z_][a-zA-Z0-9_]*)$";

    private static final Pattern COMPLEX_PATTERN_COMPILED =
        Pattern.compile(COMPLEX_PATTERN, Pattern.CASE_INSENSITIVE);

    /**
     * 基准测试1: 正常SQL检测
     */
    @Benchmark
    public boolean benchmarkNormalSQLDetection() {
        return RegexUtils.safeMatch(SQL_INJECTION_PATTERN, SAFE_SQL);
    }

    /**
     * 基准测试2: SQL注入检测
     */
    @Benchmark
    public boolean benchmarkSQLInjectionDetection() {
        return RegexUtils.safeMatch(SQL_INJECTION_PATTERN, INJECTION_ATTEMPT);
    }

    /**
     * 基准测试3: 长载荷处理
     */
    @Benchmark
    public boolean benchmarkLongPayload() {
        return RegexUtils.safeMatch(SQL_INJECTION_PATTERN, LONG_PAYLOAD);
    }

    /**
     * 基准测试4: 预编译Pattern性能
     */
    @Benchmark
    public boolean benchmarkPrecompiledPattern() {
        return RegexUtils.safeMatchPrecompiled(SQL_PATTERN_PRECOMPILED, SAFE_SQL);
    }

    /**
     * 基准测试5: 动态编译Pattern性能
     */
    @Benchmark
    public boolean benchmarkDynamicPattern() {
        return RegexUtils.safeMatch(SQL_INJECTION_PATTERN, SAFE_SQL);
    }

    /**
     * 基准测试6: 复杂正则表达式性能
     */
    @Benchmark
    public boolean benchmarkComplexPattern() {
        return RegexUtils.safeMatchPrecompiled(COMPLEX_PATTERN_COMPILED, SAFE_SQL);
    }

    /**
     * 基准测试7: 自定义超时（100ms）
     */
    @Benchmark
    public boolean benchmarkCustomTimeout100ms() {
        return RegexUtils.safeMatch(SQL_INJECTION_PATTERN, SAFE_SQL, 100);
    }

    /**
     * 基准测试8: 自定义超时（500ms）
     */
    @Benchmark
    public boolean benchmarkCustomTimeout500ms() {
        return RegexUtils.safeMatch(SQL_INJECTION_PATTERN, SAFE_SQL, 500);
    }

    /**
     * 基准测试9: 默认超时（200ms）
     */
    @Benchmark
    public boolean benchmarkDefaultTimeout() {
        return RegexUtils.safeMatch(SQL_INJECTION_PATTERN, SAFE_SQL);
    }

    /**
     * 基准测试10: 多个正则顺序检测
     */
    @Benchmark
    public boolean benchmarkMultiplePatterns() {
        boolean result = RegexUtils.safeMatch(SQL_INJECTION_PATTERN, SAFE_SQL);
        if (!result) {
            result = RegexUtils.safeMatchPrecompiled(COMPLEX_PATTERN_COMPILED, SAFE_SQL);
        }
        return result;
    }
}

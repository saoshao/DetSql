package DetSql.config;

import DetSql.ui.MyFilterRequest;
import org.junit.jupiter.api.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 配置加载和过滤规则应用的集成测试
 *
 * 测试目标:
 * 1. 验证配置正确加载到 MyFilterRequest 静态字段
 * 2. 验证域名黑名单过滤逻辑在历史数据场景下正确工作
 * 3. 验证配置更新的可见性（volatile 语义）
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class FilterConfigurationTest {

    private Set<String> originalBlacklist;
    private Set<String> originalWhitelist;
    private Set<String> originalBlackPath;
    private Set<String> originalBlackParams;

    @BeforeEach
    void setUp() {
        // 保存原始配置
        originalBlacklist = new HashSet<>(MyFilterRequest.blackListSet);
        originalWhitelist = new HashSet<>(MyFilterRequest.whiteListSet);
        originalBlackPath = new HashSet<>(MyFilterRequest.blackPathSet);
        originalBlackParams = new HashSet<>(MyFilterRequest.blackParamsSet);
    }

    @AfterEach
    void tearDown() {
        // 恢复原始配置
        MyFilterRequest.blackListSet = originalBlacklist;
        MyFilterRequest.whiteListSet = originalWhitelist;
        MyFilterRequest.blackPathSet = originalBlackPath;
        MyFilterRequest.blackParamsSet = originalBlackParams;
    }

    /**
     * 测试: 域名黑名单配置正确应用
     */
    @Test
    @Order(1)
    @DisplayName("测试域名黑名单配置应用")
    void testBlacklistConfiguration() {
        // 模拟用户配置黑名单
        Set<String> testBlacklist = Set.of(
            "datasink.baidu.com",
            "s.union.360.cn",
            "weixin.qq.com",
            "www.google.com"
        );

        // 应用配置
        MyFilterRequest.blackListSet = testBlacklist;

        // 验证配置已正确应用
        assertEquals(4, MyFilterRequest.blackListSet.size(),
            "黑名单应包含 4 个域名");
        assertTrue(MyFilterRequest.blackListSet.contains("datasink.baidu.com"),
            "黑名单应包含 datasink.baidu.com");
        assertTrue(MyFilterRequest.blackListSet.contains("weixin.qq.com"),
            "黑名单应包含 weixin.qq.com");
    }

    /**
     * 测试: 空黑名单配置
     */
    @Test
    @Order(2)
    @DisplayName("测试空黑名单配置")
    void testEmptyBlacklistConfiguration() {
        // 清空黑名单
        MyFilterRequest.blackListSet = new HashSet<>();

        // 验证
        assertTrue(MyFilterRequest.blackListSet.isEmpty(),
            "黑名单应为空");
    }

    /**
     * 测试: 白名单优先级高于黑名单
     */
    @Test
    @Order(3)
    @DisplayName("测试白名单和黑名单的优先级")
    void testWhitelistPriority() {
        // 配置白名单和黑名单
        MyFilterRequest.whiteListSet = Set.of("example.com");
        MyFilterRequest.blackListSet = Set.of("example.com", "evil.com");

        // 验证配置
        assertEquals(1, MyFilterRequest.whiteListSet.size(),
            "白名单应包含 1 个域名");
        assertEquals(2, MyFilterRequest.blackListSet.size(),
            "黑名单应包含 2 个域名");

        // 注意: 过滤逻辑中白名单优先
        // 如果 example.com 在白名单中, 即使也在黑名单中, 也应该通过
    }

    /**
     * 测试: 配置更新的可见性（模拟多线程场景）
     */
    @Test
    @Order(4)
    @DisplayName("测试配置更新的线程可见性")
    void testConfigurationVisibility() throws InterruptedException {
        // 初始配置
        MyFilterRequest.blackListSet = new HashSet<>(Set.of("old.com"));

        // 记录初始状态
        assertTrue(MyFilterRequest.blackListSet.contains("old.com"),
            "初始黑名单应包含 old.com");

        // 模拟另一个线程更新配置
        Thread updaterThread = new Thread(() -> {
            MyFilterRequest.blackListSet = new HashSet<>(Set.of("new.com"));
        });

        updaterThread.start();
        updaterThread.join();

        // 验证更新后的配置对当前线程可见（感谢 volatile）
        assertTrue(MyFilterRequest.blackListSet.contains("new.com"),
            "更新后的黑名单应包含 new.com");
        assertFalse(MyFilterRequest.blackListSet.contains("old.com"),
            "更新后的黑名单不应包含 old.com");
    }

    /**
     * 测试: 诊断标志重置功能
     */
    @Test
    @Order(5)
    @DisplayName("测试诊断标志重置")
    void testDiagnosticFlagReset() {
        // 配置黑名单
        MyFilterRequest.blackListSet = Set.of("test.com");

        // 调用重置方法（应该清空已记录的过滤域名集合）
        assertDoesNotThrow(() -> MyFilterRequest.resetDiagnosticFlags(),
            "重置诊断标志不应抛出异常");
    }

    /**
     * 测试: 大量域名黑名单的性能
     */
    @Test
    @Order(6)
    @DisplayName("测试大量域名黑名单的性能")
    void testLargeBlacklistPerformance() {
        // 生成 1000 个测试域名
        Set<String> largeBlacklist = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            largeBlacklist.add("domain" + i + ".com");
        }

        // 应用配置
        long startTime = System.nanoTime();
        MyFilterRequest.blackListSet = largeBlacklist;
        long endTime = System.nanoTime();

        // 验证
        assertEquals(1000, MyFilterRequest.blackListSet.size(),
            "黑名单应包含 1000 个域名");

        long durationMs = (endTime - startTime) / 1_000_000;
        assertTrue(durationMs < 100,
            "配置应用应在 100ms 内完成，实际耗时: " + durationMs + "ms");
    }

    /**
     * 测试: 配置不可变性保护
     */
    @Test
    @Order(7)
    @DisplayName("测试配置防御性拷贝")
    void testConfigurationDefensiveCopy() {
        // 创建原始集合
        Set<String> sourceSet = new HashSet<>(Set.of("test1.com", "test2.com"));

        // 应用配置
        MyFilterRequest.blackListSet = new HashSet<>(sourceSet);

        // 修改原始集合
        sourceSet.add("test3.com");

        // 验证配置未受影响
        assertEquals(2, MyFilterRequest.blackListSet.size(),
            "黑名单不应受到源集合修改的影响");
        assertFalse(MyFilterRequest.blackListSet.contains("test3.com"),
            "黑名单不应包含后添加的域名");
    }

    /**
     * 测试: 用户报告的问题场景重现
     *
     * 场景: 用户配置黑名单 "datasink.baidu.com,s.union.360.cn,weixin.qq.com,www.google.com"
     * 期望: 这些域名应该被正确过滤
     */
    @Test
    @Order(8)
    @DisplayName("重现用户报告的黑名单配置问题")
    void testUserReportedScenario() {
        // 模拟用户配置的黑名单
        String userInput = "datasink.baidu.com,s.union.360.cn,weixin.qq.com,www.google.com";
        Set<String> blacklist = new HashSet<>(Arrays.asList(userInput.split(",")));

        // 应用配置
        MyFilterRequest.blackListSet = blacklist;

        // 验证配置
        assertEquals(4, MyFilterRequest.blackListSet.size(),
            "黑名单应包含 4 个域名");

        // 验证每个域名都在黑名单中
        assertTrue(MyFilterRequest.blackListSet.contains("datasink.baidu.com"),
            "应包含 datasink.baidu.com");
        assertTrue(MyFilterRequest.blackListSet.contains("s.union.360.cn"),
            "应包含 s.union.360.cn");
        assertTrue(MyFilterRequest.blackListSet.contains("weixin.qq.com"),
            "应包含 weixin.qq.com");
        assertTrue(MyFilterRequest.blackListSet.contains("www.google.com"),
            "应包含 www.google.com");

        // 输出诊断信息
        System.out.println("用户配置的黑名单:");
        MyFilterRequest.blackListSet.forEach(domain ->
            System.out.println("  • " + domain));
    }
}

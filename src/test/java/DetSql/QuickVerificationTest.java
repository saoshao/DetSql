package DetSql;

import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * 快速验证测试
 * 验证所有修复是否正常工作
 * 
 * 运行方式: java DetSql.QuickVerificationTest
 */
public class QuickVerificationTest {
    
    private static int passedTests = 0;
    private static int failedTests = 0;

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║           DetSql 快速验证测试                                ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n");
        
        testMessagesChineseLoading();
        testMessagesEnglishLoading();
        testMessagesUIConfig();
        testMessagesWithParameters();
        testThreadSafeAttackMapBasic();
        testThreadSafeAttackMapConcurrency();
        testPocLogEntryFactoryMethod();
        testLogHelperWithoutInitialization();
        testMessagesKeyNotFound();
        testThreadSafeAttackMapEdgeCases();
        
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    测试结果汇总                              ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println("✅ 通过: " + passedTests + " 个测试");
        System.out.println("❌ 失败: " + failedTests + " 个测试");
        System.out.println("\n总体结果: " + (failedTests == 0 ? "✅ 全部通过" : "❌ 存在失败"));
        
        System.exit(failedTests == 0 ? 0 : 1);
    }
    
    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
    
    private static void assertFalse(boolean condition, String message) {
        if (condition) {
            throw new AssertionError(message);
        }
    }
    
    private static void assertEquals(Object expected, Object actual, String message) {
        if (expected == null && actual == null) return;
        if (expected == null || !expected.equals(actual)) {
            throw new AssertionError(message + " - Expected: " + expected + ", Actual: " + actual);
        }
    }
    
    private static void assertNotNull(Object object, String message) {
        if (object == null) {
            throw new AssertionError(message);
        }
    }
    
    private static void runTest(String testName, Runnable test) {
        System.out.println("\n" + testName);
        try {
            test.run();
            passedTests++;
        } catch (Exception e) {
            failedTests++;
            System.out.println("❌ 测试失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void testMessagesChineseLoading() {
        runTest("测试 1: Messages 中文加载", () -> {
            Messages.setLocale(Locale.SIMPLIFIED_CHINESE);
            String manualStop = Messages.get(Messages.MANUAL_STOP);
            
            assertNotNull(manualStop, "消息不应为 null");
            assertEquals("手动停止", manualStop, "中文消息应该正确");
            
            System.out.println("✅ 中文加载测试通过: " + manualStop);
        });
    }

    public static void testMessagesEnglishLoading() {
        runTest("测试 2: Messages 英文加载", () -> {
            Messages.setLocale(Locale.ENGLISH);
            String manualStop = Messages.get(Messages.MANUAL_STOP);
            
            assertNotNull(manualStop, "消息不应为 null");
            assertEquals("Manual Stop", manualStop, "英文消息应该正确");
            
            System.out.println("✅ 英文加载测试通过: " + manualStop);
        });
    }

    public static void testMessagesUIConfig() {
        runTest("测试 3: Messages UI 配置加载", () -> {
            Messages.setLocale(Locale.SIMPLIFIED_CHINESE);
            String domain = Messages.get("Domainwhitelisting");
            
            assertNotNull(domain, "UI 配置不应为 null");
            assertEquals("域名白名单", domain, "UI 配置应该正确");
            
            System.out.println("✅ UI 配置加载测试通过: " + domain);
        });
    }

    public static void testMessagesWithParameters() {
        runTest("测试 4: Messages 参数化消息", () -> {
            String error = Messages.get("error.invalid_offset", 100, 10, 20);
            
            assertNotNull(error, "参数化消息不应为 null");
            assertTrue(error.contains("100"), "应该包含参数 100");
            assertTrue(error.contains("10"), "应该包含参数 10");
            assertTrue(error.contains("20"), "应该包含参数 20");
            
            System.out.println("✅ 参数化消息测试通过: " + error);
        });
    }

    public static void testThreadSafeAttackMapBasic() {
        runTest("测试 5: ThreadSafeAttackMap 基本操作", () -> {
            ThreadSafeAttackMap map = new ThreadSafeAttackMap();
            
            // 初始化
            map.initializeRequest("test_hash");
            
            // 添加条目
            PocLogEntry entry = new PocLogEntry(
                "username", "' OR '1'='1", "90%", "errsql",
                "1234", "200", "0.123", null, "test_hash"
            );
            map.addEntry("test_hash", entry);
            
            // 验证
            assertTrue(map.hasAttacks("test_hash"), "应该有攻击记录");
            assertEquals(1, map.getAttackCount("test_hash"), "应该有 1 条记录");
            
            System.out.println("✅ ThreadSafeAttackMap 基本操作测试通过");
        });
    }

    public static void testThreadSafeAttackMapConcurrency() {
        runTest("测试 6: ThreadSafeAttackMap 并发安全", () -> {
            try {
                ThreadSafeAttackMap map = new ThreadSafeAttackMap();
                ExecutorService executor = Executors.newFixedThreadPool(10);
                
                // 并发写入 100 次
                for (int i = 0; i < 100; i++) {
                    final int index = i;
                    executor.submit(() -> {
                        String hash = "request_" + (index % 10);
                        map.initializeRequest(hash);
                        
                        PocLogEntry entry = new PocLogEntry(
                            "param" + index, "payload", "90%", "errsql",
                            "1234", "200", "0.123", null, hash
                        );
                        map.addEntry(hash, entry);
                    });
                }
                
                executor.shutdown();
                assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS), "应该在 5 秒内完成");
                
                // 验证结果
                assertEquals(10, map.size(), "应该有 10 个不同的请求");
                
                // 验证每个请求的条目数
                int totalEntries = 0;
                for (int i = 0; i < 10; i++) {
                    String hash = "request_" + i;
                    totalEntries += map.getAttackCount(hash);
                }
                assertEquals(100, totalEntries, "总共应该有 100 条记录");
                
                System.out.println("✅ ThreadSafeAttackMap 并发安全测试通过");
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public static void testPocLogEntryFactoryMethod() {
        runTest("测试 7: PocLogEntry 工厂方法", () -> {
            // 注意: 这里传 null 作为 response 仅用于测试
            // 实际使用时应该传入真实的 HttpRequestResponse
            PocLogEntry entry = PocLogEntry.fromResponse(
                "username",
                "' OR '1'='1",
                "90%",
                "errsql",
                null,  // 测试用
                "test_hash"
            );
            
            assertNotNull(entry, "条目不应为 null");
            assertEquals("username", entry.getName(), "参数名应该正确");
            assertEquals("' OR '1'='1", entry.getPoc(), "Payload 应该正确");
            assertEquals("90%", entry.getSimilarity(), "相似度应该正确");
            assertEquals("errsql", entry.getVulnState(), "注入类型应该正确");
            
            System.out.println("✅ PocLogEntry 工厂方法测试通过");
        });
    }

    public static void testLogHelperWithoutInitialization() {
        runTest("测试 8: LogHelper 未初始化降级处理", () -> {
            // LogHelper 未初始化时应该降级到 System.out/err
            // 不应该抛出异常
            LogHelper.logInfo("测试信息");
            LogHelper.logError("测试错误");
            LogHelper.logDebug("测试调试");
            
            System.out.println("✅ LogHelper 降级处理测试通过");
        });
    }

    public static void testMessagesKeyNotFound() {
        runTest("测试 9: Messages 键不存在时的降级处理", () -> {
            String notFound = Messages.get("non.existent.key");
            
            assertNotNull(notFound, "不存在的键应该返回键本身");
            assertEquals("non.existent.key", notFound, "应该返回键本身");
            
            System.out.println("✅ Messages 降级处理测试通过");
        });
    }

    public static void testThreadSafeAttackMapEdgeCases() {
        runTest("测试 10: ThreadSafeAttackMap 边界情况", () -> {
            ThreadSafeAttackMap map = new ThreadSafeAttackMap();
            
            // 测试未初始化的请求
            assertFalse(map.hasAttacks("non_existent"), "不存在的请求应该返回 false");
            assertEquals(0, map.getAttackCount("non_existent"), "不存在的请求应该返回 0");
            
            // 测试空列表
            map.initializeRequest("empty");
            assertFalse(map.hasAttacks("empty"), "空列表应该返回 false");
            assertEquals(0, map.getAttackCount("empty"), "空列表应该返回 0");
            
            // 测试清空
            map.initializeRequest("test");
            map.addEntry("test", new PocLogEntry(
                "param", "payload", "90%", "errsql",
                "1234", "200", "0.123", null, "test"
            ));
            map.clear();
            assertEquals(0, map.size(), "清空后应该为 0");
            
            System.out.println("✅ ThreadSafeAttackMap 边界情况测试通过");
        });
    }
}

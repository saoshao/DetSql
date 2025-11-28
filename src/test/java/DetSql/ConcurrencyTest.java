package DetSql;
import DetSql.model.PocLogEntry;


import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.*;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;
import DetSql.util.Statistics;

/**
 * 并发测试：验证多线程环境下的正确性
 */
public class ConcurrencyTest {
    
    @Test
    @DisplayName("attackMap 并发插入测试 - 验证 putIfAbsent 原子性")
    public void testAttackMapConcurrency() throws Exception {
        // 创建线程安全的 Map
        Map<String, List<PocLogEntry>> attackMap = 
            Collections.synchronizedMap(new HashMap<>());
        
        ExecutorService executor = Executors.newFixedThreadPool(10);
        String hash = "test-hash-" + System.currentTimeMillis();
        
        // 用于记录哪个线程成功插入
        ConcurrentHashMap<Integer, Boolean> winners = new ConcurrentHashMap<>();
        
        // 10 个线程同时尝试插入相同的 hash
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            final int threadId = i;
            futures.add(executor.submit(() -> {
                List<PocLogEntry> existing = attackMap.putIfAbsent(
                    hash, 
                    Collections.synchronizedList(new ArrayList<>())
                );
                if (existing == null) {
                    winners.put(threadId, true);
                }
            }));
        }
        
        // 等待所有线程完成
        for (Future<?> future : futures) {
            future.get(5, TimeUnit.SECONDS);
        }
        
        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        
        // 验证：只应有一个线程成功插入
        assertEquals(1, winners.size(), 
            "应该只有一个线程成功插入");
        assertEquals(1, attackMap.size(), 
            "Map 中应该只有一个条目");
        assertNotNull(attackMap.get(hash), 
            "插入的条目应该存在");
    }
    
    @Test
    @DisplayName("Statistics 并发记录测试 - 验证计数器线程安全")
    public void testStatisticsConcurrency() throws Exception {
        Statistics stats = new Statistics();
        ExecutorService executor = Executors.newFixedThreadPool(20);
        
        int threadsCount = 20;
        int operationsPerThread = 100;
        
        // 20 个线程同时记录统计信息
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threadsCount; i++) {
            final int threadId = i;
            futures.add(executor.submit(() -> {
                for (int j = 0; j < operationsPerThread; j++) {
                    stats.incrementRequestsProcessed();
                    stats.recordVulnerableParam(
                        "GET",
                        "example.com",
                        80,
                        "/api/test",
                        "param" + threadId + "_" + j
                    );
                }
            }));
        }
        
        for (Future<?> future : futures) {
            future.get(10, TimeUnit.SECONDS);
        }
        
        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        
        // 验证：应该有正确数量的请求
        int expectedRequests = threadsCount * operationsPerThread;
        assertEquals(expectedRequests, stats.getRequestsProcessed(),
            "请求计数应该准确");
        
        // 验证：应该有正确数量的不同参数
        int expectedVulnerabilities = threadsCount * operationsPerThread;
        assertEquals(expectedVulnerabilities, stats.getVulnerabilitiesFound(),
            "漏洞计数应该准确");
    }
    
    @Test
    @DisplayName("并发访问共享 List 测试")
    public void testConcurrentListAccess() throws Exception {
        List<PocLogEntry> sharedList = Collections.synchronizedList(new ArrayList<>());
        ExecutorService executor = Executors.newFixedThreadPool(10);
        
        int threadsCount = 10;
        int itemsPerThread = 50;
        
        // 多个线程同时向 List 添加元素
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threadsCount; i++) {
            final int threadId = i;
            futures.add(executor.submit(() -> {
                for (int j = 0; j < itemsPerThread; j++) {
                    PocLogEntry entry = new PocLogEntry(
                        "param" + j,
                        "payload" + j,
                        "0.95",
                        "ERROR_BASED",
                        "1024",
                        "200",
                        "0.5",
                        "http://example.com/test",
                        "GET",
                        "response preview",
                        System.currentTimeMillis(),
                        "hash" + threadId
                    );
                    sharedList.add(entry);
                }
            }));
        }
        
        for (Future<?> future : futures) {
            future.get(10, TimeUnit.SECONDS);
        }
        
        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        
        // 验证：所有元素都应该被添加
        int expectedSize = threadsCount * itemsPerThread;
        assertEquals(expectedSize, sharedList.size(),
            "List 大小应该等于所有线程添加的元素总数");
    }
    
    @Test
    @DisplayName("高并发场景下的压力测试")
    public void testHighConcurrencyStress() throws Exception {
        Map<String, List<PocLogEntry>> attackMap = 
            Collections.synchronizedMap(new HashMap<>());
        Statistics stats = new Statistics();
        
        ExecutorService executor = Executors.newFixedThreadPool(50);
        
        int threadsCount = 50;
        int operationsPerThread = 200;
        
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threadsCount; i++) {
            final int threadId = i;
            futures.add(executor.submit(() -> {
                for (int j = 0; j < operationsPerThread; j++) {
                    // 模拟真实场景：插入 Map、更新统计
                    String hash = "hash-" + (threadId % 10); // 10 个不同的 hash
                    
                    attackMap.computeIfAbsent(hash, 
                        k -> Collections.synchronizedList(new ArrayList<>()));
                    
                    stats.incrementRequestsProcessed();
                    
                    if (j % 10 == 0) {
                        stats.recordVulnerableParam(
                            "GET", "example.com", 80, 
                            "/api", "param" + threadId
                        );
                    }
                }
            }));
        }
        
        for (Future<?> future : futures) {
            future.get(30, TimeUnit.SECONDS);
        }
        
        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        
        // 验证：Map 应该有 10 个条目
        assertEquals(10, attackMap.size(),
            "应该有 10 个不同的 hash");
        
        // 验证：请求计数正确
        int expectedRequests = threadsCount * operationsPerThread;
        assertEquals(expectedRequests, stats.getRequestsProcessed(),
            "请求计数应该准确");
    }
}

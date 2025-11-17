package DetSql;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AttackMap 缓存测试 - 测试关键路径的存储、检索和并发安全性
 *
 * AttackMap 结构: ConcurrentHashMap&lt;String, List&lt;PocLogEntry&gt;&gt;
 * - Key: 请求的唯一标识 (hash)
 * - Value: 该请求的所有 SQL 注入检测结果列表
 *
 * 这些测试将在 Task 1 (LRU 缓存替换) 时作为回归测试基准
 */
public class AttackMapCacheTest {

    private ConcurrentHashMap<String, List<PocLogEntry>> mAttackMap;

    @BeforeEach
    void setUp() {
        mAttackMap = new ConcurrentHashMap<>();
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 基本存储和检索测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_StoreEntry_when_AddingNewKey() {
        // Arrange
        String hash = "test_hash_123";
        PocLogEntry entry = new PocLogEntry("id", "' OR 1=1--", "0.95");

        // Act
        List<PocLogEntry> entries = new ArrayList<>();
        entries.add(entry);
        mAttackMap.put(hash, entries);

        // Assert
        assertTrue(mAttackMap.containsKey(hash), "AttackMap should contain the key");
        assertEquals(1, mAttackMap.get(hash).size(), "Should have 1 entry");
        assertEquals("id", mAttackMap.get(hash).get(0).getName(), "Entry name should match");
    }

    @Test
    void should_RetrieveCorrectEntry_when_MultipleKeysExist() {
        // Arrange
        String hash1 = "hash_001";
        String hash2 = "hash_002";
        PocLogEntry entry1 = new PocLogEntry("user", "admin' --", "0.85");
        PocLogEntry entry2 = new PocLogEntry("pass", "' OR '1'='1", "0.90");

        // Act
        mAttackMap.put(hash1, List.of(entry1));
        mAttackMap.put(hash2, List.of(entry2));

        // Assert
        assertEquals("user", mAttackMap.get(hash1).get(0).getName(), "hash1 should map to entry1");
        assertEquals("pass", mAttackMap.get(hash2).get(0).getName(), "hash2 should map to entry2");
    }

    @Test
    void should_AppendToExistingList_when_KeyAlreadyExists() {
        // Arrange
        String hash = "existing_hash";
        PocLogEntry entry1 = new PocLogEntry("id", "1' OR '1'='1", "0.80");
        PocLogEntry entry2 = new PocLogEntry("id", "1' UNION SELECT", "0.75");

        // Act
        List<PocLogEntry> entries = new ArrayList<>();
        entries.add(entry1);
        mAttackMap.put(hash, entries);

        // 追加第二个 entry (模拟实际使用场景)
        mAttackMap.get(hash).add(entry2);

        // Assert
        assertEquals(2, mAttackMap.get(hash).size(), "Should have 2 entries for same hash");
        assertEquals("1' OR '1'='1", mAttackMap.get(hash).get(0).getPoc());
        assertEquals("1' UNION SELECT", mAttackMap.get(hash).get(1).getPoc());
    }

    @Test
    void should_ReturnNull_when_KeyDoesNotExist() {
        // Arrange
        String nonExistentHash = "nonexistent_hash";

        // Act
        List<PocLogEntry> result = mAttackMap.get(nonExistentHash);

        // Assert
        assertNull(result, "Non-existent key should return null");
    }

    @Test
    void should_ReplaceList_when_PuttingSameKeyAgain() {
        // Arrange
        String hash = "hash_replace";
        PocLogEntry oldEntry = new PocLogEntry("old", "old_poc", "0.5");
        PocLogEntry newEntry = new PocLogEntry("new", "new_poc", "0.9");

        // Act
        mAttackMap.put(hash, List.of(oldEntry));
        mAttackMap.put(hash, List.of(newEntry)); // 替换

        // Assert
        assertEquals(1, mAttackMap.get(hash).size(), "Should have 1 entry after replacement");
        assertEquals("new", mAttackMap.get(hash).get(0).getName(), "Should contain new entry");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 并发安全性测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_HandleConcurrentWrites_when_MultipleThreadsWrite() throws InterruptedException {
        // Arrange
        int threadCount = 10;
        int entriesPerThread = 100;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        // Act: 10 个线程并发写入
        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    startLatch.await(); // 等待所有线程就绪
                    for (int i = 0; i < entriesPerThread; i++) {
                        String hash = "thread_" + threadId + "_entry_" + i;
                        PocLogEntry entry = new PocLogEntry("param" + i, "poc" + i, "0.8");
                        mAttackMap.put(hash, List.of(entry));
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown(); // 同时开始
        boolean completed = doneLatch.await(10, TimeUnit.SECONDS);

        // Assert
        assertTrue(completed, "All threads should complete within timeout");
        assertEquals(threadCount * entriesPerThread, mAttackMap.size(),
            "Should have correct number of entries after concurrent writes");

        executor.shutdown();
    }

    @Test
    void should_HandleConcurrentReadsAndWrites_when_MixedOperations() throws InterruptedException {
        // Arrange
        int readerCount = 5;
        int writerCount = 5;
        AtomicInteger readSuccessCount = new AtomicInteger(0);
        AtomicInteger writeCount = new AtomicInteger(0);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(readerCount + writerCount);
        ExecutorService executor = Executors.newFixedThreadPool(readerCount + writerCount);

        // 预填充一些数据
        for (int i = 0; i < 50; i++) {
            String hash = "initial_" + i;
            mAttackMap.put(hash, List.of(new PocLogEntry("param", "poc", "0.8")));
        }

        // Act: 启动读线程
        for (int r = 0; r < readerCount; r++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int i = 0; i < 100; i++) {
                        String hash = "initial_" + (i % 50);
                        List<PocLogEntry> result = mAttackMap.get(hash);
                        if (result != null && !result.isEmpty()) {
                            readSuccessCount.incrementAndGet();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        // Act: 启动写线程
        for (int w = 0; w < writerCount; w++) {
            final int writerId = w;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int i = 0; i < 100; i++) {
                        String hash = "writer_" + writerId + "_" + i;
                        mAttackMap.put(hash, List.of(new PocLogEntry("param", "poc", "0.8")));
                        writeCount.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean completed = doneLatch.await(10, TimeUnit.SECONDS);

        // Assert
        assertTrue(completed, "All threads should complete");
        assertTrue(readSuccessCount.get() > 0, "Should have successful reads");
        assertEquals(writerCount * 100, writeCount.get(), "Should have correct write count");
        assertTrue(mAttackMap.size() >= 50, "Should have at least initial entries");

        executor.shutdown();
    }

    @Test
    void should_HandleConcurrentAppends_when_SameKeyUpdatedByMultipleThreads() throws InterruptedException {
        // Arrange: 测试同一个 key 被多个线程追加的场景
        String sharedHash = "shared_key";
        int threadCount = 10;
        int appendsPerThread = 10;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        // 初始化共享 key,使用线程安全的 List
        List<PocLogEntry> synchronizedList = new CopyOnWriteArrayList<>();
        mAttackMap.put(sharedHash, synchronizedList);

        // Act: 多个线程追加到同一个 key
        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int i = 0; i < appendsPerThread; i++) {
                        PocLogEntry entry = new PocLogEntry("thread_" + threadId, "poc_" + i, "0.8");
                        mAttackMap.get(sharedHash).add(entry);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean completed = doneLatch.await(10, TimeUnit.SECONDS);

        // Assert
        assertTrue(completed, "All threads should complete");
        assertEquals(threadCount * appendsPerThread, mAttackMap.get(sharedHash).size(),
            "Should have correct number of entries appended by all threads");

        executor.shutdown();
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 边界情况测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_HandleEmptyList_when_StoringEmptyList() {
        // Arrange
        String hash = "empty_list_hash";
        List<PocLogEntry> emptyList = new ArrayList<>();

        // Act
        mAttackMap.put(hash, emptyList);

        // Assert
        assertTrue(mAttackMap.containsKey(hash), "Should contain key even with empty list");
        assertEquals(0, mAttackMap.get(hash).size(), "List should be empty");
    }

    @Test
    void should_HandleLargeNumberOfEntries_when_StoringManyKeys() {
        // Arrange & Act
        int keyCount = 10000;
        for (int i = 0; i < keyCount; i++) {
            String hash = "key_" + i;
            PocLogEntry entry = new PocLogEntry("param_" + i, "poc_" + i, "0.8");
            mAttackMap.put(hash, List.of(entry));
        }

        // Assert
        assertEquals(keyCount, mAttackMap.size(), "Should store large number of keys");

        // 验证随机访问
        String randomKey = "key_5000";
        assertNotNull(mAttackMap.get(randomKey), "Should be able to retrieve from large map");
        assertEquals("param_5000", mAttackMap.get(randomKey).get(0).getName());
    }

    @Test
    void should_HandleSpecialCharactersInHash_when_UsingComplexKeys() {
        // Arrange
        String complexHash = "SM3:ABC123!@#$%^&*()_+-=[]{}|;':\",./<>?";
        PocLogEntry entry = new PocLogEntry("id", "poc", "0.8");

        // Act
        mAttackMap.put(complexHash, List.of(entry));

        // Assert
        assertTrue(mAttackMap.containsKey(complexHash), "Should handle special characters in key");
        assertNotNull(mAttackMap.get(complexHash), "Should retrieve entry with special char key");
    }

    @Test
    void should_ClearAllEntries_when_CallingClear() {
        // Arrange
        for (int i = 0; i < 100; i++) {
            mAttackMap.put("key_" + i, List.of(new PocLogEntry("p", "poc", "0.8")));
        }

        // Act
        mAttackMap.clear();

        // Assert
        assertEquals(0, mAttackMap.size(), "Map should be empty after clear");
        assertTrue(mAttackMap.isEmpty(), "Map should report as empty");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 真实场景模拟
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_SimulateTypicalScanWorkflow_when_AddingMultiplePayloadsPerRequest() {
        // Arrange: 模拟对一个请求进行多种 payload 测试
        String requestHash = "request_abc123";

        // Act: 模拟扫描流程 - Error-based SQL
        List<PocLogEntry> entries = new ArrayList<>();
        entries.add(new PocLogEntry("id", "1' AND '1'='1", "0.95", "errsql", "1234", "200", "123", null, requestHash));
        entries.add(new PocLogEntry("id", "1' AND '1'='2", "0.45", "errsql", "567", "500", "125", null, requestHash));

        // String-based SQL
        entries.add(new PocLogEntry("id", "test' OR '1'='1", "0.90", "stringsql", "2000", "200", "130", null, requestHash));

        // Numeric-based SQL
        entries.add(new PocLogEntry("id", "1 OR 1=1", "0.88", "numsql", "1234", "200", "128", null, requestHash));

        mAttackMap.put(requestHash, entries);

        // Assert
        List<PocLogEntry> results = mAttackMap.get(requestHash);
        assertNotNull(results, "Should retrieve scan results");
        assertEquals(4, results.size(), "Should have 4 different payloads tested");

        // 验证不同注入类型
        long errorSqlCount = results.stream().filter(e -> "errsql".equals(e.getVulnState())).count();
        assertEquals(2, errorSqlCount, "Should have 2 error-based tests");

        long stringSqlCount = results.stream().filter(e -> "stringsql".equals(e.getVulnState())).count();
        assertEquals(1, stringSqlCount, "Should have 1 string-based test");
    }

    @Test
    void should_HandleHashCollision_when_MultipleRequestsWithSameHash() {
        // Arrange: 虽然 ConcurrentHashMap 会处理哈希碰撞,但测试相同 key 的覆盖行为
        String hash = "collision_hash";

        // Act
        mAttackMap.put(hash, List.of(new PocLogEntry("first", "poc1", "0.8")));
        mAttackMap.put(hash, List.of(new PocLogEntry("second", "poc2", "0.9")));

        // Assert: 后者覆盖前者
        assertEquals(1, mAttackMap.get(hash).size(), "Latest put should win");
        assertEquals("second", mAttackMap.get(hash).get(0).getName(), "Should have latest entry");
    }

    @RepeatedTest(3)
    void should_BeConsistent_when_RepeatedlyTestedUnderLoad() {
        // Arrange & Act: 重复测试确保一致性
        String hash = "consistency_test";
        for (int i = 0; i < 1000; i++) {
            PocLogEntry entry = new PocLogEntry("param_" + i, "poc_" + i, "0.8");
            List<PocLogEntry> list = new ArrayList<>();
            list.add(entry);
            mAttackMap.put(hash + "_" + i, list);
        }

        // Assert
        assertEquals(1000, mAttackMap.size(), "Should have consistent size");
        for (int i = 0; i < 1000; i++) {
            assertNotNull(mAttackMap.get(hash + "_" + i), "Should retrieve all entries");
        }
    }
}

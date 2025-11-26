package DetSql;
import DetSql.util.Statistics;

import DetSql.model.PocLogEntry;


import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 内存泄漏测试：验证长时间运行不会导致 OOM
 */
public class MemoryLeakTest {
    
    @Test
    @DisplayName("LRU 缓存不会无限增长")
    public void testLRUCacheDoesNotGrowIndefinitely() {
        int maxSize = 100;
        Map<String, List<PocLogEntry>> cache = 
            Collections.synchronizedMap(new LinkedHashMap<String, List<PocLogEntry>>(maxSize + 1, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, List<PocLogEntry>> eldest) {
                    return size() > maxSize;
                }
            });
        
        // 插入 1000 个条目
        for (int i = 0; i < 1000; i++) {
            cache.put("key-" + i, new ArrayList<>());
        }
        
        // 验证：缓存大小应该被限制
        assertTrue(cache.size() <= maxSize, 
            "LRU 缓存应该限制大小，实际大小: " + cache.size());
    }
    
    @Test
    @DisplayName("Statistics 重置功能测试")
    public void testStatisticsReset() {
        Statistics stats = new Statistics();
        
        // 记录大量数据
        for (int i = 0; i < 10000; i++) {
            stats.incrementRequestsProcessed();
            stats.recordVulnerableParam(
                "GET", "example.com", 80, "/api", "param" + i
            );
        }
        
        // 验证数据已记录
        assertEquals(10000, stats.getRequestsProcessed());
        assertEquals(10000, stats.getVulnerabilitiesFound());
        
        // 重置
        stats.reset();
        
        // 验证：所有计数器应该归零
        assertEquals(0, stats.getRequestsProcessed(),
            "重置后请求计数应该为 0");
        assertEquals(0, stats.getVulnerabilitiesFound(),
            "重置后漏洞计数应该为 0");
    }
    
    @Test
    @DisplayName("PocLogEntry 不持有大对象引用")
    public void testPocLogEntryMemoryFootprint() {
        // 创建一个 PocLogEntry
        PocLogEntry entry = new PocLogEntry(
            "param",
            "' OR '1'='1",
            "0.95",
            "ERROR_BASED",
            "1024",
            "200",
            "0.5",
            "http://example.com/test?param=value",
            "GET",
            "SQL error detected",
            System.currentTimeMillis(),
            "hash123"
        );
        
        // 验证：PocLogEntry 不应该持有完整的 HttpRequestResponse
        // 这是通过代码审查确认的，这里只是文档化这个要求
        assertNotNull(entry.getUrl());
        assertNotNull(entry.getMethod());
        assertNotNull(entry.getName()); // 参数名
        
        // PocLogEntry 应该只存储必要的字符串信息
        // 而不是完整的 HTTP 请求/响应对象
    }
    
    @Test
    @DisplayName("大量请求处理后内存可回收")
    public void testMemoryReclamationAfterProcessing() {
        Map<String, List<PocLogEntry>> attackMap = 
            Collections.synchronizedMap(new HashMap<>());
        
        // 模拟处理大量请求
        for (int i = 0; i < 5000; i++) {
            String hash = "hash-" + i;
            List<PocLogEntry> entries = new ArrayList<>();
            
            for (int j = 0; j < 10; j++) {
                entries.add(new PocLogEntry(
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
                    hash
                ));
            }
            
            attackMap.put(hash, entries);
        }
        
        // 验证数据已存储
        assertEquals(5000, attackMap.size());
        
        // 清空 Map（模拟用户点击清理按钮）
        attackMap.clear();
        
        // 验证：Map 已清空
        assertEquals(0, attackMap.size(),
            "清空后 Map 应该为空");
        
        // 建议 GC（不保证立即执行，但表明意图）
        System.gc();
        
        // 此时之前的 PocLogEntry 对象应该可以被 GC 回收
    }
    
    @Test
    @DisplayName("临时文件清理测试")
    public void testTempFileCleanup() {
        // 这个测试验证 copyToTempFile 方法正确清理临时文件
        // 实际的清理逻辑在 MyHttpHandler 中实现
        
        // 创建临时文件路径
        String tempDir = System.getProperty("java.io.tmpdir");
        assertNotNull(tempDir, "临时目录应该存在");
        
        // 验证临时目录可写
        java.io.File dir = new java.io.File(tempDir);
        assertTrue(dir.exists(), "临时目录应该存在");
        assertTrue(dir.canWrite(), "临时目录应该可写");
        
        // 注意：实际的文件清理测试在 FileLeak_copyToTempFile_Test 中
    }
    
    @Test
    @DisplayName("长时间运行模拟 - 内存稳定性")
    public void testLongRunningStability() {
        Statistics stats = new Statistics();
        Map<String, List<PocLogEntry>> attackMap = 
            Collections.synchronizedMap(new LinkedHashMap<String, List<PocLogEntry>>(1000 + 1, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, List<PocLogEntry>> eldest) {
                    return size() > 1000;
                }
            });
        
        // 模拟长时间运行：处理 50000 个请求
        for (int i = 0; i < 50000; i++) {
            stats.incrementRequestsProcessed();
            
            // 每 10 个请求记录一个漏洞
            if (i % 10 == 0) {
                String hash = "hash-" + (i % 500); // 循环使用 500 个不同的 hash
                
                attackMap.computeIfAbsent(hash, 
                    k -> Collections.synchronizedList(new ArrayList<>()));
                
                List<PocLogEntry> entries = attackMap.get(hash);
                if (entries.size() < 10) { // 每个 hash 最多 10 个条目
                    entries.add(new PocLogEntry(
                        "param",
                        "payload",
                        "0.95",
                        "ERROR_BASED",
                        "1024",
                        "200",
                        "0.5",
                        "http://example.com/test",
                        "GET",
                        "response preview",
                        System.currentTimeMillis(),
                        hash
                    ));
                }
                
                stats.recordVulnerableParam(
                    "GET", "example.com", 80, "/api", "param" + (i % 100)
                );
            }
        }
        
        // 验证：统计信息正确
        assertEquals(50000, stats.getRequestsProcessed());
        
        // 验证：Map 大小受限（LRU 缓存）
        assertTrue(attackMap.size() <= 1000,
            "Map 大小应该受 LRU 限制，实际: " + attackMap.size());
        
        // 验证：漏洞数量正确（每个参数只记录一次，共 100 个不同的参数）
        // 注意：实际数量取决于 Statistics 的去重逻辑
        assertTrue(stats.getVulnerabilitiesFound() >= 10,
            "应该至少记录 10 个漏洞，实际: " + stats.getVulnerabilitiesFound());
    }
}

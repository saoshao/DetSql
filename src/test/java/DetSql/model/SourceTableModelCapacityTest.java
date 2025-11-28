package DetSql.model;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * P0-1 修复验证测试：SourceTableModel 容量限制
 * 
 * 测试目标：
 * - 验证 10000 条记录上限
 * - 验证超出容量时自动移除最旧记录
 * - 验证 hashIndex 同步更新
 */
public class SourceTableModelCapacityTest {

    @Test
    public void testCapacityLimit_ExactlyMaxSize() {
        SourceTableModel model = new SourceTableModel();
        
        // 添加恰好 10000 条记录
        for (int i = 0; i < 10000; i++) {
            SourceLogEntry entry = createEntry(i);
            model.add(entry);
        }
        
        // 应该恰好保留 10000 条
        assertEquals(10000, model.getRowCount(), "应该保留恰好 10000 条记录");
    }

    @Test
    public void testCapacityLimit_ExceedMaxSize() {
        SourceTableModel model = new SourceTableModel();
        
        // 添加 10001 条记录
        for (int i = 0; i < 10001; i++) {
            SourceLogEntry entry = createEntry(i);
            model.add(entry);
        }
        
        // 应该只保留最新的 10000 条
        assertEquals(10000, model.getRowCount(), "超出容量时应该只保留 10000 条记录");
        
        // 验证最旧的记录 (id=0) 已被移除
        SourceLogEntry firstEntry = model.get(0);
        assertEquals(1, firstEntry.getId(), "最旧的记录应该被移除,当前第一条应该是 id=1");
    }

    @Test
    public void testCapacityLimit_LargeVolume() {
        SourceTableModel model = new SourceTableModel();
        
        // 模拟长期扫描：添加 15000 条记录
        for (int i = 0; i < 15000; i++) {
            SourceLogEntry entry = createEntry(i);
            model.add(entry);
        }
        
        // 应该只保留最新的 10000 条
        assertEquals(10000, model.getRowCount(), "大量添加后应该稳定在 10000 条");
        
        // 验证保留的是最新的 10000 条 (id: 5000-14999)
        SourceLogEntry firstEntry = model.get(0);
        SourceLogEntry lastEntry = model.get(9999);
        
        assertEquals(5000, firstEntry.getId(), "第一条应该是 id=5000");
        assertEquals(14999, lastEntry.getId(), "最后一条应该是 id=14999");
    }

    @Test
    public void testHashIndexSynchronization() {
        SourceTableModel model = new SourceTableModel();
        
        // 添加 10005 条带 hash 的记录
        for (int i = 0; i < 10005; i++) {
            SourceLogEntry entry = createEntry(i);
            model.add(entry);
        }
        
        // 验证 hashIndex 与 log 保持同步
        // 前 5 条 (id: 0-4) 应该已被移除,无法通过 hash 查找
        assertNull(model.findByHash("hash-0"), "被移除的记录不应该在 hashIndex 中");
        assertNull(model.findByHash("hash-4"), "被移除的记录不应该在 hashIndex 中");
        
        // 后续记录 (id: 5-10004) 应该可以通过 hash 查找
        assertNotNull(model.findByHash("hash-5"), "保留的记录应该在 hashIndex 中");
        assertNotNull(model.findByHash("hash-10004"), "保留的记录应该在 hashIndex 中");
    }

    @Test
    public void testMemoryStability() {
        SourceTableModel model = new SourceTableModel();
        
        // 模拟持续添加 (如长时间扫描)
        for (int i = 0; i < 20000; i++) {
            SourceLogEntry entry = createEntry(i);
            model.add(entry);
            
            // 每次添加后都不应该超过上限
            assertTrue(model.getRowCount() <= 10000, 
                "任何时刻记录数都不应超过 10000,当前: " + model.getRowCount());
        }
        
        // 最终应该稳定在 10000
        assertEquals(10000, model.getRowCount(), "应该稳定在 10000 条");
    }

    /**
     * 创建测试用的 SourceLogEntry
     */
    private SourceLogEntry createEntry(int id) {
        String myHash = "hash-" + id;
        SourceLogEntry entry = new SourceLogEntry(
            id,                          // id
            "Proxy",                     // tool
            myHash,                      // myHash
            null,                        // vulnState
            100,                         // bodyLength
            null,                        // requestResponse (简化测试,不创建完整对象)
            "example.com",               // httpService
            "GET",                       // method
            "/path/" + id                // path
        );
        return entry;
    }
}

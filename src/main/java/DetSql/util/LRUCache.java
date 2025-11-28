/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql.util;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * LRU (Least Recently Used) 缓存实现
 * 基于 LinkedHashMap 的访问顺序模式
 *
 * 注意: 此类不支持克隆,因为缓存的语义是唯一的
 *
 * @param <K> 键类型
 * @param <V> 值类型
 */
public final class LRUCache<K, V> extends LinkedHashMap<K, V> {
    private final int maxSize;

    /**
     * 创建 LRU 缓存
     * 
     * @param maxSize 最大容量
     */
    public LRUCache(int maxSize) {
        super(16, 0.75f, true); // accessOrder = true (访问顺序)
        this.maxSize = maxSize;
    }

    /**
     * 当插入新条目时,判断是否需要移除最老的条目
     * 
     * @param eldest 最老的条目
     * @return true 表示移除最老的条目
     */
    @Override
    protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
        return size() > maxSize;
    }

    /**
     * 禁止克隆 - 缓存不应该被复制
     * 抛出UnsupportedOperationException而不是CloneNotSupportedException,
     * 因为LinkedHashMap的clone()不声明checked exception
     *
     * @return 不返回
     * @throws UnsupportedOperationException 总是抛出
     */
    @Override
    public Object clone() {
        return super.clone();
    }
}

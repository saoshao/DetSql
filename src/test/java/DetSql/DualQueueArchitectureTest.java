package DetSql;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.reflect.Field;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 测试双队列架构的基本功能
 * 
 * 验证：
 * 1. RECEIVE_EXECUTOR 和 SCAN_EXECUTOR 的配置正确
 * 2. 线程池参数符合设计要求
 */
public class DualQueueArchitectureTest {

    /**
     * 使用反射获取私有的线程池字段
     */
    private ThreadPoolExecutor getExecutor(String fieldName) throws Exception {
        Field field = MyHttpHandler.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return (ThreadPoolExecutor) field.get(null);
    }

    @Test
    void testReceiveExecutorConfiguration() throws Exception {
        ThreadPoolExecutor receiveExecutor = getExecutor("RECEIVE_EXECUTOR");
        
        assertNotNull(receiveExecutor, "RECEIVE_EXECUTOR 应该被初始化");
        
        int processors = Runtime.getRuntime().availableProcessors();
        
        // 验证核心线程数（根据 CPU 性能动态调整）
        assertEquals(processors, receiveExecutor.getCorePoolSize(), 
            "RECEIVE_EXECUTOR 核心线程数应该等于 CPU 核心数");
        
        // 验证最大线程数（根据 CPU 性能动态调整）
        assertEquals(processors * 2, receiveExecutor.getMaximumPoolSize(), 
            "RECEIVE_EXECUTOR 最大线程数应该是 CPU 核心数的 2 倍");
        
        // 验证队列容量（基准：5000）
        assertEquals(5000, receiveExecutor.getQueue().remainingCapacity(), 
            "RECEIVE_EXECUTOR 队列容量应该是 5000（基准）");
        
        // 验证线程名称前缀
        Thread testThread = receiveExecutor.getThreadFactory().newThread(() -> {});
        assertTrue(testThread.getName().startsWith("DetSql-Receive-"), 
            "RECEIVE_EXECUTOR 线程名称应该以 'DetSql-Receive-' 开头");
        
        // 验证是守护线程
        assertTrue(testThread.isDaemon(), 
            "RECEIVE_EXECUTOR 的线程应该是守护线程");
    }

    @Test
    void testScanExecutorConfiguration() throws Exception {
        ThreadPoolExecutor scanExecutor = getExecutor("SCAN_EXECUTOR");
        
        assertNotNull(scanExecutor, "SCAN_EXECUTOR 应该被初始化");
        
        int processors = Runtime.getRuntime().availableProcessors();
        
        // 验证核心线程数
        assertEquals(processors, scanExecutor.getCorePoolSize(), 
            "SCAN_EXECUTOR 核心线程数应该等于 CPU 核心数");
        
        // 验证最大线程数
        assertEquals(processors * 2, scanExecutor.getMaximumPoolSize(), 
            "SCAN_EXECUTOR 最大线程数应该是 CPU 核心数的 2 倍");
        
        // 验证队列容量
        assertTrue(scanExecutor.getQueue().remainingCapacity() >= 1000, 
            "SCAN_EXECUTOR 队列容量应该至少是 1000");
        
        // 验证线程名称前缀
        Thread testThread = scanExecutor.getThreadFactory().newThread(() -> {});
        assertTrue(testThread.getName().startsWith("DetSql-Scan-"), 
            "SCAN_EXECUTOR 线程名称应该以 'DetSql-Scan-' 开头");
        
        // 验证是守护线程
        assertTrue(testThread.isDaemon(), 
            "SCAN_EXECUTOR 的线程应该是守护线程");
    }

    @Test
    void testKeepAliveTime() throws Exception {
        ThreadPoolExecutor receiveExecutor = getExecutor("RECEIVE_EXECUTOR");
        ThreadPoolExecutor scanExecutor = getExecutor("SCAN_EXECUTOR");
        
        // 验证空闲线程存活时间
        assertEquals(60L, receiveExecutor.getKeepAliveTime(TimeUnit.SECONDS), 
            "RECEIVE_EXECUTOR 空闲线程存活时间应该是 60 秒");
        assertEquals(60L, scanExecutor.getKeepAliveTime(TimeUnit.SECONDS), 
            "SCAN_EXECUTOR 空闲线程存活时间应该是 60 秒");
    }

    @Test
    void testRejectionPolicy() throws Exception {
        ThreadPoolExecutor receiveExecutor = getExecutor("RECEIVE_EXECUTOR");
        ThreadPoolExecutor scanExecutor = getExecutor("SCAN_EXECUTOR");
        
        // 验证拒绝策略是 CallerRunsPolicy
        assertTrue(receiveExecutor.getRejectedExecutionHandler() 
            instanceof ThreadPoolExecutor.CallerRunsPolicy,
            "RECEIVE_EXECUTOR 应该使用 CallerRunsPolicy");
        assertTrue(scanExecutor.getRejectedExecutionHandler() 
            instanceof ThreadPoolExecutor.CallerRunsPolicy,
            "SCAN_EXECUTOR 应该使用 CallerRunsPolicy");
    }

    @Test
    @Timeout(5)
    void testReceiveExecutorCanExecuteTasks() throws Exception {
        ThreadPoolExecutor receiveExecutor = getExecutor("RECEIVE_EXECUTOR");
        
        // 提交一个简单的任务
        final boolean[] taskExecuted = {false};
        receiveExecutor.execute(() -> {
            taskExecuted[0] = true;
        });
        
        // 等待任务执行
        Thread.sleep(100);
        
        assertTrue(taskExecuted[0], "RECEIVE_EXECUTOR 应该能够执行任务");
    }

    @Test
    @Timeout(5)
    void testScanExecutorCanExecuteTasks() throws Exception {
        ThreadPoolExecutor scanExecutor = getExecutor("SCAN_EXECUTOR");
        
        // 提交一个简单的任务
        final boolean[] taskExecuted = {false};
        scanExecutor.execute(() -> {
            taskExecuted[0] = true;
        });
        
        // 等待任务执行
        Thread.sleep(100);
        
        assertTrue(taskExecuted[0], "SCAN_EXECUTOR 应该能够执行任务");
    }

    @Test
    void testQueueCapacityDifference() throws Exception {
        ThreadPoolExecutor receiveExecutor = getExecutor("RECEIVE_EXECUTOR");
        ThreadPoolExecutor scanExecutor = getExecutor("SCAN_EXECUTOR");
        
        int receiveCapacity = receiveExecutor.getQueue().remainingCapacity();
        int scanCapacity = scanExecutor.getQueue().remainingCapacity();
        
        // RECEIVE_EXECUTOR 的队列应该比 SCAN_EXECUTOR 大（5000 vs 1000）
        assertTrue(receiveCapacity > scanCapacity, 
            "RECEIVE_EXECUTOR 的队列容量（5000）应该大于 SCAN_EXECUTOR（1000）");
        assertEquals(5000, receiveCapacity, "RECEIVE_EXECUTOR 队列容量应该是 5000");
        assertEquals(1000, scanCapacity, "SCAN_EXECUTOR 队列容量应该是 1000");
    }

    @Test
    void testThreadPoolSizes() throws Exception {
        ThreadPoolExecutor receiveExecutor = getExecutor("RECEIVE_EXECUTOR");
        ThreadPoolExecutor scanExecutor = getExecutor("SCAN_EXECUTOR");
        
        int processors = Runtime.getRuntime().availableProcessors();
        
        // RECEIVE_EXECUTOR 和 SCAN_EXECUTOR 现在使用相同的线程池大小
        assertEquals(processors, receiveExecutor.getCorePoolSize(), 
            "RECEIVE_EXECUTOR 核心线程数应该等于 CPU 核心数");
        assertEquals(processors * 2, receiveExecutor.getMaximumPoolSize(), 
            "RECEIVE_EXECUTOR 最大线程数应该是 CPU 核心数的 2 倍");
        
        assertEquals(processors, scanExecutor.getCorePoolSize(), 
            "SCAN_EXECUTOR 核心线程数应该等于 CPU 核心数");
        assertEquals(processors * 2, scanExecutor.getMaximumPoolSize(), 
            "SCAN_EXECUTOR 最大线程数应该是 CPU 核心数的 2 倍");
    }

    @Test
    void testThreadNaming() throws Exception {
        ThreadPoolExecutor receiveExecutor = getExecutor("RECEIVE_EXECUTOR");
        ThreadPoolExecutor scanExecutor = getExecutor("SCAN_EXECUTOR");
        
        // 创建多个线程，验证命名规则
        Thread receiveThread1 = receiveExecutor.getThreadFactory().newThread(() -> {});
        Thread receiveThread2 = receiveExecutor.getThreadFactory().newThread(() -> {});
        
        Thread scanThread1 = scanExecutor.getThreadFactory().newThread(() -> {});
        Thread scanThread2 = scanExecutor.getThreadFactory().newThread(() -> {});
        
        // 验证线程名称包含递增的计数器
        assertNotEquals(receiveThread1.getName(), receiveThread2.getName(), 
            "RECEIVE_EXECUTOR 的线程名称应该不同");
        assertNotEquals(scanThread1.getName(), scanThread2.getName(), 
            "SCAN_EXECUTOR 的线程名称应该不同");
    }

    @Test
    void testArchitectureDesignPrinciples() throws Exception {
        ThreadPoolExecutor receiveExecutor = getExecutor("RECEIVE_EXECUTOR");
        ThreadPoolExecutor scanExecutor = getExecutor("SCAN_EXECUTOR");
        
        int processors = Runtime.getRuntime().availableProcessors();
        
        // 验证设计原则：
        // 1. RECEIVE_EXECUTOR：动态线程池 + 大队列（5000）= 快速接收，避免丢失
        assertEquals(processors, receiveExecutor.getCorePoolSize(), 
            "接收队列核心线程数应该等于 CPU 核心数");
        assertEquals(5000, receiveExecutor.getQueue().remainingCapacity(), 
            "接收队列容量应该是 5000（基准）");
        
        // 2. SCAN_EXECUTOR：动态线程池 + 中等队列（1000）= 并发测试
        assertEquals(processors, scanExecutor.getCorePoolSize(), 
            "扫描队列核心线程数应该等于 CPU 核心数");
        assertEquals(1000, scanExecutor.getQueue().remainingCapacity(), 
            "扫描队列容量应该是 1000");
        
        // 3. 队列容量差异：RECEIVE > SCAN（避免丢失请求）
        assertTrue(receiveExecutor.getQueue().remainingCapacity() > 
            scanExecutor.getQueue().remainingCapacity(), 
            "接收队列容量应该大于扫描队列容量");
    }

    @Test
    @Timeout(10)
    void testConcurrentExecution() throws Exception {
        ThreadPoolExecutor receiveExecutor = getExecutor("RECEIVE_EXECUTOR");
        ThreadPoolExecutor scanExecutor = getExecutor("SCAN_EXECUTOR");
        
        // 提交多个任务到接收队列
        final int[] receiveCount = {0};
        for (int i = 0; i < 10; i++) {
            receiveExecutor.execute(() -> {
                synchronized (receiveCount) {
                    receiveCount[0]++;
                }
            });
        }
        
        // 提交多个任务到扫描队列
        final int[] scanCount = {0};
        for (int i = 0; i < 10; i++) {
            scanExecutor.execute(() -> {
                synchronized (scanCount) {
                    scanCount[0]++;
                }
            });
        }
        
        // 等待所有任务完成
        Thread.sleep(1000);
        
        assertEquals(10, receiveCount[0], "所有接收任务应该被执行");
        assertEquals(10, scanCount[0], "所有扫描任务应该被执行");
    }
}

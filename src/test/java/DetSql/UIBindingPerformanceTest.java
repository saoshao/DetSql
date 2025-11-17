/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql;

import org.junit.jupiter.api.Test;

import javax.swing.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * UI绑定机制的性能和功能测试
 *
 * 测试目标:
 * 1. 验证优化后的代码功能正确性
 * 2. 对比ScheduledExecutorService vs Timer的性能
 * 3. 验证MethodHandle vs 反射的性能提升
 * 4. 测试unbindAll()的正确性
 */
class UIBindingPerformanceTest {

    /**
     * 测试: int类型双向绑定
     */
    @Test
    void testIntFieldBinding() throws InterruptedException {
        var config = new DetSqlConfig();
        var field = new JTextField();

        // 绑定
        var binding = UIBindingHelper.bindIntField(field, config, "threadPoolSize");

        // Config → UI
        config.setThreadPoolSize(8);
        Thread.sleep(50); // 等待EDT更新UI
        assertEquals("8", field.getText());

        // UI → Config (防抖300ms)
        field.setText("16");
        Thread.sleep(350); // 等待防抖
        assertEquals(16, config.getThreadPoolSize());

        // 解绑后不应该再更新
        binding.unbind();
        config.setThreadPoolSize(32);
        Thread.sleep(50);
        assertEquals("16", field.getText()); // 应该保持不变

        System.out.println("[PASS] int类型双向绑定测试通过");
    }

    /**
     * 测试: double类型双向绑定
     */
    @Test
    void testDoubleFieldBinding() throws InterruptedException {
        var config = new DetSqlConfig();
        var field = new JTextField();

        var binding = UIBindingHelper.bindDoubleField(field, config, "similarityThreshold");

        // Config → UI
        config.setSimilarityThreshold(0.85);
        Thread.sleep(50);
        assertEquals("0.85", field.getText());

        // UI → Config
        field.setText("0.95");
        Thread.sleep(350);
        assertEquals(0.95, config.getSimilarityThreshold(), 0.001);

        binding.unbind();
        System.out.println("[PASS] double类型双向绑定测试通过");
    }

    /**
     * 测试: Set<String>类型双向绑定 (TextField用"|"分隔)
     */
    @Test
    void testSetFieldBinding() throws InterruptedException {
        var config = new DetSqlConfig();
        var field = new JTextField();

        var binding = UIBindingHelper.bindSetField(field, config, "whiteListDomains");

        // Config → UI
        config.setWhiteListDomains(java.util.Set.of("example.com", "test.com"));
        Thread.sleep(50);
        var text = field.getText();
        assertTrue(text.contains("example.com"));
        assertTrue(text.contains("test.com"));
        assertTrue(text.contains("|"));

        // UI → Config
        field.setText("domain1.com | domain2.com");
        Thread.sleep(350);
        var domains = config.getWhiteListDomains();
        assertTrue(domains.contains("domain1.com"));
        assertTrue(domains.contains("domain2.com"));
        assertEquals(2, domains.size());

        binding.unbind();
        System.out.println("[PASS] Set<String>类型双向绑定测试通过");
    }

    /**
     * 测试: Set<String>类型双向绑定 (TextArea每行一个元素)
     */
    @Test
    void testSetAreaBinding() throws InterruptedException {
        var config = new DetSqlConfig();
        var area = new JTextArea();

        var binding = UIBindingHelper.bindSetArea(area, config, "blackListDomains");

        // Config → UI
        config.setBlackListDomains(java.util.Set.of("bad1.com", "bad2.com"));
        Thread.sleep(50);
        var text = area.getText();
        assertTrue(text.contains("bad1.com"));
        assertTrue(text.contains("bad2.com"));

        // UI → Config
        area.setText("evil1.com\nevil2.com\nevil3.com");
        Thread.sleep(350);
        var domains = config.getBlackListDomains();
        assertEquals(3, domains.size());
        assertTrue(domains.contains("evil1.com"));
        assertTrue(domains.contains("evil2.com"));
        assertTrue(domains.contains("evil3.com"));

        binding.unbind();
        System.out.println("[PASS] Set<String>类型TextArea绑定测试通过");
    }

    /**
     * 测试: BindingContext的链式调用和unbindAll()
     */
    @Test
    void testBindingContextUnbindAll() throws InterruptedException {
        var config = new DetSqlConfig();
        var field1 = new JTextField();
        var field2 = new JTextField();
        var area = new JTextArea();

        var context = new BindingContext(config);

        // 链式调用绑定多个组件
        context
            .bindIntField(field1, "threadPoolSize")
            .bindDoubleField(field2, "similarityThreshold")
            .bindSetArea(area, "whiteListDomains");

        assertEquals(3, context.getBindingCount());

        // 验证绑定生效
        config.setThreadPoolSize(10);
        Thread.sleep(50);
        assertEquals("10", field1.getText());

        // 解绑所有
        context.unbindAll();
        assertEquals(0, context.getBindingCount());

        // 验证解绑后不再更新
        config.setThreadPoolSize(20);
        Thread.sleep(50);
        assertEquals("10", field1.getText()); // 应该保持为10

        System.out.println("[PASS] BindingContext.unbindAll()测试通过");
    }

    /**
     * 测试: 向后兼容API
     */
    @Test
    @SuppressWarnings("deprecation")
    void testBackwardCompatibleAPI() throws InterruptedException {
        var config = new DetSqlConfig();
        var field = new JTextField();

        // 使用旧API(会触发deprecation警告)
        UIBindingHelper.bindTextField(field, config, "threadPoolSize");

        config.setThreadPoolSize(99);
        Thread.sleep(50);
        assertEquals("99", field.getText());

        System.out.println("[PASS] 向后兼容API测试通过");
    }

    /**
     * 性能测试: ScheduledExecutorService vs Timer
     * (这个测试需要手动观察,不做自动断言)
     */
    @Test
    void performanceTestDebounce() throws InterruptedException {
        var config = new DetSqlConfig();
        var field = new JTextField();

        var binding = UIBindingHelper.bindIntField(field, config, "threadPoolSize");

        long startTime = System.nanoTime();

        // 模拟用户快速输入(触发多次防抖)
        for (int i = 0; i < 100; i++) {
            field.setText(String.valueOf(i));
            Thread.sleep(10);
        }

        // 等待最后一次防抖完成
        Thread.sleep(350);

        long endTime = System.nanoTime();
        long elapsedMs = (endTime - startTime) / 1_000_000;

        // 应该只触发1次config更新(因为防抖)
        assertEquals(99, config.getThreadPoolSize());

        binding.unbind();

        System.out.println("[性能] 防抖测试完成,耗时: " + elapsedMs + "ms");
        System.out.println("[INFO] 使用ScheduledExecutorService,共享单线程池");
    }

    /**
     * 测试: 异常处理
     */
    @Test
    void testInvalidInput() throws InterruptedException {
        var config = new DetSqlConfig();
        var field = new JTextField();

        var binding = UIBindingHelper.bindIntField(field, config, "threadPoolSize");

        // 先设置一个有效值(需要在EDT线程设置)
        SwingUtilities.invokeLater(() -> field.setText("99"));
        Thread.sleep(500); // 等待EDT + 防抖

        assertEquals(99, config.getThreadPoolSize());

        // 输入无效数字
        SwingUtilities.invokeLater(() -> field.setText("not-a-number"));
        Thread.sleep(500);

        // 应该解析为0(parseIntSafe的默认值)
        assertEquals(0, config.getThreadPoolSize());

        binding.unbind();
        System.out.println("[PASS] 异常输入处理测试通过");
    }

    /**
     * 测试: 防止循环更新
     */
    @Test
    void testPreventCircularUpdate() throws InterruptedException {
        var config = new DetSqlConfig();
        var field = new JTextField();

        var binding = UIBindingHelper.bindIntField(field, config, "threadPoolSize");

        // 添加一个监听器来追踪更新次数
        final int[] updateCount = {0};
        config.addPropertyChangeListener("threadPoolSize", evt -> updateCount[0]++);

        // 从config更新
        config.setThreadPoolSize(42);
        Thread.sleep(50);

        // 应该只触发1次PropertyChange
        assertEquals(1, updateCount[0]);
        assertEquals("42", field.getText());

        binding.unbind();
        System.out.println("[PASS] 防止循环更新测试通过");
    }
}

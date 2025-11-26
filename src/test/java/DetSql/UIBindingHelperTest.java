/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import DetSql.config.DetSqlConfig;
import DetSql.ui.UIBindingHelper;

/**
 * UI绑定机制测试
 *
 * 验证:
 * 1. TextField → Config 单向更新
 * 2. Config → TextField 单向更新
 * 3. 双向绑定不产生死循环
 * 4. TextArea → Config 单向更新
 * 5. 防抖动机制
 */
class UIBindingHelperTest {

    private DetSqlConfig config;
    private JTextField textField;
    private JTextArea textArea;

    @BeforeEach
    void setUp() {
        config = new DetSqlConfig();
        textField = new JTextField();
        textArea = new JTextArea();
    }

    @Test
    void testTextFieldToConfig() throws InterruptedException {
        // 绑定 (使用新的类型安全API)
        UIBindingHelper.bindSetField(textField, config, "whiteListDomains");

        // UI → Config
        SwingUtilities.invokeLater(() -> textField.setText("example.com|test.com"));

        // 等待防抖动定时器触发 (300ms)
        Thread.sleep(500);

        Set<String> result = config.getWhiteListDomains();
        assertTrue(result.contains("example.com"));
        assertTrue(result.contains("test.com"));
        assertEquals(2, result.size());
    }

    @Test
    void testConfigToTextField() throws Exception {
        // 绑定 (使用新的类型安全API)
        UIBindingHelper.bindSetField(textField, config, "whiteListDomains");

        // Config → UI
        Set<String> domains = new HashSet<>();
        domains.add("foo.com");
        domains.add("bar.com");
        config.setWhiteListDomains(domains);

        // 等待EDT线程更新UI
        Thread.sleep(100);
        SwingUtilities.invokeAndWait(() -> {
            String text = textField.getText();
            assertTrue(text.contains("foo.com"));
            assertTrue(text.contains("bar.com"));
        });
    }

    @Test
    void testBidirectionalBinding() throws InterruptedException {
        // 记录PropertyChange触发次数
        AtomicInteger changeCount = new AtomicInteger(0);
        config.addPropertyChangeListener("whiteListDomains", evt -> {
            changeCount.incrementAndGet();
        });

        // 绑定 (使用新的类型安全API)
        UIBindingHelper.bindSetField(textField, config, "whiteListDomains");

        // UI → Config → UI (应该只触发一次PropertyChange)
        SwingUtilities.invokeLater(() -> textField.setText("test.com"));
        Thread.sleep(500);

        // 验证没有死循环 (changeCount应该是1,而不是无限增长)
        assertTrue(changeCount.get() <= 2, "PropertyChange触发次数过多,可能存在死循环");
    }

    @Test
    void testTextAreaToConfig() throws InterruptedException {
        // 绑定 (使用新的类型安全API)
        UIBindingHelper.bindSetArea(textArea, config, "diyPayloads");

        // UI → Config (必须在EDT线程修改UI)
        SwingUtilities.invokeLater(() -> textArea.setText("payload1\npayload2\npayload3"));
        Thread.sleep(500);

        Set<String> result = config.getDiyPayloads();
        assertEquals(3, result.size());
        assertTrue(result.contains("payload1"));
        assertTrue(result.contains("payload2"));
        assertTrue(result.contains("payload3"));
    }

    @Test
    void testConfigToTextArea() throws Exception {
        // 绑定 (使用新的类型安全API)
        UIBindingHelper.bindSetArea(textArea, config, "diyPayloads");

        // Config → UI
        Set<String> payloads = new HashSet<>();
        payloads.add("payload_a");
        payloads.add("payload_b");
        config.setDiyPayloads(payloads);

        Thread.sleep(100);
        SwingUtilities.invokeAndWait(() -> {
            String text = textArea.getText();
            assertTrue(text.contains("payload_a"));
            assertTrue(text.contains("payload_b"));
        });
    }

    @Test
    void testDebounce() throws InterruptedException {
        // 记录更新次数
        AtomicInteger updateCount = new AtomicInteger(0);
        config.addPropertyChangeListener("whiteListDomains", evt -> {
            updateCount.incrementAndGet();
        });

        UIBindingHelper.bindSetField(textField, config, "whiteListDomains");

        // 模拟用户快速输入 (100ms内多次修改)
        SwingUtilities.invokeLater(() -> textField.setText("a"));
        Thread.sleep(50);
        SwingUtilities.invokeLater(() -> textField.setText("ab"));
        Thread.sleep(50);
        SwingUtilities.invokeLater(() -> textField.setText("abc"));

        // 等待防抖动定时器触发
        Thread.sleep(500);

        // 验证只触发了一次更新 (防抖动生效)
        assertTrue(updateCount.get() <= 2, "防抖动失效,更新次数: " + updateCount.get());
    }

    @Test
    void testEmptyValueHandling() throws InterruptedException {
        UIBindingHelper.bindSetField(textField, config, "whiteListDomains");

        // 测试空值
        SwingUtilities.invokeLater(() -> textField.setText(""));
        Thread.sleep(500);

        Set<String> result = config.getWhiteListDomains();
        assertTrue(result.isEmpty(), "空值应该被解析为空Set");
    }

    @Test
    void testWhitespaceHandling() throws InterruptedException {
        UIBindingHelper.bindSetField(textField, config, "whiteListDomains");

        // 测试前后空格
        SwingUtilities.invokeLater(() -> textField.setText(" example.com | test.com "));
        Thread.sleep(500);

        Set<String> result = config.getWhiteListDomains();
        assertTrue(result.contains("example.com"));
        assertTrue(result.contains("test.com"));
        assertFalse(result.contains(" example.com"), "应该自动trim空格");
    }
}

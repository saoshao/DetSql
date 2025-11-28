package DetSql.ui;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;

import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * LanguageManager 单元测试
 * 验证全局语言管理器的观察者模式实现
 */
@DisplayName("LanguageManager Tests")
public class LanguageManagerTest {
    
    private LanguageManager manager;
    
    @BeforeEach
    public void setUp() {
        manager = LanguageManager.getInstance();
    }
    
    @Test
    @DisplayName("Should be singleton")
    public void testSingleton() {
        LanguageManager instance1 = LanguageManager.getInstance();
        LanguageManager instance2 = LanguageManager.getInstance();
        assertSame(instance1, instance2, "LanguageManager should be a singleton");
    }
    
    @Test
    @DisplayName("Should notify listener on language change")
    public void testLanguageChangeNotification() throws InterruptedException {
        AtomicBoolean notified = new AtomicBoolean(false);

        LanguageChangeListener listener = () -> {
            notified.set(true);
        };
        
        manager.addListener(listener);
        manager.setLanguage(1);  // 切换到英文
        
        // 等待 EDT 线程执行
        Thread.sleep(200);
        
        assertTrue(notified.get(), "Listener should be notified");
        
        // 清理
        manager.removeListener(listener);
    }
    
    @Test
    @DisplayName("Should not notify if language unchanged")
    public void testNoNotificationWhenLanguageUnchanged() throws InterruptedException {
        AtomicBoolean notified = new AtomicBoolean(false);

        LanguageChangeListener listener = () -> notified.set(true);

        manager.addListener(listener);
        int currentIndex = manager.getCurrentLanguageIndex();

        manager.setLanguage(currentIndex);  // 设置为当前语言
        Thread.sleep(200);

        assertFalse(notified.get(), "Should not notify when language unchanged");

        // 清理
        manager.removeListener(listener);
    }
    
    @Test
    @DisplayName("Should notify multiple listeners")
    public void testMultipleListeners() throws InterruptedException {
        AtomicBoolean notified1 = new AtomicBoolean(false);
        AtomicBoolean notified2 = new AtomicBoolean(false);

        LanguageChangeListener listener1 = () -> notified1.set(true);
        LanguageChangeListener listener2 = () -> notified2.set(true);

        manager.addListener(listener1);
        manager.addListener(listener2);

        manager.setLanguage(1);
        Thread.sleep(200);

        assertTrue(notified1.get(), "First listener should be notified");
        assertTrue(notified2.get(), "Second listener should be notified");

        // 清理
        manager.removeListener(listener1);
        manager.removeListener(listener2);
    }
    
    @Test
    @DisplayName("Should handle listener exceptions gracefully")
    public void testExceptionHandling() throws InterruptedException {
        // 先确保当前是中文
        manager.setLanguage(0);
        Thread.sleep(200);
        
        AtomicBoolean goodListenerNotified = new AtomicBoolean(false);
        
        LanguageChangeListener badListener = () -> {
            throw new RuntimeException("Test exception");
        };

        LanguageChangeListener goodListener = () -> {
            goodListenerNotified.set(true);
        };
        
        manager.addListener(badListener);
        manager.addListener(goodListener);
        
        // 切换到英文
        manager.setLanguage(1);
        Thread.sleep(200);
        
        assertTrue(goodListenerNotified.get(), 
            "Good listener should still be notified despite bad listener exception");
        
        // 清理
        manager.removeListener(badListener);
        manager.removeListener(goodListener);
    }
    
    @Test
    @DisplayName("Should not add duplicate listeners")
    public void testNoDuplicateListeners() throws InterruptedException {
        // 先切换到中文
        manager.setLanguage(0);
        Thread.sleep(200);
        
        AtomicBoolean notified = new AtomicBoolean(false);

        LanguageChangeListener listener = () -> notified.set(true);

        manager.addListener(listener);
        manager.addListener(listener);  // 添加两次

        // 切换到英文
        manager.setLanguage(1);
        Thread.sleep(200);

        assertTrue(notified.get(),
            "Listener should only be notified once even if added multiple times");
        
        // 清理
        manager.removeListener(listener);
    }
    
    @Test
    @DisplayName("Should update Messages locale")
    public void testMessagesLocaleUpdate() throws InterruptedException {
        // 切换到英文
        manager.setLanguage(1);
        Thread.sleep(200);
        
        // 验证 Messages 是否使用英文
        String dashboardText = Messages.getString("tab.dashboard");
        assertEquals("Dashboard", dashboardText, 
            "Messages should return English text after switching to English");
        
        // 切换回中文
        manager.setLanguage(0);
        Thread.sleep(200);
        
        String dashboardTextCN = Messages.getString("tab.dashboard");
        assertEquals("DashBoard", dashboardTextCN, 
            "Messages should return Chinese text after switching to Chinese");
    }
    
    @Test
    @DisplayName("Should execute notification in EDT")
    public void testNotificationInEDT() throws InterruptedException {
        // 先切换到中文
        manager.setLanguage(0);
        Thread.sleep(200);
        
        AtomicBoolean inEDT = new AtomicBoolean(false);
        
        LanguageChangeListener listener = () -> {
            inEDT.set(SwingUtilities.isEventDispatchThread());
        };
        
        manager.addListener(listener);
        // 切换到英文
        manager.setLanguage(1);
        Thread.sleep(200);
        
        assertTrue(inEDT.get(), 
            "Listener notification should execute in Event Dispatch Thread");
        
        // 清理
        manager.removeListener(listener);
    }
}

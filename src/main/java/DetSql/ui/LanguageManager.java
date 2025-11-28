package DetSql.ui;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 全局语言管理器 (单例模式)
 * 负责管理语言变更事件的订阅和通知
 * 
 * 特性:
 * - 线程安全的观察者模式实现
 * - 自动在 EDT 线程中通知监听器
 * - 防止单个监听器异常影响其他监听器
 * - 与 Messages 类集成,自动更新 ResourceBundle
 * 
 * 使用示例:
 * <pre>
 * // 注册监听器
 * LanguageManager.getInstance().addListener(myPanel);
 * 
 * // 切换语言
 * LanguageManager.getInstance().setLanguage(1); // 切换到英文
 * </pre>
 * 
 * @author DetSql Team
 * @version 3.3.0
 */
public class LanguageManager {
    private static final LanguageManager INSTANCE = new LanguageManager();
    
    private final List<LanguageChangeListener> listeners = new ArrayList<>();
    private int currentLanguageIndex = 0;  // 默认简体中文
    
    /**
     * 私有构造函数 (单例模式)
     */
    private LanguageManager() {}
    
    /**
     * 获取单例实例
     */
    public static LanguageManager getInstance() {
        return INSTANCE;
    }
    
    /**
     * 注册语言变更监听器
     * 
     * @param listener 监听器实例
     */
    public synchronized void addListener(LanguageChangeListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }
    
    /**
     * 移除监听器
     * 
     * @param listener 监听器实例
     */
    public synchronized void removeListener(LanguageChangeListener listener) {
        listeners.remove(listener);
    }
    
    /**
     * 切换语言
     * 
     * @param languageIndex 语言索引 (0=简体中文, 1=English)
     */
    public void setLanguage(int languageIndex) {
        if (this.currentLanguageIndex == languageIndex) {
            return;  // 语言未变化,无需通知
        }
        
        this.currentLanguageIndex = languageIndex;
        
        // 更新 Messages 的 Locale
        Locale locale = (languageIndex == 0) ? 
            Locale.SIMPLIFIED_CHINESE : Locale.ENGLISH;
        Messages.setLocale(locale);
        
        // 在 EDT 线程中通知所有监听器
        SwingUtilities.invokeLater(() -> {
            // 创建副本避免并发修改异常
            List<LanguageChangeListener> listenersCopy;
            synchronized (this) {
                listenersCopy = new ArrayList<>(listeners);
            }
            
            for (LanguageChangeListener listener : listenersCopy) {
                try {
                    listener.onLanguageChanged();
                } catch (Exception e) {
                    // 防止单个监听器异常影响其他监听器
                    System.err.println("Error notifying language change listener: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        });
    }
    
    /**
     * 获取当前语言索引
     * 
     * @return 语言索引 (0=简体中文, 1=English)
     */
    public int getCurrentLanguageIndex() {
        return currentLanguageIndex;
    }
    
    /**
     * 获取当前监听器数量 (用于测试)
     * 
     * @return 监听器数量
     */
    synchronized int getListenerCount() {
        return listeners.size();
    }
}

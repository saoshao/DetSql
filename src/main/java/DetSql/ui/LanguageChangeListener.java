package DetSql.ui;

/**
 * 语言变更监听器接口
 * 所有需要响应语言切换的 UI 组件应实现此接口
 *
 * 使用示例:
 * <pre>
 * public class MyPanel extends JPanel implements LanguageChangeListener {
 *     public MyPanel() {
 *         LanguageManager.getInstance().addListener(this);
 *     }
 *
 *     {@literal @}Override
 *     public void onLanguageChanged() {
 *         // 使用 Messages.getString() 获取本地化文本
 *         updateLabels();
 *     }
 * }
 * </pre>
 *
 * @author DetSql Team
 * @version 3.3.0
 */
public interface LanguageChangeListener {
    /**
     * 当语言设置改变时调用
     * 监听器应通过 Messages.getString() 获取本地化文本
     */
    void onLanguageChanged();
}

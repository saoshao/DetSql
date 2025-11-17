/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 绑定上下文管理器 - 管理UI与DetSqlConfig的所有绑定关系 (Linus风格重构版)
 *
 * 职责:
 * 1. 统一管理所有UI绑定
 * 2. 提供真正有效的解绑功能
 * 3. 支持链式调用
 *
 * 优化要点:
 * - 修复了原unbindAll()不工作的问题(listeners列表实际上是空的)
 * - 现在追踪所有Binding对象,可以真正解绑
 * - 支持链式调用,提高代码可读性
 */
public class BindingContext {

    private final DetSqlConfig config;
    private final List<UIBindingHelper.Binding<?>> bindings = new ArrayList<>();

    /**
     * 创建绑定上下文
     * @param config 配置对象
     */
    public BindingContext(DetSqlConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("config不能为null");
        }
        this.config = config;
    }

    /**
     * 绑定JTextField到int属性
     *
     * @param field UI组件
     * @param propertyName 属性名
     * @return this (链式调用)
     */
    public BindingContext bindIntField(JTextField field, String propertyName) {
        var binding = UIBindingHelper.bindIntField(field, config, propertyName);
        bindings.add(binding);
        return this;
    }

    /**
     * 绑定JTextField到double属性
     */
    public BindingContext bindDoubleField(JTextField field, String propertyName) {
        var binding = UIBindingHelper.bindDoubleField(field, config, propertyName);
        bindings.add(binding);
        return this;
    }

    /**
     * 绑定JTextField到String属性
     */
    public BindingContext bindStringField(JTextField field, String propertyName) {
        var binding = UIBindingHelper.bindStringField(field, config, propertyName);
        bindings.add(binding);
        return this;
    }

    /**
     * 绑定JTextField到Set<String>属性 (用"|"分隔)
     */
    public BindingContext bindSetField(JTextField field, String propertyName) {
        var binding = UIBindingHelper.bindSetField(field, config, propertyName);
        bindings.add(binding);
        return this;
    }

    /**
     * 绑定JTextArea到Set<String>属性 (每行一个元素)
     */
    public BindingContext bindSetArea(JTextArea area, String propertyName) {
        var binding = UIBindingHelper.bindSetArea(area, config, propertyName);
        bindings.add(binding);
        return this;
    }

    /**
     * 向后兼容API - 自动检测属性类型并绑定
     * (推荐使用类型安全的 bindIntField/bindDoubleField 等方法)
     *
     * @param field UI组件
     * @param propertyName 属性名
     * @return this (链式调用)
     */
    @Deprecated
    public BindingContext bindTextField(JTextField field, String propertyName) {
        UIBindingHelper.bindTextField(field, config, propertyName);
        return this;
    }

    /**
     * 向后兼容API - 绑定TextArea到Set<String>
     */
    @Deprecated
    public BindingContext bindTextArea(JTextArea area, String propertyName) {
        UIBindingHelper.bindTextArea(area, config, propertyName);
        return this;
    }

    /**
     * 解除所有绑定
     *
     * 调用所有Binding.unbind()来:
     * - 移除DocumentListener
     * - 移除PropertyChangeListener
     * - 取消待处理的防抖任务
     */
    public void unbindAll() {
        for (var binding : bindings) {
            binding.unbind();
        }
        bindings.clear();
    }

    /**
     * 获取配置对象
     */
    public DetSqlConfig getConfig() {
        return config;
    }

    /**
     * 获取当前绑定数量
     */
    public int getBindingCount() {
        return bindings.size();
    }
}

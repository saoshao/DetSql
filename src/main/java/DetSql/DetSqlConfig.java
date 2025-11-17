/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * 统一配置管理类 - 集中管理所有DetSql配置项
 *
 * 设计原则:
 * - 所有配置项集中在此类中,消除分散的静态变量
 * - 默认值在字段初始化时定义,无需空值检查
 * - 提供 load/save 方法持久化配置到文件
 * - 通过 Getter/Setter 访问配置项
 * - 支持PropertyChangeListener实现UI双向绑定
 */
public class DetSqlConfig {

    // PropertyChange支持 - 用于UI绑定
    private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);

    /**
     * 辅助方法: 设置属性并触发PropertyChange事件
     *
     * 用途: 消除setter中的重复代码
     * 优化: 从3行代码减少到1行方法调用
     *
     * @param propertyName 属性名
     * @param oldValue 旧值
     * @param newValue 新值
     */
    protected <T> void fireChange(String propertyName, T oldValue, T newValue) {
        pcs.firePropertyChange(propertyName, oldValue, newValue);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 检测阈值配置
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * 相似度判定阈值 (0.0-1.0)
     * 高于此值认为相似,低于此值认为不相似
     */
    private double similarityThreshold = 0.9;

    /**
     * 最大响应体大小 (字节)
     * 超过此大小的响应不进行检测
     */
    private int maxResponseSize = 50000;

    /**
     * 长度差异阈值 (字节)
     * 响应体长度差异超过此值直接判定为不相似
     */
    private int lengthDiffThreshold = 100;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 性能配置
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * 主线程池大小 (小响应体)
     */
    private int threadPoolSize = 4;

    /**
     * 辅助线程池大小 (大响应体)
     */
    private int threadPoolSize2 = 1;

    /**
     * 响应延迟阈值 (毫秒)
     * 用于time-based检测
     */
    private int delayTimeMs = 0;

    /**
     * 请求间固定延迟 (毫秒)
     */
    private int staticTimeMs = 100;

    /**
     * 请求间随机延迟起始值 (毫秒)
     */
    private int startTimeMs = 0;

    /**
     * 请求间随机延迟结束值 (毫秒)
     */
    private int endTimeMs = 0;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 过滤配置
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * 域名白名单 (仅测试这些域名)
     */
    private Set<String> whiteListDomains = new HashSet<>();

    /**
     * 域名黑名单 (不测试这些域名)
     */
    private Set<String> blackListDomains = new HashSet<>();

    /**
     * 参数黑名单 (不测试这些参数)
     */
    private Set<String> blackListParams = new HashSet<>();

    /**
     * 路径黑名单 (不测试这些路径)
     */
    private Set<String> blackListPaths = new HashSet<>();

    /**
     * 禁止的文件后缀 (静态资源过滤)
     */
    private Set<String> unLegalExtensions = new HashSet<>(DefaultConfig.DEFAULT_SUFFIX_SET);

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Payload配置
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * 报错注入Payload列表 (用于URL/BODY/COOKIE参数)
     */
    private String[] errorPayloads = DefaultConfig.DEFAULT_ERR_POCS.clone();

    /**
     * 报错注入Payload列表 (用于JSON/XML参数,包含转义变体)
     */
    private String[] errorPayloadsJson = DefaultConfig.DEFAULT_ERR_POCS_JSON.clone();

    /**
     * 自定义DIY Payload集合
     */
    private Set<String> diyPayloads = new HashSet<>();

    /**
     * 自定义响应匹配正则表达式集合
     */
    private Set<String> diyRegexs = new HashSet<>();

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 持久化方法
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * 从文件加载配置
     *
     * @param configPath 配置文件路径 (如 ~/DetSqlConfig.txt)
     * @throws IOException 文件读取失败
     */
    public void load(String configPath) throws IOException {
        File configFile = new File(configPath);
        if (!configFile.exists()) {
            return; // 文件不存在,使用默认值
        }

        Properties prop = new Properties();
        try (InputStreamReader reader = new InputStreamReader(
                new FileInputStream(configFile), StandardCharsets.UTF_8)) {
            prop.load(reader);
        }

        // 加载检测阈值配置
        this.similarityThreshold = parseDoubleWithDefault(
            prop.getProperty("similarityThreshold"), 0.9);
        this.maxResponseSize = parseIntWithDefault(
            prop.getProperty("maxResponseSize"), 50000);
        this.lengthDiffThreshold = parseIntWithDefault(
            prop.getProperty("lengthDiffThreshold"), 100);

        // 加载性能配置
        this.threadPoolSize = parseIntWithDefault(
            prop.getProperty("threadPoolSize"), 4);
        this.threadPoolSize2 = parseIntWithDefault(
            prop.getProperty("threadPoolSize2"), 1);
        this.delayTimeMs = parseIntWithDefault(
            prop.getProperty("delaytime"), 0);
        this.staticTimeMs = parseIntWithDefault(
            prop.getProperty("statictime"), 100);
        this.startTimeMs = parseIntWithDefault(
            prop.getProperty("starttime"), 0);
        this.endTimeMs = parseIntWithDefault(
            prop.getProperty("endtime"), 0);

        // 加载过滤配置
        this.whiteListDomains = parseSetProperty(
            prop, "whitelist", new HashSet<>());
        this.blackListDomains = parseSetProperty(
            prop, "blacklist", new HashSet<>());
        this.blackListParams = parseSetProperty(
            prop, "paramslist", new HashSet<>());
        this.blackListPaths = parseSetProperty(
            prop, "blackpath", new HashSet<>());

        // 后缀列表特殊处理:为空时使用默认值
        String suffixProp = prop.getProperty("suffixlist", "").trim();
        if (suffixProp.isEmpty()) {
            this.unLegalExtensions = new HashSet<>(DefaultConfig.DEFAULT_SUFFIX_SET);
        } else {
            this.unLegalExtensions = new HashSet<>(Arrays.asList(suffixProp.split("\\|")));
        }

        // 加载Payload配置
        String errPocList = prop.getProperty("errpoclist", "").trim();
        if (errPocList.isEmpty()) {
            this.errorPayloads = DefaultConfig.DEFAULT_ERR_POCS.clone();
            this.errorPayloadsJson = DefaultConfig.DEFAULT_ERR_POCS_JSON.clone();
        } else {
            this.errorPayloads = errPocList.split("\\|");
            this.errorPayloadsJson = deriveJsonErrPocs(this.errorPayloads);
        }

        this.diyPayloads = parseSetProperty(
            prop, "diypayloads", new HashSet<>());
        this.diyRegexs = parseSetProperty(
            prop, "diyregex", new HashSet<>());
    }

    /**
     * 保存配置到文件
     *
     * @param configPath 配置文件路径
     * @throws IOException 文件写入失败
     */
    public void save(String configPath) throws IOException {
        Properties prop = new Properties();

        // 检测阈值配置
        prop.setProperty("similarityThreshold", String.valueOf(similarityThreshold));
        prop.setProperty("maxResponseSize", String.valueOf(maxResponseSize));
        prop.setProperty("lengthDiffThreshold", String.valueOf(lengthDiffThreshold));

        // 性能配置
        prop.setProperty("threadPoolSize", String.valueOf(threadPoolSize));
        prop.setProperty("threadPoolSize2", String.valueOf(threadPoolSize2));
        prop.setProperty("delaytime", String.valueOf(delayTimeMs));
        prop.setProperty("statictime", String.valueOf(staticTimeMs));
        prop.setProperty("starttime", String.valueOf(startTimeMs));
        prop.setProperty("endtime", String.valueOf(endTimeMs));

        // 过滤配置
        prop.setProperty("whitelist", String.join("|", whiteListDomains));
        prop.setProperty("blacklist", String.join("|", blackListDomains));
        prop.setProperty("paramslist", String.join("|", blackListParams));
        prop.setProperty("blackpath", String.join("|", blackListPaths));
        prop.setProperty("suffixlist", String.join("|", unLegalExtensions));

        // Payload配置
        prop.setProperty("errpoclist", String.join("|", errorPayloads));
        prop.setProperty("diypayloads", String.join("\n", diyPayloads));
        prop.setProperty("diyregex", String.join("\n", diyRegexs));

        try (OutputStreamWriter writer = new OutputStreamWriter(
                new FileOutputStream(configPath), StandardCharsets.UTF_8)) {
            prop.store(writer, "DetSql Configuration");
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 私有辅助方法
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * 解析整数配置,失败时返回默认值
     */
    private int parseIntWithDefault(String value, int defaultValue) {
        if (value == null || value.trim().isEmpty()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * 解析浮点数配置,失败时返回默认值
     */
    private double parseDoubleWithDefault(String value, double defaultValue) {
        if (value == null || value.trim().isEmpty()) {
            return defaultValue;
        }
        try {
            return Double.parseDouble(value.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * 解析Set配置 (用"|"分隔的字符串)
     */
    private Set<String> parseSetProperty(Properties prop, String key, Set<String> defaultValue) {
        String value = prop.getProperty(key, "");
        if (value.trim().isEmpty()) {
            return defaultValue;
        }
        return new HashSet<>(Arrays.asList(value.split("\\|")));
    }

    /**
     * 从基础payload派生JSON安全变体
     * (复制自 DetSql.deriveJsonErrPocs)
     */
    private static String[] deriveJsonErrPocs(String[] base) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String s : base) {
            if (s == null) continue;

            out.add(s);

            if (s.contains("\"")) {
                out.add(s.replace("\"", "\\\""));
            }

            if (s.contains("\"")) {
                out.add(s.replace("\"", "\\u0022"));
            }
            if (s.contains("'")) {
                out.add(s.replace("'", "\\u0027"));
            }
        }
        return out.toArray(new String[0]);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Getter/Setter 方法
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    public double getSimilarityThreshold() {
        return similarityThreshold;
    }

    public void setSimilarityThreshold(double similarityThreshold) {
        var old = this.similarityThreshold;
        this.similarityThreshold = similarityThreshold;
        fireChange("similarityThreshold", old, similarityThreshold);
    }

    public int getMaxResponseSize() {
        return maxResponseSize;
    }

    public void setMaxResponseSize(int maxResponseSize) {
        var old = this.maxResponseSize;
        this.maxResponseSize = maxResponseSize;
        fireChange("maxResponseSize", old, maxResponseSize);
    }

    public int getLengthDiffThreshold() {
        return lengthDiffThreshold;
    }

    public void setLengthDiffThreshold(int lengthDiffThreshold) {
        var old = this.lengthDiffThreshold;
        this.lengthDiffThreshold = lengthDiffThreshold;
        fireChange("lengthDiffThreshold", old, lengthDiffThreshold);
    }

    public int getThreadPoolSize() {
        return threadPoolSize;
    }

    public void setThreadPoolSize(int threadPoolSize) {
        var old = this.threadPoolSize;
        this.threadPoolSize = threadPoolSize;
        fireChange("threadPoolSize", old, threadPoolSize);
    }

    public int getThreadPoolSize2() {
        return threadPoolSize2;
    }

    public void setThreadPoolSize2(int threadPoolSize2) {
        var old = this.threadPoolSize2;
        this.threadPoolSize2 = threadPoolSize2;
        fireChange("threadPoolSize2", old, threadPoolSize2);
    }

    public int getDelayTimeMs() {
        return delayTimeMs;
    }

    public void setDelayTimeMs(int delayTimeMs) {
        var old = this.delayTimeMs;
        this.delayTimeMs = delayTimeMs;
        fireChange("delayTimeMs", old, delayTimeMs);
    }

    public int getStaticTimeMs() {
        return staticTimeMs;
    }

    public void setStaticTimeMs(int staticTimeMs) {
        var old = this.staticTimeMs;
        this.staticTimeMs = staticTimeMs;
        fireChange("staticTimeMs", old, staticTimeMs);
    }

    public int getStartTimeMs() {
        return startTimeMs;
    }

    public void setStartTimeMs(int startTimeMs) {
        var old = this.startTimeMs;
        this.startTimeMs = startTimeMs;
        fireChange("startTimeMs", old, startTimeMs);
    }

    public int getEndTimeMs() {
        return endTimeMs;
    }

    public void setEndTimeMs(int endTimeMs) {
        var old = this.endTimeMs;
        this.endTimeMs = endTimeMs;
        fireChange("endTimeMs", old, endTimeMs);
    }

    public Set<String> getWhiteListDomains() {
        return whiteListDomains;
    }

    public void setWhiteListDomains(Set<String> whiteListDomains) {
        var old = this.whiteListDomains;
        this.whiteListDomains = whiteListDomains;
        fireChange("whiteListDomains", old, whiteListDomains);
    }

    public Set<String> getBlackListDomains() {
        return blackListDomains;
    }

    public void setBlackListDomains(Set<String> blackListDomains) {
        var old = this.blackListDomains;
        this.blackListDomains = blackListDomains;
        fireChange("blackListDomains", old, blackListDomains);
    }

    public Set<String> getBlackListParams() {
        return blackListParams;
    }

    public void setBlackListParams(Set<String> blackListParams) {
        var old = this.blackListParams;
        this.blackListParams = blackListParams;
        fireChange("blackListParams", old, blackListParams);
    }

    public Set<String> getBlackListPaths() {
        return blackListPaths;
    }

    public void setBlackListPaths(Set<String> blackListPaths) {
        var old = this.blackListPaths;
        this.blackListPaths = blackListPaths;
        fireChange("blackListPaths", old, blackListPaths);
    }

    public Set<String> getUnLegalExtensions() {
        return unLegalExtensions;
    }

    public void setUnLegalExtensions(Set<String> unLegalExtensions) {
        var old = this.unLegalExtensions;
        this.unLegalExtensions = unLegalExtensions;
        fireChange("unLegalExtensions", old, unLegalExtensions);
    }

    public String[] getErrorPayloads() {
        return errorPayloads;
    }

    public void setErrorPayloads(String[] errorPayloads) {
        var old = this.errorPayloads;
        this.errorPayloads = errorPayloads;
        fireChange("errorPayloads", old, errorPayloads);
    }

    public String[] getErrorPayloadsJson() {
        return errorPayloadsJson;
    }

    public void setErrorPayloadsJson(String[] errorPayloadsJson) {
        var old = this.errorPayloadsJson;
        this.errorPayloadsJson = errorPayloadsJson;
        fireChange("errorPayloadsJson", old, errorPayloadsJson);
    }

    public Set<String> getDiyPayloads() {
        return Collections.unmodifiableSet(diyPayloads);
    }

    public void setDiyPayloads(Set<String> diyPayloads) {
        var old = this.diyPayloads;
        this.diyPayloads = diyPayloads;
        fireChange("diyPayloads", old, diyPayloads);
    }

    public Set<String> getDiyRegexs() {
        return Collections.unmodifiableSet(diyRegexs);
    }

    public void setDiyRegexs(Set<String> diyRegexs) {
        var old = this.diyRegexs;
        this.diyRegexs = diyRegexs;
        fireChange("diyRegexs", old, diyRegexs);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 属性变化监听器管理（Java Beans标准）
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * 添加属性变化监听器（底层PropertyChangeListener）
     *
     * 直接使用Java Beans标准PropertyChangeListener，适用于与Swing/JavaFX绑定。
     *
     * @param listener PropertyChangeListener
     */
    public void addPropertyChangeListener(PropertyChangeListener listener) {
        pcs.addPropertyChangeListener(listener);
    }

    /**
     * 添加特定属性的PropertyChangeListener
     *
     * @param propertyName 属性名称
     * @param listener PropertyChangeListener
     */
    public void addPropertyChangeListener(String propertyName, PropertyChangeListener listener) {
        pcs.addPropertyChangeListener(propertyName, listener);
    }

    /**
     * 移除属性变化监听器
     */
    public void removePropertyChangeListener(PropertyChangeListener listener) {
        pcs.removePropertyChangeListener(listener);
    }

    /**
     * 移除特定属性的监听器
     */
    public void removePropertyChangeListener(String propertyName, PropertyChangeListener listener) {
        pcs.removePropertyChangeListener(propertyName, listener);
    }
}

/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql.config;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 配置管理器
 * 负责加载和保存 YAML 配置文件
 */
public class ConfigManager {
    private static final String CONFIG_DIR_NAME = ".config/DetSql";
    private static final String CONFIG_FILE_NAME = "config.yaml";

    private final Path configPath;

    public ConfigManager() {
        String userHome = System.getProperty("user.home");
        Path configDir = Paths.get(userHome, CONFIG_DIR_NAME);
        this.configPath = configDir.resolve(CONFIG_FILE_NAME);

        // 确保配置目录存在
        try {
            Files.createDirectories(configDir);
        } catch (IOException e) {
            System.err.println("无法创建配置目录: " + e.getMessage());
        }
    }

    /**
     * 加载配置文件
     * 如果 YAML 文件不存在,尝试迁移老的 Properties 文件
     * 如果都不存在,返回默认配置
     */
    public DetSqlYamlConfig loadConfig() {
        Path configFile = getConfigPath();

        // 1. 优先加载 YAML 配置
        if (Files.exists(configFile)) {
            DetSqlYamlConfig config = loadYamlConfig(configFile);
            // 与默认配置合并,确保新字段有默认值
            return mergeWithDefaults(config);
        }

        // 2. 尝试迁移老配置文件
        Path legacyConfigPath = Paths.get(System.getProperty("user.home"), "DetSqlConfig.txt");
        if (Files.exists(legacyConfigPath)) {
            System.out.println("检测到老配置文件,开始自动迁移: " + legacyConfigPath);
            DetSqlYamlConfig config = migrateLegacyConfig(legacyConfigPath);
            if (config != null) {
                // 迁移成功后先与默认配置合并(修正无效值),再保存为 YAML 并删除老文件
                config = mergeWithDefaults(config);
                try {
                    saveConfig(config);
                    Files.delete(legacyConfigPath);
                    System.out.println("配置迁移成功,老配置文件已删除");
                } catch (Exception e) {
                    System.err.println("保存迁移后的配置失败: " + e.getMessage());
                }
                return config;
            }
        }

        // 3. 返回默认配置
        return createDefaultConfig();
    }

    /**
     * 重新加载配置文件
     * 直接从文件加载,不做任何重置,确保用户配置不丢失
     */
    public DetSqlYamlConfig reloadConfig() {
        return loadConfig();
    }

    /**
     * 从指定路径加载配置文件
     * 用于 UI 的"载入"功能,允许用户从任意位置加载配置
     *
     * @param configFile 配置文件路径
     * @return 加载的配置对象,如果加载失败则返回 null
     */
    public DetSqlYamlConfig loadConfigFromFile(Path configFile) {
        if (!Files.exists(configFile)) {
            System.err.println("配置文件不存在: " + configFile);
            return null;
        }

        DetSqlYamlConfig config = loadYamlConfig(configFile);
        if (config != null) {
            // 与默认配置合并,确保新字段有默认值
            return mergeWithDefaults(config);
        }
        return null;
    }

    /**
     * 将加载的配置与默认配置合并
     * 确保所有字段都有值,新增字段使用默认值
     */
    private DetSqlYamlConfig mergeWithDefaults(DetSqlYamlConfig config) {
        if (config == null) {
            return createDefaultConfig();
        }

        DetSqlYamlConfig defaults = createDefaultConfig();

        // 修正无效的时间配置 - 如果为负数,使用默认值
        // 注意: delaytime 允许为 0 (表示无延迟)
        if (config.getDelaytime() < 0) {
            System.err.println("警告: 延迟时间为负数,使用默认值: " + defaults.getDelaytime());
            config.setDelaytime(defaults.getDelaytime());
        }
        if (config.getStatictime() < 0) {
            System.err.println("警告: 固定间隔为负数,使用默认值: " + defaults.getStatictime());
            config.setStatictime(defaults.getStatictime());
        }
        if (config.getStarttime() < 0) {
            System.err.println("警告: 开始时间为负数,使用默认值: " + defaults.getStarttime());
            config.setStarttime(defaults.getStarttime());
        }
        if (config.getEndtime() < 0) {
            System.err.println("警告: 结束时间为负数,使用默认值: " + defaults.getEndtime());
            config.setEndtime(defaults.getEndtime());
        }

        // 修正无效的语言索引
        if (config.getLanguageindex() < 0 || config.getLanguageindex() > 1) {
            System.err.println("警告: 语言索引无效,使用默认值 0: " + config.getLanguageindex());
            config.setLanguageindex(0);
        }

        // DetSqlYamlConfig 的所有列表和字符串字段都有默认值 (new ArrayList<>(), "")
        // 不需要 null 检查,SnakeYAML 会自动使用字段的默认值

        return config;
    }

    /**
     * 加载 YAML 配置文件
     */
    private DetSqlYamlConfig loadYamlConfig(Path configFile) {
        try (InputStream input = Files.newInputStream(configFile);
                InputStreamReader reader = new InputStreamReader(input, StandardCharsets.UTF_8)) {
            // 使用受限的 Constructor 防止反序列化 RCE 漏洞
            // 只允许反序列化 DetSqlYamlConfig 类,阻止恶意 Gadget 执行
            LoaderOptions loaderOptions = new LoaderOptions();
            Constructor constructor = new Constructor(DetSqlYamlConfig.class, loaderOptions);
            Yaml yaml = new Yaml(constructor);
            DetSqlYamlConfig config = yaml.loadAs(reader, DetSqlYamlConfig.class);

            if (config == null) {
                System.err.println("警告: 配置文件解析结果为 null,使用默认配置");
                return createDefaultConfig();
            }

            // 验证配置
            ConfigValidator.ValidationResult validation = ConfigValidator.validate(config);
            if (!validation.isValid()) {
                System.err.println("警告: 配置文件包含无效值: " + validation.getErrorMessage());
                System.err.println("将使用默认值修正无效配置项");
                // 继续使用配置,mergeWithDefaults 会修正无效值
            }

            return config;
        } catch (Exception e) {
            System.err.println("加载 YAML 配置文件失败: " + configFile);
            System.err.println("错误详情: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.err.println("将使用默认配置");
            return createDefaultConfig();
        }
    }

    /**
     * 迁移老的 Properties 配置文件到 YAML 格式
     */
    private DetSqlYamlConfig migrateLegacyConfig(Path legacyPath) {
        try (InputStream input = Files.newInputStream(legacyPath);
                InputStreamReader reader = new InputStreamReader(input, StandardCharsets.UTF_8)) {
            Properties prop = new Properties();
            prop.load(reader);

            DetSqlYamlConfig config = new DetSqlYamlConfig();

            // 迁移域名过滤配置
            config.setWhitelist(splitToList(prop.getProperty("whitelist", ""), "\\|"));
            config.setBlacklist(splitToList(prop.getProperty("blacklist", ""), "\\|"));
            config.setSuffixlist(splitToList(prop.getProperty("suffixlist", ""), "\\|"));
            config.setParamslist(splitToList(prop.getProperty("paramslist", ""), "\\|"));

            // 迁移路径黑名单
            config.setBlackpath(prop.getProperty("blackpath", "").replace("\\n", "\n"));

            // 迁移 Payload 配置
            config.setErrpoclist(splitToList(prop.getProperty("errpoclist", ""), "\\|"));
            config.setDiypayloads(prop.getProperty("diypayloads", "").replace("\\n", "\n"));
            config.setDiyregex(prop.getProperty("diyregex", "").replace("\\n", "\n"));

            // 迁移时间配置
            config.setDelaytime(parseIntWithDefault(prop.getProperty("delaytime"), 500));
            config.setStatictime(parseIntWithDefault(prop.getProperty("statictime"), 2000));
            config.setStarttime(parseIntWithDefault(prop.getProperty("starttime"), 2000));
            config.setEndtime(parseIntWithDefault(prop.getProperty("endtime"), 6000));

            // 迁移检测开关配置
            config.setSwitchEnabled(parseBoolWithDefault(prop.getProperty("switch"), true));
            config.setCookiecheck(parseBoolWithDefault(prop.getProperty("cookiecheck"), false));
            config.setErrorcheck(parseBoolWithDefault(prop.getProperty("errorcheck"), true));
            config.setNumcheck(parseBoolWithDefault(prop.getProperty("numcheck"), true));
            config.setStringcheck(parseBoolWithDefault(prop.getProperty("stringcheck"), true));
            config.setOrdercheck(parseBoolWithDefault(prop.getProperty("ordercheck"), true));
            config.setRepeatercheck(parseBoolWithDefault(prop.getProperty("repeatercheck"), false));
            config.setBoolcheck(parseBoolWithDefault(prop.getProperty("boolcheck"), true));
            config.setDiycheck(parseBoolWithDefault(prop.getProperty("diycheck"), false));

            // 迁移语言配置
            config.setLanguageindex(parseIntWithDefault(prop.getProperty("languageindex"), 0));

            return config;
        } catch (Exception e) {
            System.err.println("迁移老配置文件失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 分割字符串为列表
     */
    private List<String> splitToList(String value, String delimiter) {
        if (value == null || value.trim().isEmpty()) {
            return new ArrayList<>();
        }
        return Arrays.asList(value.split(delimiter));
    }

    /**
     * 解析整数,失败时返回默认值
     */
    private int parseIntWithDefault(String value, int defaultValue) {
        try {
            return value != null ? Integer.parseInt(value.trim()) : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * 解析布尔值,失败时返回默认值
     */
    private boolean parseBoolWithDefault(String value, boolean defaultValue) {
        return value != null ? Boolean.parseBoolean(value.trim()) : defaultValue;
    }

    /**
     * 保存配置文件
     */
    public void saveConfig(DetSqlYamlConfig config) throws IOException {
        if (config == null) {
            throw new IllegalArgumentException("配置对象不能为 null");
        }
        
        System.out.println("[DEBUG] ConfigManager.saveConfig() 被调用");
        System.out.println("[DEBUG] 配置对象: blackpath=" + config.getBlackpath());
        System.out.println("[DEBUG] 配置对象: blacklist=" + config.getBlacklist());

        // 字段级验证 + 自动修正无效值 (不阻止保存)
        config = sanitizeConfig(config);

        // 配置 YAML 输出格式
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);  // 使用块状样式
        options.setPrettyFlow(true);                                  // 美化输出
        options.setIndent(2);                                         // 基础缩进 2 空格
        options.setIndicatorIndent(0);                                // 列表标记符不额外缩进
        options.setIndentWithIndicator(true);                         // 列表内容与标记对齐
        // 移除 PLAIN 风格约束，让 SnakeYAML 自动选择最佳格式
        // 简单字符串会使用 plain 风格，多行文本会自动使用 literal 块（|）
        options.setSplitLines(false);                                 // 不自动拆分长行
        options.setWidth(120);                                        // 行宽限制 120 字符

        // 使用 Representer 并配置不输出类型标签
        org.yaml.snakeyaml.representer.Representer representer = new org.yaml.snakeyaml.representer.Representer(
                options);
        // 关键: 将DetSqlYamlConfig类映射为普通MAP,不输出类型标签
        representer.addClassTag(DetSqlYamlConfig.class, org.yaml.snakeyaml.nodes.Tag.MAP);
        representer.getPropertyUtils().setSkipMissingProperties(true);

        Yaml yaml = new Yaml(representer, options);

        try (OutputStream output = Files.newOutputStream(configPath);
                OutputStreamWriter writer = new OutputStreamWriter(output, StandardCharsets.UTF_8)) {
            System.out.println("[DEBUG] 开始写入文件: " + configPath);
            yaml.dump(config, writer);
            writer.flush(); // 强制刷新缓冲区
            System.out.println("[DEBUG] 文件写入完成");
            System.out.println("配置已成功保存到: " + configPath);
            
            // 验证文件是否真的被写入
            if (Files.exists(configPath)) {
                long fileSize = Files.size(configPath);
                System.out.println("[DEBUG] 文件存在，大小: " + fileSize + " bytes");
            } else {
                System.err.println("[DEBUG] 警告: 文件不存在！");
            }
        } catch (IOException e) {
            System.err.println("保存配置文件失败: " + configPath);
            System.err.println("错误详情: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * 创建默认配置
     */
    private DetSqlYamlConfig createDefaultConfig() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();

        // 设置默认值
        config.setDelaytime(DefaultConfig.DEFAULT_DELAY_TIME_MS);
        config.setStatictime(DefaultConfig.DEFAULT_STATIC_TIME_MS);
        config.setStarttime(DefaultConfig.DEFAULT_START_TIME_MS);
        config.setEndtime(DefaultConfig.DEFAULT_END_TIME_MS);

        config.setSwitchEnabled(true);
        config.setErrorcheck(true);
        config.setNumcheck(true);
        config.setStringcheck(true);
        config.setOrdercheck(true);
        config.setBoolcheck(true);

        return config;
    }

    /**
     * 字段级配置验证 + 自动修正
     * 不阻止保存,只修正无效值为默认值
     * 这样可以避免一个字段无效导致整个配置(包括域名黑名单)无法保存
     */
    private DetSqlYamlConfig sanitizeConfig(DetSqlYamlConfig config) {
        boolean hasWarnings = false;
        StringBuilder warnings = new StringBuilder();

        // 修正时间字段
        if (config.getDelaytime() < 0) {
            warnings.append("- delaytime 为负数 (").append(config.getDelaytime())
                   .append("), 已修正为默认值 ").append(DefaultConfig.DEFAULT_DELAY_TIME_MS).append("\n");
            config.setDelaytime(DefaultConfig.DEFAULT_DELAY_TIME_MS);
            hasWarnings = true;
        }

        if (config.getStatictime() < 0) {
            warnings.append("- statictime 为负数 (").append(config.getStatictime())
                   .append("), 已修正为默认值 ").append(DefaultConfig.DEFAULT_STATIC_TIME_MS).append("\n");
            config.setStatictime(DefaultConfig.DEFAULT_STATIC_TIME_MS);
            hasWarnings = true;
        }

        if (config.getStarttime() < 0) {
            warnings.append("- starttime 为负数 (").append(config.getStarttime())
                   .append("), 已修正为默认值 ").append(DefaultConfig.DEFAULT_START_TIME_MS).append("\n");
            config.setStarttime(DefaultConfig.DEFAULT_START_TIME_MS);
            hasWarnings = true;
        }

        if (config.getEndtime() < 0) {
            warnings.append("- endtime 为负数 (").append(config.getEndtime())
                   .append("), 已修正为默认值 ").append(DefaultConfig.DEFAULT_END_TIME_MS).append("\n");
            config.setEndtime(DefaultConfig.DEFAULT_END_TIME_MS);
            hasWarnings = true;
        }

        // 修正语言索引
        if (config.getLanguageindex() < 0 || config.getLanguageindex() > 1) {
            warnings.append("- languageindex 超出范围 [0,1] (").append(config.getLanguageindex())
                   .append("), 已修正为 0 (中文)\n");
            config.setLanguageindex(0);
            hasWarnings = true;
        }

        // 验证自定义正则表达式 - 只记录警告,移除无效的正则
        if (!config.getDiyregex().isBlank()) {
            java.util.List<String> validRegexList = new java.util.ArrayList<>();
            for (String line : config.getDiyregex().split("\n")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    try {
                        java.util.regex.Pattern.compile(trimmed);
                        validRegexList.add(trimmed);
                    } catch (java.util.regex.PatternSyntaxException e) {
                        warnings.append("- 无效的正则表达式已移除: ").append(trimmed)
                               .append(" (错误: ").append(e.getMessage()).append(")\n");
                        hasWarnings = true;
                    }
                }
            }
            config.setDiyregex(String.join("\n", validRegexList));
        }

        // 输出警告信息
        if (hasWarnings) {
            System.err.println("警告: 配置包含无效值,已自动修正为默认值:");
            System.err.println(warnings.toString());
            System.err.println("配置仍然会被保存,其他有效字段(如域名黑名单)不受影响。");
        }

        return config;
    }

    /**
     * 获取配置文件路径
     */
    public Path getConfigPath() {
        return configPath;
    }
}

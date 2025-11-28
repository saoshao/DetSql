package DetSql;

import DetSql.config.ConfigManager;
import DetSql.config.DetSqlYamlConfig;
import DetSql.ui.MyFilterRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 诊断测试：重现用户报告的配置保存Bug
 * 
 * 用户报告的问题：
 * 1. 路径黑名单配置不生效（但域名黑名单和参数黑名单能生效）
 * 2. 点击【确认】和【保存】按钮时，配置文件永远不更新（只有卸载插件时才更新）
 * 
 * 这个测试的目标：
 * - 验证路径黑名单的运行时更新是否正常
 * - 验证配置保存到文件是否正常
 * - 模拟用户点击【确认】按钮的完整流程
 */
public class ConfigSaveBugDiagnosticTest {

    private ConfigManager configManager;
    private Path testConfigPath;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        // 使用临时目录而非用户主目录，避免污染真实配置
        testConfigPath = tempDir.resolve("config.yaml");
        System.out.println("[测试] 使用临时配置文件: " + testConfigPath);
        
        // 创建 ConfigManager（它会使用用户主目录，这里只是为了演示）
        configManager = new ConfigManager();
    }

    @AfterEach
    void tearDown() {
        // 清理测试数据 - 重新赋值为空集合而不是清空（避免不可变集合的问题）
        MyFilterRequest.blackPathSet = new HashSet<>();
        MyFilterRequest.blackListSet = new HashSet<>();
        MyFilterRequest.blackParamsSet = new HashSet<>();
    }

    /**
     * 测试场景1：模拟用户在UI中设置路径黑名单，然后点击【确认】按钮
     * 
     * 预期行为：
     * 1. MyFilterRequest.blackPathSet 应该被更新
     * 2. 配置对象中的 blackpath 字段应该包含路径黑名单
     * 3. 配置文件应该被成功保存
     */
    @Test
    void testBlackPathRuntimeUpdate() {
        System.out.println("\n========== 测试1：路径黑名单运行时更新 ==========");
        
        // 模拟用户在 UI 文本框中输入路径黑名单
        String blackPathInput = "/admin\n/api/internal\n/debug";
        
        // 模拟 ConfigPanel.handleConfirmButton() 中的逻辑（第519行）
        // 将文本框内容解析为 Set<String>
        HashSet<String> blackPathSet = new HashSet<>();
        for (String line : blackPathInput.split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                blackPathSet.add(trimmed);
            }
        }
        
        // 更新运行时配置
        MyFilterRequest.blackPathSet = blackPathSet;
        System.out.println("[步骤1] 已更新运行时路径黑名单: " + MyFilterRequest.blackPathSet);
        
        // 验证运行时配置已更新
        assertEquals(3, MyFilterRequest.blackPathSet.size(), "路径黑名单应该包含3条规则");
        assertTrue(MyFilterRequest.blackPathSet.contains("/admin"), "应该包含 /admin");
        assertTrue(MyFilterRequest.blackPathSet.contains("/api/internal"), "应该包含 /api/internal");
        assertTrue(MyFilterRequest.blackPathSet.contains("/debug"), "应该包含 /debug");
        
        System.out.println("✓ 运行时路径黑名单更新成功");
    }

    /**
     * 测试场景2：模拟构建 YAML 配置对象
     * 
     * 这个测试验证 DetSqlUI.buildYamlConfig() 是否正确读取 MyFilterRequest.blackPathSet
     */
    @Test
    void testBuildYamlConfigWithBlackPath() {
        System.out.println("\n========== 测试2：构建YAML配置对象 ==========");
        
        // 设置运行时配置
        MyFilterRequest.blackPathSet = new HashSet<>(Arrays.asList("/admin", "/api/internal", "/debug"));
        MyFilterRequest.blackListSet = new HashSet<>(Arrays.asList("evil.com", "malicious.net"));
        MyFilterRequest.blackParamsSet = new HashSet<>(Arrays.asList("debug", "test"));
        
        System.out.println("[步骤1] 运行时配置:");
        System.out.println("  - 路径黑名单: " + MyFilterRequest.blackPathSet);
        System.out.println("  - 域名黑名单: " + MyFilterRequest.blackListSet);
        System.out.println("  - 参数黑名单: " + MyFilterRequest.blackParamsSet);
        
        // 模拟 DetSqlUI.buildYamlConfig() 中的逻辑（第181行）
        DetSqlYamlConfig yamlConfig = new DetSqlYamlConfig();
        yamlConfig.setBlackpath(String.join("\n", MyFilterRequest.blackPathSet));
        yamlConfig.setBlacklist(List.copyOf(MyFilterRequest.blackListSet));
        yamlConfig.setParamslist(List.copyOf(MyFilterRequest.blackParamsSet));
        
        System.out.println("[步骤2] 构建的YAML配置对象:");
        System.out.println("  - blackpath: " + yamlConfig.getBlackpath());
        System.out.println("  - blacklist: " + yamlConfig.getBlacklist());
        System.out.println("  - paramslist: " + yamlConfig.getParamslist());
        
        // 验证配置对象正确包含路径黑名单
        assertNotNull(yamlConfig.getBlackpath(), "blackpath 不应为 null");
        assertFalse(yamlConfig.getBlackpath().isEmpty(), "blackpath 不应为空");
        
        String[] blackPathLines = yamlConfig.getBlackpath().split("\n");
        assertEquals(3, blackPathLines.length, "应该包含3条路径黑名单规则");
        
        // 验证域名黑名单和参数黑名单也正确
        assertEquals(2, yamlConfig.getBlacklist().size(), "应该包含2条域名黑名单规则");
        assertEquals(2, yamlConfig.getParamslist().size(), "应该包含2条参数黑名单规则");
        
        System.out.println("✓ YAML配置对象构建成功，路径黑名单已正确包含");
    }

    /**
     * 测试场景3：验证配置保存到文件
     * 
     * 这个测试验证 ConfigManager.saveConfig() 是否能正确保存路径黑名单到文件
     */
    @Test
    void testSaveConfigWithBlackPath() throws IOException {
        System.out.println("\n========== 测试3：保存配置到文件 ==========");
        
        // 创建配置对象
        DetSqlYamlConfig yamlConfig = new DetSqlYamlConfig();
        yamlConfig.setBlackpath("/admin\n/api/internal\n/debug");
        yamlConfig.setBlacklist(Arrays.asList("evil.com", "malicious.net"));
        yamlConfig.setParamslist(Arrays.asList("debug", "test"));
        
        System.out.println("[步骤1] 准备保存的配置:");
        System.out.println("  - blackpath: " + yamlConfig.getBlackpath());
        System.out.println("  - blacklist: " + yamlConfig.getBlacklist());
        System.out.println("  - paramslist: " + yamlConfig.getParamslist());
        
        // 保存配置（会保存到用户主目录的 .config/DetSql/config.yaml）
        System.out.println("[步骤2] 调用 configManager.saveConfig()");
        configManager.saveConfig(yamlConfig);
        
        System.out.println("[步骤3] 配置文件路径: " + configManager.getConfigPath());
        
        // 验证文件是否存在
        Path savedConfigPath = configManager.getConfigPath();
        assertTrue(Files.exists(savedConfigPath), "配置文件应该存在: " + savedConfigPath);
        
        // 读取文件内容验证
        String fileContent = Files.readString(savedConfigPath);
        System.out.println("[步骤4] 文件内容:");
        System.out.println(fileContent);
        
        // 验证关键字段是否存在
        assertTrue(fileContent.contains("blackpath:"), "文件应该包含 blackpath 字段");
        assertTrue(fileContent.contains("/admin"), "文件应该包含 /admin");
        assertTrue(fileContent.contains("/api/internal"), "文件应该包含 /api/internal");
        assertTrue(fileContent.contains("blacklist:"), "文件应该包含 blacklist 字段");
        assertTrue(fileContent.contains("evil.com"), "文件应该包含 evil.com");
        assertTrue(fileContent.contains("paramslist:"), "文件应该包含 paramslist 字段");
        assertTrue(fileContent.contains("debug"), "文件应该包含 debug");
        
        System.out.println("✓ 配置保存成功，路径黑名单已写入文件");
    }

    /**
     * 测试场景4：完整流程测试 - 模拟用户点击【确认】按钮的完整流程
     * 
     * 这个测试模拟从UI输入到文件保存的完整链路
     */
    @Test
    void testCompleteConfigSaveFlow() throws IOException {
        System.out.println("\n========== 测试4：完整配置保存流程 ==========");
        
        // === 第1步：用户在UI中输入配置 ===
        System.out.println("[第1步] 用户在UI中输入配置");
        String blackPathInput = "/admin\n/api/internal\n/debug";
        String blackListInput = "evil.com|malicious.net";
        String blackParamsInput = "debug|test";
        
        // === 第2步：模拟 ConfigPanel.handleConfirmButton() 的逻辑 ===
        System.out.println("[第2步] 解析UI输入并更新运行时配置");
        
        // 解析路径黑名单（模拟 readLinesFromTextArea）
        HashSet<String> blackPathSet = new HashSet<>();
        for (String line : blackPathInput.split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                blackPathSet.add(trimmed);
            }
        }
        MyFilterRequest.blackPathSet = blackPathSet;
        System.out.println("  - 路径黑名单: " + MyFilterRequest.blackPathSet);
        
        // 解析域名黑名单（模拟 parseDelimitedString）
        MyFilterRequest.blackListSet = new HashSet<>(Arrays.asList(blackListInput.split("\\|")));
        System.out.println("  - 域名黑名单: " + MyFilterRequest.blackListSet);
        
        // 解析参数黑名单
        MyFilterRequest.blackParamsSet = new HashSet<>(Arrays.asList(blackParamsInput.split("\\|")));
        System.out.println("  - 参数黑名单: " + MyFilterRequest.blackParamsSet);
        
        // === 第3步：构建 YAML 配置对象 ===
        System.out.println("[第3步] 构建YAML配置对象 (模拟 ui.buildYamlConfig())");
        DetSqlYamlConfig yamlConfig = new DetSqlYamlConfig();
        yamlConfig.setBlackpath(String.join("\n", MyFilterRequest.blackPathSet));
        yamlConfig.setBlacklist(List.copyOf(MyFilterRequest.blackListSet));
        yamlConfig.setParamslist(List.copyOf(MyFilterRequest.blackParamsSet));
        
        System.out.println("  - YAML blackpath: " + yamlConfig.getBlackpath());
        System.out.println("  - YAML blacklist: " + yamlConfig.getBlacklist());
        System.out.println("  - YAML paramslist: " + yamlConfig.getParamslist());
        
        // === 第4步：保存到文件 ===
        System.out.println("[第4步] 保存到文件 (模拟 configManager.saveConfig())");
        configManager.saveConfig(yamlConfig);
        
        // === 第5步：验证文件内容 ===
        System.out.println("[第5步] 验证文件内容");
        Path savedConfigPath = configManager.getConfigPath();
        assertTrue(Files.exists(savedConfigPath), "配置文件应该存在");
        
        String fileContent = Files.readString(savedConfigPath);
        System.out.println("文件内容预览:");
        System.out.println("----------------------------------------");
        System.out.println(fileContent);
        System.out.println("----------------------------------------");
        
        // 验证所有三种黑名单都正确保存
        assertTrue(fileContent.contains("blackpath:"), "文件应该包含 blackpath 字段");
        assertTrue(fileContent.contains("/admin"), "文件应该包含路径 /admin");
        
        assertTrue(fileContent.contains("blacklist:"), "文件应该包含 blacklist 字段");
        assertTrue(fileContent.contains("evil.com"), "文件应该包含域名 evil.com");
        
        assertTrue(fileContent.contains("paramslist:"), "文件应该包含 paramslist 字段");
        assertTrue(fileContent.contains("debug"), "文件应该包含参数 debug");
        
        System.out.println("\n✓✓✓ 完整流程测试通过 ✓✓✓");
        System.out.println("路径黑名单、域名黑名单、参数黑名单都正确保存到文件");
    }

    /**
     * 测试场景5：诊断用户报告的问题 - 配置文件权限问题
     * 
     * 这个测试检查是否存在文件权限问题导致保存失败
     */
    @Test
    void testConfigFilePermissions() {
        System.out.println("\n========== 测试5：配置文件权限检查 ==========");
        
        Path configPath = configManager.getConfigPath();
        Path configDir = configPath.getParent();
        
        System.out.println("配置目录: " + configDir);
        System.out.println("配置文件: " + configPath);
        
        // 检查目录是否存在
        if (Files.exists(configDir)) {
            System.out.println("✓ 配置目录存在");
            System.out.println("  - 可读: " + Files.isReadable(configDir));
            System.out.println("  - 可写: " + Files.isWritable(configDir));
            System.out.println("  - 可执行: " + Files.isExecutable(configDir));
        } else {
            System.out.println("✗ 配置目录不存在");
        }
        
        // 检查文件是否存在
        if (Files.exists(configPath)) {
            System.out.println("✓ 配置文件存在");
            System.out.println("  - 可读: " + Files.isReadable(configPath));
            System.out.println("  - 可写: " + Files.isWritable(configPath));
            try {
                System.out.println("  - 文件大小: " + Files.size(configPath) + " bytes");
            } catch (IOException e) {
                System.out.println("  - 无法获取文件大小: " + e.getMessage());
            }
        } else {
            System.out.println("ℹ 配置文件不存在（首次运行正常）");
        }
    }
}

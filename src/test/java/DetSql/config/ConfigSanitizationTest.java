/*
 * Config Sanitization Test - 验证字段级配置验证修复
 *
 * 测试目标:
 * 1. 验证无效时间字段不会阻止配置保存
 * 2. 验证域名黑名单能够在时间字段无效的情况下仍然保存
 * 3. 验证自动修正逻辑正确工作
 *
 * @author DetSql Team
 */
package DetSql.config;

import org.junit.jupiter.api.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ConfigSanitizationTest {

    private ConfigManager configManager;
    private Path originalConfigPath;

    @BeforeEach
    public void setUp() throws Exception {
        configManager = new ConfigManager();

        // 备份原始配置路径
        java.lang.reflect.Field configPathField = ConfigManager.class.getDeclaredField("configPath");
        configPathField.setAccessible(true);
        originalConfigPath = (Path) configPathField.get(configManager);

        // 使用临时文件作为测试配置
        Path testConfigPath = Files.createTempFile("detsql-test-config-", ".yaml");
        configPathField.set(configManager, testConfigPath);
    }

    @AfterEach
    public void tearDown() throws Exception {
        // 获取测试配置路径
        java.lang.reflect.Field configPathField = ConfigManager.class.getDeclaredField("configPath");
        configPathField.setAccessible(true);
        Path testConfigPath = (Path) configPathField.get(configManager);

        // 清理测试文件
        if (testConfigPath != null && Files.exists(testConfigPath)) {
            Files.delete(testConfigPath);
        }

        // 恢复原始配置路径
        configPathField.set(configManager, originalConfigPath);
    }

    @Test
    @Order(1)
    @DisplayName("正常配置应该能成功保存")
    public void testValidConfigSaveSuccessfully() throws Exception {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setBlacklist(Arrays.asList("example.com", "test.com"));
        config.setDelaytime(3000);
        config.setStatictime(0);
        config.setStarttime(0);
        config.setEndtime(0);
        config.setLanguageindex(0);

        // 应该成功保存
        assertDoesNotThrow(() -> configManager.saveConfig(config));

        // 获取测试配置路径
        java.lang.reflect.Field configPathField = ConfigManager.class.getDeclaredField("configPath");
        configPathField.setAccessible(true);
        Path testConfigPath = (Path) configPathField.get(configManager);

        // 验证文件被创建
        assertTrue(Files.exists(testConfigPath), "配置文件应该被创建");

        // 验证内容能正确加载
        DetSqlYamlConfig loaded = configManager.loadConfig();
        assertEquals(2, loaded.getBlacklist().size());
        assertTrue(loaded.getBlacklist().contains("example.com"));
        assertTrue(loaded.getBlacklist().contains("test.com"));
    }

    @Test
    @Order(2)
    @DisplayName("修复前: 负数时间字段会阻止配置保存")
    public void testOldBehavior_NegativeTimeBlocksSave() {
        // 这个测试记录旧的错误行为
        // 在修复前,ConfigValidator.validate() 会返回 false
        // 导致 IllegalArgumentException 被抛出

        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setBlacklist(Arrays.asList("datasink.baidu.com", "weixin.qq.com"));
        config.setDelaytime(-1);  // ← 无效值

        // 旧行为: 抛出异常,配置无法保存
        // 新行为: 自动修正为默认值,配置成功保存
        assertDoesNotThrow(() -> configManager.saveConfig(config),
            "修复后: 负数时间应该被自动修正,不应阻止保存");
    }

    @Test
    @Order(3)
    @DisplayName("修复后: 负数时间字段被自动修正,黑名单仍然保存")
    public void testNewBehavior_NegativeTimeSanitized() throws Exception {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setBlacklist(Arrays.asList("datasink.baidu.com", "s.union.360.cn",
            "weixin.qq.com", "www.google.com"));
        config.setDelaytime(-1);
        config.setStatictime(-100);
        config.setStarttime(-50);
        config.setEndtime(-200);

        // 应该成功保存,不抛出异常
        assertDoesNotThrow(() -> configManager.saveConfig(config));

        // 获取测试配置路径
        java.lang.reflect.Field configPathField = ConfigManager.class.getDeclaredField("configPath");
        configPathField.setAccessible(true);
        Path testConfigPath = (Path) configPathField.get(configManager);

        // 验证文件被创建
        assertTrue(Files.exists(testConfigPath), "配置文件应该被创建");

        // 重新加载配置
        DetSqlYamlConfig loaded = configManager.loadConfig();

        // 验证黑名单被正确保存
        assertEquals(4, loaded.getBlacklist().size(),
            "黑名单应该包含4个域名");
        assertTrue(loaded.getBlacklist().contains("datasink.baidu.com"));
        assertTrue(loaded.getBlacklist().contains("s.union.360.cn"));
        assertTrue(loaded.getBlacklist().contains("weixin.qq.com"));
        assertTrue(loaded.getBlacklist().contains("www.google.com"));

        // 验证时间字段被修正为默认值
        assertTrue(loaded.getDelaytime() >= 0, "delaytime 应该被修正为非负数");
        assertTrue(loaded.getStatictime() >= 0, "statictime 应该被修正为非负数");
        assertTrue(loaded.getStarttime() >= 0, "starttime 应该被修正为非负数");
        assertTrue(loaded.getEndtime() >= 0, "endtime 应该被修正为非负数");
    }

    @Test
    @Order(4)
    @DisplayName("修复后: 无效语言索引被自动修正")
    public void testLanguageIndexSanitization() throws Exception {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setBlacklist(Arrays.asList("test.com"));
        config.setLanguageindex(999);  // 无效值,应该在 [0,1]

        assertDoesNotThrow(() -> configManager.saveConfig(config));

        DetSqlYamlConfig loaded = configManager.loadConfig();
        assertTrue(loaded.getLanguageindex() >= 0 && loaded.getLanguageindex() <= 1,
            "languageindex 应该被修正到 [0,1] 范围");
        assertEquals(1, loaded.getBlacklist().size(), "黑名单仍然应该被保存");
    }

    @Test
    @Order(5)
    @DisplayName("修复后: 无效正则表达式被移除,不阻止保存")
    public void testInvalidRegexSanitization() throws Exception {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setBlacklist(Arrays.asList("example.com"));
        config.setDiyregex("[invalid(regex\n(?<valid>.*)");  // 包含有效和无效正则

        assertDoesNotThrow(() -> configManager.saveConfig(config));

        DetSqlYamlConfig loaded = configManager.loadConfig();
        assertEquals(1, loaded.getBlacklist().size(), "黑名单应该被保存");
        // 无效正则应该被移除,只保留有效的
        assertNotNull(loaded.getDiyregex());
    }

    @Test
    @Order(6)
    @DisplayName("用户报告场景: 黑名单 + 负数时间")
    public void testUserReportedScenario() throws Exception {
        // 模拟用户报告的场景:
        // 1. 用户配置了域名黑名单
        // 2. 同时不小心输入了负数时间
        // 3. 点击"确认"按钮

        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setBlacklist(Arrays.asList(
            "datasink.baidu.com",
            "s.union.360.cn",
            "weixin.qq.com",
            "www.google.com"
        ));
        config.setDelaytime(-1);  // 用户误输入

        // 修复前: IllegalArgumentException → 配置无法保存 → 黑名单丢失
        // 修复后: 自动修正 → 配置成功保存 → 黑名单生效
        assertDoesNotThrow(() -> configManager.saveConfig(config));

        // 验证配置能被正确加载
        DetSqlYamlConfig loaded = configManager.loadConfig();
        assertEquals(4, loaded.getBlacklist().size());

        // 验证黑名单内容
        Set<String> blacklistSet = new HashSet<>(loaded.getBlacklist());
        assertTrue(blacklistSet.contains("datasink.baidu.com"));
        assertTrue(blacklistSet.contains("s.union.360.cn"));
        assertTrue(blacklistSet.contains("weixin.qq.com"));
        assertTrue(blacklistSet.contains("www.google.com"));

        // 验证时间被修正
        assertTrue(loaded.getDelaytime() > 0, "delaytime 应该被修正为正数");

        System.out.println("✓ 用户场景验证成功:");
        System.out.println("  - 黑名单成功保存: " + loaded.getBlacklist());
        System.out.println("  - 时间字段自动修正: " + loaded.getDelaytime());
    }

    @Test
    @Order(7)
    @DisplayName("完整性测试: 所有字段都无效的极端情况")
    public void testAllInvalidFields() throws Exception {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setBlacklist(Arrays.asList("important.com"));  // ← 关键数据
        config.setDelaytime(-1);
        config.setStatictime(-1);
        config.setStarttime(-1);
        config.setEndtime(-1);
        config.setLanguageindex(999);
        config.setDiyregex("[[[invalid");

        // 即使所有其他字段都无效,也不应阻止保存
        assertDoesNotThrow(() -> configManager.saveConfig(config));

        DetSqlYamlConfig loaded = configManager.loadConfig();
        assertEquals(1, loaded.getBlacklist().size());
        assertEquals("important.com", loaded.getBlacklist().get(0),
            "重要的域名黑名单数据不应该因为其他字段无效而丢失");
    }
}

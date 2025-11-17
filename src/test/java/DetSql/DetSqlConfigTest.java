package DetSql;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * DetSqlConfig 测试 - 验证配置加载、保存和验证逻辑
 *
 * 测试范围:
 * - 默认值初始化
 * - 配置文件加载和解析
 * - 配置文件保存
 * - 边界情况和错误处理
 * - PropertyChangeListener 通知机制
 */
public class DetSqlConfigTest {

    private DetSqlConfig mConfig;

    @TempDir
    Path tempDir; // JUnit 5 提供的临时目录

    @BeforeEach
    void setUp() {
        mConfig = new DetSqlConfig();
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 默认值测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_HaveCorrectDefaults_when_NewInstanceCreated() {
        // Assert: 验证默认值
        assertEquals(0.9, mConfig.getSimilarityThreshold(), 1e-9, "Default similarity threshold");
        assertEquals(50000, mConfig.getMaxResponseSize(), "Default max response size");
        assertEquals(100, mConfig.getLengthDiffThreshold(), "Default length diff threshold");
        assertEquals(4, mConfig.getThreadPoolSize(), "Default thread pool size");
        assertEquals(1, mConfig.getThreadPoolSize2(), "Default thread pool size 2");
        assertEquals(0, mConfig.getDelayTimeMs(), "Default delay time");
        assertEquals(100, mConfig.getStaticTimeMs(), "Default static time");
    }

    @Test
    void should_HaveEmptyCollections_when_NewInstanceCreated() {
        // Assert: 验证集合初始化
        assertTrue(mConfig.getWhiteListDomains().isEmpty(), "White list should be empty");
        assertTrue(mConfig.getBlackListDomains().isEmpty(), "Black list should be empty");
        assertTrue(mConfig.getBlackListParams().isEmpty(), "Params black list should be empty");
        assertTrue(mConfig.getBlackListPaths().isEmpty(), "Paths black list should be empty");
        assertTrue(mConfig.getDiyPayloads().isEmpty(), "DIY payloads should be empty");
        assertTrue(mConfig.getDiyRegexs().isEmpty(), "DIY regexs should be empty");
    }

    @Test
    void should_HaveDefaultPayloads_when_NewInstanceCreated() {
        // Assert: 验证默认 payload
        String[] errorPayloads = mConfig.getErrorPayloads();
        assertNotNull(errorPayloads, "Error payloads should not be null");
        assertTrue(errorPayloads.length > 0, "Should have default error payloads");

        String[] errorPayloadsJson = mConfig.getErrorPayloadsJson();
        assertNotNull(errorPayloadsJson, "JSON error payloads should not be null");
        assertTrue(errorPayloadsJson.length >= errorPayloads.length,
            "JSON payloads should include base payloads and variants");
    }

    @Test
    void should_HaveDefaultSuffixSet_when_NewInstanceCreated() {
        // Assert: 验证默认后缀集合
        Set<String> suffixes = mConfig.getUnLegalExtensions();
        assertNotNull(suffixes, "Suffix set should not be null");
        assertFalse(suffixes.isEmpty(), "Should have default suffixes");
        assertTrue(suffixes.contains("js"), "Should contain js");
        assertTrue(suffixes.contains("css"), "Should contain css");
        assertTrue(suffixes.contains("png"), "Should contain png");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Getter/Setter 测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_UpdateValue_when_CallingSetters() {
        // Act
        mConfig.setSimilarityThreshold(0.85);
        mConfig.setMaxResponseSize(100000);
        mConfig.setLengthDiffThreshold(200);
        mConfig.setThreadPoolSize(8);
        mConfig.setDelayTimeMs(500);

        // Assert
        assertEquals(0.85, mConfig.getSimilarityThreshold(), 1e-9);
        assertEquals(100000, mConfig.getMaxResponseSize());
        assertEquals(200, mConfig.getLengthDiffThreshold());
        assertEquals(8, mConfig.getThreadPoolSize());
        assertEquals(500, mConfig.getDelayTimeMs());
    }

    @Test
    void should_UpdateCollections_when_CallingSetters() {
        // Arrange
        Set<String> whitelist = new HashSet<>();
        whitelist.add("example.com");
        whitelist.add("test.com");

        Set<String> blacklistParams = new HashSet<>();
        blacklistParams.add("token");
        blacklistParams.add("session");

        // Act
        mConfig.setWhiteListDomains(whitelist);
        mConfig.setBlackListParams(blacklistParams);

        // Assert
        assertEquals(2, mConfig.getWhiteListDomains().size());
        assertTrue(mConfig.getWhiteListDomains().contains("example.com"));
        assertEquals(2, mConfig.getBlackListParams().size());
        assertTrue(mConfig.getBlackListParams().contains("token"));
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // PropertyChangeListener 测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_NotifyListener_when_PropertyChanges() {
        // Arrange
        AtomicInteger notifyCount = new AtomicInteger(0);
        PropertyChangeListener listener = new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if ("similarityThreshold".equals(evt.getPropertyName())) {
                    notifyCount.incrementAndGet();
                    assertEquals(0.9, evt.getOldValue());
                    assertEquals(0.8, evt.getNewValue());
                }
            }
        };
        mConfig.addPropertyChangeListener(listener);

        // Act
        mConfig.setSimilarityThreshold(0.8);

        // Assert
        assertEquals(1, notifyCount.get(), "Listener should be notified once");
    }

    @Test
    void should_NotifyMultipleListeners_when_PropertyChanges() {
        // Arrange
        AtomicInteger count1 = new AtomicInteger(0);
        AtomicInteger count2 = new AtomicInteger(0);

        mConfig.addPropertyChangeListener(evt -> {
            if ("maxResponseSize".equals(evt.getPropertyName())) {
                count1.incrementAndGet();
            }
        });

        mConfig.addPropertyChangeListener(evt -> {
            if ("maxResponseSize".equals(evt.getPropertyName())) {
                count2.incrementAndGet();
            }
        });

        // Act
        mConfig.setMaxResponseSize(80000);

        // Assert
        assertEquals(1, count1.get(), "First listener should be notified");
        assertEquals(1, count2.get(), "Second listener should be notified");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 配置文件加载测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_LoadConfiguration_when_ValidFileExists() throws IOException {
        // Arrange: 创建测试配置文件
        Path configPath = tempDir.resolve("test_config.properties");
        String configContent = String.join("\n",
            "similarityThreshold=0.85",
            "maxResponseSize=80000",
            "lengthDiffThreshold=150",
            "threadPoolSize=6",
            "delaytime=200",
            "statictime=50",
            "whitelist=example.com|test.com",
            "paramslist=token|csrf"
        );
        Files.writeString(configPath, configContent);

        // Act
        mConfig.load(configPath.toString());

        // Assert
        assertEquals(0.85, mConfig.getSimilarityThreshold(), 1e-9);
        assertEquals(80000, mConfig.getMaxResponseSize());
        assertEquals(150, mConfig.getLengthDiffThreshold());
        assertEquals(6, mConfig.getThreadPoolSize());
        assertEquals(200, mConfig.getDelayTimeMs());
        assertEquals(50, mConfig.getStaticTimeMs());
        assertTrue(mConfig.getWhiteListDomains().contains("example.com"));
        assertTrue(mConfig.getBlackListParams().contains("token"));
    }

    @Test
    void should_UseDefaults_when_FileDoesNotExist() throws IOException {
        // Arrange
        Path nonExistentPath = tempDir.resolve("nonexistent.properties");

        // Act
        mConfig.load(nonExistentPath.toString());

        // Assert: 应该保持默认值
        assertEquals(0.9, mConfig.getSimilarityThreshold(), 1e-9);
        assertEquals(50000, mConfig.getMaxResponseSize());
    }

    @Test
    void should_UseDefaults_when_PropertyIsMissing() throws IOException {
        // Arrange: 配置文件只包含部分属性
        Path configPath = tempDir.resolve("partial_config.properties");
        String configContent = "similarityThreshold=0.75\n";
        Files.writeString(configPath, configContent);

        // Act
        mConfig.load(configPath.toString());

        // Assert
        assertEquals(0.75, mConfig.getSimilarityThreshold(), 1e-9, "Should load specified value");
        assertEquals(50000, mConfig.getMaxResponseSize(), "Should use default for missing property");
    }

    @Test
    void should_UseDefaults_when_PropertyValueIsInvalid() throws IOException {
        // Arrange: 配置文件包含无效值
        Path configPath = tempDir.resolve("invalid_config.properties");
        String configContent = String.join("\n",
            "similarityThreshold=invalid_number",
            "maxResponseSize=not_a_number",
            "threadPoolSize=abc"
        );
        Files.writeString(configPath, configContent);

        // Act
        mConfig.load(configPath.toString());

        // Assert: 应该使用默认值
        assertEquals(0.9, mConfig.getSimilarityThreshold(), 1e-9, "Should use default for invalid double");
        assertEquals(50000, mConfig.getMaxResponseSize(), "Should use default for invalid int");
        assertEquals(4, mConfig.getThreadPoolSize(), "Should use default for invalid int");
    }

    @Test
    void should_ParseDelimitedLists_when_LoadingConfiguration() throws IOException {
        // Arrange
        Path configPath = tempDir.resolve("list_config.properties");
        String configContent = String.join("\n",
            "whitelist=domain1.com|domain2.com|domain3.com",
            "blacklist=bad1.com|bad2.com",
            "paramslist=id|user|pass",
            "suffixlist=jpg|png|gif"  // 注意: 不带点号
        );
        Files.writeString(configPath, configContent);

        // Act
        mConfig.load(configPath.toString());

        // Assert
        assertEquals(3, mConfig.getWhiteListDomains().size());
        assertTrue(mConfig.getWhiteListDomains().contains("domain1.com"));
        assertTrue(mConfig.getWhiteListDomains().contains("domain2.com"));

        assertEquals(2, mConfig.getBlackListDomains().size());
        assertTrue(mConfig.getBlackListDomains().contains("bad1.com"));

        assertEquals(3, mConfig.getBlackListParams().size());
        assertTrue(mConfig.getBlackListParams().contains("id"));

        assertEquals(3, mConfig.getUnLegalExtensions().size(), "Should have 3 suffixes");
        assertTrue(mConfig.getUnLegalExtensions().contains("jpg"), "Should contain jpg");
        assertTrue(mConfig.getUnLegalExtensions().contains("png"), "Should contain png");
        assertTrue(mConfig.getUnLegalExtensions().contains("gif"), "Should contain gif");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 配置文件保存测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_SaveConfiguration_when_CallingS() throws IOException {
        // Arrange: 修改配置
        mConfig.setSimilarityThreshold(0.88);
        mConfig.setMaxResponseSize(90000);
        mConfig.setLengthDiffThreshold(120);

        Set<String> whitelist = new HashSet<>();
        whitelist.add("test1.com");
        whitelist.add("test2.com");
        mConfig.setWhiteListDomains(whitelist);

        Path configPath = tempDir.resolve("saved_config.properties");

        // Act
        mConfig.save(configPath.toString());

        // Assert: 验证文件存在
        assertTrue(Files.exists(configPath), "Config file should be created");

        // 验证内容
        String content = Files.readString(configPath);
        assertTrue(content.contains("similarityThreshold=0.88"), "Should contain similarity threshold");
        assertTrue(content.contains("maxResponseSize=90000"), "Should contain max response size");
        assertTrue(content.contains("lengthDiffThreshold=120"), "Should contain length diff threshold");
        assertTrue(content.contains("whitelist="), "Should contain whitelist");
        assertTrue(content.contains("test1.com"), "Should contain whitelist domain");
    }

    @Test
    void should_RoundTripConfiguration_when_SaveAndLoad() throws IOException {
        // Arrange: 设置配置
        mConfig.setSimilarityThreshold(0.77);
        mConfig.setMaxResponseSize(60000);
        mConfig.setThreadPoolSize(10);

        Set<String> blacklist = new HashSet<>();
        blacklist.add("blocked.com");
        mConfig.setBlackListDomains(blacklist);

        Path configPath = tempDir.resolve("roundtrip_config.properties");

        // Act: 保存再加载
        mConfig.save(configPath.toString());

        DetSqlConfig newConfig = new DetSqlConfig();
        newConfig.load(configPath.toString());

        // Assert: 验证一致性
        assertEquals(mConfig.getSimilarityThreshold(), newConfig.getSimilarityThreshold(), 1e-9);
        assertEquals(mConfig.getMaxResponseSize(), newConfig.getMaxResponseSize());
        assertEquals(mConfig.getThreadPoolSize(), newConfig.getThreadPoolSize());
        assertTrue(newConfig.getBlackListDomains().contains("blocked.com"));
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Payload 配置测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_LoadCustomPayloads_when_ConfigFileSpecifiesThem() throws IOException {
        // Arrange
        Path configPath = tempDir.resolve("payload_config.properties");
        String configContent = "errpoclist=payload1|payload2|payload3\n";
        Files.writeString(configPath, configContent);

        // Act
        mConfig.load(configPath.toString());

        // Assert
        String[] payloads = mConfig.getErrorPayloads();
        assertEquals(3, payloads.length);
        assertEquals("payload1", payloads[0]);
        assertEquals("payload2", payloads[1]);
        assertEquals("payload3", payloads[2]);

        // JSON 变体应该包含更多
        String[] jsonPayloads = mConfig.getErrorPayloadsJson();
        assertTrue(jsonPayloads.length >= 3, "JSON payloads should include base and variants");
    }

    @Test
    void should_HandleEmptyPayloadList_when_ConfigSpecifiesEmpty() throws IOException {
        // Arrange: 空的 errpoclist 应该使用默认值
        Path configPath = tempDir.resolve("empty_payload_config.properties");
        String configContent = "errpoclist=\n";
        Files.writeString(configPath, configContent);

        // Act
        mConfig.load(configPath.toString());

        // Assert: 应该使用默认 payload
        String[] payloads = mConfig.getErrorPayloads();
        assertTrue(payloads.length > 0, "Empty config should fall back to defaults");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 边界情况测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_HandleEmptyStringValues_when_LoadingConfiguration() throws IOException {
        // Arrange
        Path configPath = tempDir.resolve("empty_values_config.properties");
        String configContent = String.join("\n",
            "similarityThreshold=",
            "whitelist=",
            "paramslist="
        );
        Files.writeString(configPath, configContent);

        // Act
        mConfig.load(configPath.toString());

        // Assert: 空值应该使用默认值
        assertEquals(0.9, mConfig.getSimilarityThreshold(), 1e-9);
        assertTrue(mConfig.getWhiteListDomains().isEmpty());
        assertTrue(mConfig.getBlackListParams().isEmpty());
    }

    @Test
    void should_HandleWhitespaceValues_when_LoadingConfiguration() throws IOException {
        // Arrange
        Path configPath = tempDir.resolve("whitespace_config.properties");
        String configContent = String.join("\n",
            "similarityThreshold=  0.95  ",
            "maxResponseSize=  70000  "
        );
        Files.writeString(configPath, configContent);

        // Act
        mConfig.load(configPath.toString());

        // Assert: 应该正确 trim 空白
        assertEquals(0.95, mConfig.getSimilarityThreshold(), 1e-9);
        assertEquals(70000, mConfig.getMaxResponseSize());
    }

    @Test
    void should_HandleBoundaryValues_when_SettingConfiguration() {
        // Act: 设置边界值
        mConfig.setSimilarityThreshold(0.0);
        mConfig.setMaxResponseSize(0);
        mConfig.setLengthDiffThreshold(Integer.MAX_VALUE);

        // Assert
        assertEquals(0.0, mConfig.getSimilarityThreshold(), 1e-9);
        assertEquals(0, mConfig.getMaxResponseSize());
        assertEquals(Integer.MAX_VALUE, mConfig.getLengthDiffThreshold());
    }
}

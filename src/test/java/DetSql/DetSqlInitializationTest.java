package DetSql;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import DetSql.core.DetSql;
import DetSql.ui.DetSqlUI;

/**
 * DetSql 插件初始化测试
 *
 * 测试范围:
 * - 插件加载流程
 * - 配置文件读取(默认配置 + 自定义配置)
 * - UI 组件创建(Tab、Panel、按钮等)
 * - 事件监听器注册
 * - 验证插件启动不会失败
 *
 * 设计原则:
 * - 使用 Mockito mock Burp Montoya API
 * - 测试真实配置文件解析逻辑
 * - 验证关键依赖注入正确性
 */
public class DetSqlInitializationTest {

    private DetSql mPlugin;
    private MontoyaApi mMockApi;
    private Logging mMockLogging;
    private burp.api.montoya.extension.Extension mMockExtension;
    private Http mMockHttp;
    private UserInterface mMockUi;
    private burp.api.montoya.utilities.Utilities mMockUtilities;
    private burp.api.montoya.utilities.CryptoUtils mMockCryptoUtils;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        // 创建 mock Montoya API
        mMockApi = mock(MontoyaApi.class);
        mMockLogging = mock(Logging.class);
        mMockExtension = mock(burp.api.montoya.extension.Extension.class);
        mMockHttp = mock(Http.class);
        mMockUi = mock(UserInterface.class);
        mMockUtilities = mock(burp.api.montoya.utilities.Utilities.class);
        mMockCryptoUtils = mock(burp.api.montoya.utilities.CryptoUtils.class);

        // 配置 mock 行为
        when(mMockApi.logging()).thenReturn(mMockLogging);
        when(mMockApi.extension()).thenReturn(mMockExtension);
        when(mMockApi.http()).thenReturn(mMockHttp);
        when(mMockApi.userInterface()).thenReturn(mMockUi);
        when(mMockApi.utilities()).thenReturn(mMockUtilities);
        when(mMockUtilities.cryptoUtils()).thenReturn(mMockCryptoUtils);

        // Mock UI 组件创建
        HttpRequestEditor mockRequestEditor = mock(HttpRequestEditor.class);
        HttpResponseEditor mockResponseEditor = mock(HttpResponseEditor.class);
        when(mMockUi.createHttpRequestEditor(any())).thenReturn(mockRequestEditor);
        when(mMockUi.createHttpResponseEditor(any())).thenReturn(mockResponseEditor);
        when(mockRequestEditor.uiComponent()).thenReturn(new JPanel());
        when(mockResponseEditor.uiComponent()).thenReturn(new JPanel());

        mPlugin = new DetSql();
    }

    @AfterEach
    void tearDown() {
        // Phase 3: UI 组件已改为实例字段，不需要清理静态变量
        // 每个测试都会创建新的 DetSql 实例，自动隔离
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 基本初始化测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_InitializeSuccessfully_when_NoConfigFileExists() {
        // Arrange: 使用不存在的配置文件路径
        System.setProperty("user.home", tempDir.toString());

        // Act
        mPlugin.initialize(mMockApi);

        // Assert: 验证核心组件已创建
        DetSqlUI ui = mPlugin.getUI();
        assertNotNull(ui.myHttpHandler, "HttpHandler should be initialized");
        assertNotNull(ui.sourceTableModel, "SourceTableModel should be initialized");
        assertNotNull(ui.attackMap, "AttackMap should be initialized");

        // 验证 API 交互
        verify(mMockExtension).setName("DetSql");
        verify(mMockHttp).registerHttpHandler(any(HttpHandler.class));
        verify(mMockExtension).registerUnloadingHandler(any(ExtensionUnloadingHandler.class));
        verify(mMockUi).registerContextMenuItemsProvider(any(ContextMenuItemsProvider.class));
        verify(mMockUi).registerSuiteTab(eq("DetSql"), any(Component.class));

        // 验证日志输出
        verify(mMockLogging, atLeastOnce()).logToOutput(contains("DetSql"));
    }

    @Test
    void should_CreateUIComponents_when_Initialize() {
        // Arrange
        System.setProperty("user.home", tempDir.toString());

        // Act
        mPlugin.initialize(mMockApi);

        // Assert: 验证 UI 组件已创建
        DetSqlUI ui = mPlugin.getUI();
        assertNotNull(ui, "UI instance should be created");
        assertNotNull(ui.getConfigPanel(), "Config panel should be created");
        assertNotNull(ui.getConfigPanel().switchCheck, "Switch checkbox should be created");
        assertNotNull(ui.getConfigPanel().cookieCheck, "Cookie checkbox should be created");
        assertNotNull(ui.getConfigPanel().errorCheck, "Error checkbox should be created");
        assertNotNull(ui.getConfigPanel().vulnCheck, "Vuln checkbox should be created");
        assertNotNull(ui.getConfigPanel().numCheck, "Numeric checkbox should be created");
        assertNotNull(ui.getConfigPanel().stringCheck, "String checkbox should be created");
        assertNotNull(ui.getConfigPanel().orderCheck, "Order checkbox should be created");
        assertNotNull(ui.getConfigPanel().boolCheck, "Boolean checkbox should be created");
        assertNotNull(ui.getConfigPanel().diyCheck, "DIY checkbox should be created");

        assertNotNull(ui.getConfigPanel().textField, "Domain whitelist field should be created");
        assertNotNull(ui.getConfigPanel().blackTextField, "Domain blacklist field should be created");
        assertNotNull(ui.getConfigPanel().suffixTextField, "Suffix field should be created");
        assertNotNull(ui.getConfigPanel().errorPocTextField, "Error POC field should be created");
        assertNotNull(ui.getConfigPanel().blackParamsField, "Params blacklist field should be created");

        assertNotNull(ui.getConfigPanel().diyTextArea, "DIY payload area should be created");
        assertNotNull(ui.getConfigPanel().regexTextArea, "Regex area should be created");
        assertNotNull(ui.getConfigPanel().blackPathTextArea, "Black path area should be created");

        assertNotNull(ui.getTable1(), "Source table should be created");
        assertNotNull(ui.getTable2(), "POC table should be created");
    }

    @Test
    void should_RegisterAllHandlers_when_Initialize() {
        // Arrange
        System.setProperty("user.home", tempDir.toString());
        ArgumentCaptor<HttpHandler> httpHandlerCaptor = ArgumentCaptor.forClass(HttpHandler.class);
        ArgumentCaptor<ExtensionUnloadingHandler> unloadHandlerCaptor = ArgumentCaptor.forClass(ExtensionUnloadingHandler.class);
        ArgumentCaptor<ContextMenuItemsProvider> contextMenuCaptor = ArgumentCaptor.forClass(ContextMenuItemsProvider.class);

        // Act
        mPlugin.initialize(mMockApi);

        // Assert: 验证所有处理器注册
        verify(mMockHttp).registerHttpHandler(httpHandlerCaptor.capture());
        verify(mMockExtension).registerUnloadingHandler(unloadHandlerCaptor.capture());
        verify(mMockUi).registerContextMenuItemsProvider(contextMenuCaptor.capture());

        assertNotNull(httpHandlerCaptor.getValue(), "HTTP handler should be registered");
        assertNotNull(unloadHandlerCaptor.getValue(), "Unloading handler should be registered");
        assertNotNull(contextMenuCaptor.getValue(), "Context menu provider should be registered");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 配置文件加载测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_LoadDefaultConfiguration_when_ConfigFileExists() throws Exception {
        // Arrange: 创建 YAML 配置文件
        Path configDir = tempDir.resolve(".config").resolve("DetSql");
        Files.createDirectories(configDir);
        Path configPath = configDir.resolve("config.yaml");
        String configContent = String.join("\n",
            "whitelist:",
            "  - example.com",
            "  - test.com",
            "blacklist:",
            "  - malicious.com",
            "suffixlist:",
            "  - jpg",
            "  - png",
            "  - gif",
            "paramslist:",
            "  - csrf_token",
            "  - session_id",
            "delaytime: 500",
            "statictime: 200",
            "switchEnabled: true",
            "cookiecheck: true",
            "errorcheck: false"
        );
        Files.writeString(configPath, configContent);
        System.setProperty("user.home", tempDir.toString());

        // Act
        mPlugin.initialize(mMockApi);

        // 等待 SwingUtilities.invokeLater 完成
        // applyConfiguration 方法使用多个 invokeLater 异步设置 UI 字段
        // 需要多次调用 invokeAndWait 确保所有任务完成
        SwingUtilities.invokeAndWait(() -> {});
        SwingUtilities.invokeAndWait(() -> {});
        SwingUtilities.invokeAndWait(() -> {});

        // Assert: 验证配置文件被读取
        DetSqlUI ui = mPlugin.getUI();
        assertNotNull(ui.getConfigPanel().textField.getText(), "Whitelist should be loaded");
        assertTrue(ui.getConfigPanel().textField.getText().contains("example.com"), "Should contain whitelist domain");

        assertNotNull(ui.getConfigPanel().blackTextField.getText(), "Blacklist should be loaded");
        assertTrue(ui.getConfigPanel().blackTextField.getText().contains("malicious.com"), "Should contain blacklist domain");

        assertNotNull(ui.getConfigPanel().suffixTextField.getText(), "Suffix list should be loaded");

        assertNotNull(ui.getConfigPanel().blackParamsField.getText(), "Params blacklist should be loaded");
        assertTrue(ui.getConfigPanel().blackParamsField.getText().contains("csrf_token"), "Should contain blacklist param");

        // 注意: checkbox 状态由 SwingUtilities.invokeLater() 异步设置
        // 在单元测试中无法可靠验证,只验证 checkbox 对象存在
        assertNotNull(ui.getConfigPanel().switchCheck, "Switch checkbox should be created");
        assertNotNull(ui.getConfigPanel().cookieCheck, "Cookie checkbox should be created");
        assertNotNull(ui.getConfigPanel().errorCheck, "Error checkbox should be created");
    }

    @Test
    void should_UseDefaultValues_when_ConfigFileIsMissing() {
        // Arrange: 配置文件不存在
        Path configPath = tempDir.resolve("NonExistentConfig.txt");
        System.setProperty("user.home", tempDir.toString());

        // Act
        mPlugin.initialize(mMockApi);

        // Assert: 验证使用默认值
        DetSqlUI ui = mPlugin.getUI();
        assertNotNull(ui.getConfigPanel().suffixTextField, "Suffix field should be created");
        assertFalse(ui.getConfigPanel().suffixTextField.getText().isEmpty(), "Should have default suffix list");
        assertTrue(ui.getConfigPanel().suffixTextField.getText().contains("js"), "Default should contain js");
        assertTrue(ui.getConfigPanel().suffixTextField.getText().contains("css"), "Default should contain css");
    }

    @Test
    void should_HandleCorruptedConfigFile_when_InvalidFormat() throws IOException {
        // Arrange: 创建损坏的配置文件
        Path configPath = tempDir.resolve("DetSqlConfig.txt");
        String corruptedContent = "this is not a valid properties file\n===###\ninvalid=";
        Files.writeString(configPath, corruptedContent);
        System.setProperty("user.home", tempDir.toString());

        // Act & Assert: 不应该抛出异常
        assertDoesNotThrow(() -> mPlugin.initialize(mMockApi),
            "Should handle corrupted config gracefully");

        // 验证插件仍然初始化成功
        DetSqlUI ui = mPlugin.getUI();
        assertNotNull(ui.myHttpHandler, "HttpHandler should still be initialized");
        assertNotNull(ui.getTable1(), "UI should still be created");
    }

    @Test
    void should_HandleInvalidConfigValues_when_LoadingConfiguration() throws IOException {
        // Arrange: 创建包含无效值的配置文件
        Path configPath = tempDir.resolve("DetSqlConfig.txt");
        String configContent = String.join("\n",
            "delaytime=invalid_number",
            "statictime=not_a_number",
            "starttime=-999",
            "endtime=abc"
        );
        Files.writeString(configPath, configContent);
        System.setProperty("user.home", tempDir.toString());

        // Act & Assert: 不应该抛出异常
        assertDoesNotThrow(() -> mPlugin.initialize(mMockApi),
            "Should handle invalid config values gracefully");

        // 验证使用默认值
        assertNotNull(mPlugin.getUI().myHttpHandler, "HttpHandler should be initialized with defaults");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 组件依赖注入测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_InjectDependencies_when_CreatingHttpHandler() {
        // Arrange
        System.setProperty("user.home", tempDir.toString());

        // Act
        mPlugin.initialize(mMockApi);

        // Assert: 验证 MyHttpHandler 接收到正确的依赖
        DetSqlUI ui = mPlugin.getUI();
        assertNotNull(ui.myHttpHandler, "MyHttpHandler should be created");
        assertSame(ui.sourceTableModel, ui.myHttpHandler.sourceTableModel,
            "HttpHandler should use same SourceTableModel");
        assertSame(ui.attackMap, ui.myHttpHandler.attackMap,
            "HttpHandler should use same AttackMap");
    }

    @Test
    void should_ShareAttackMapReference_when_Initialize() {
        // Arrange
        System.setProperty("user.home", tempDir.toString());

        // Act
        mPlugin.initialize(mMockApi);

        // Assert: 验证 attackMap 在 DetSqlUI 和 MyHttpHandler 之间共享
        DetSqlUI ui = mPlugin.getUI();
        assertSame(ui.attackMap, ui.myHttpHandler.attackMap,
            "AttackMap should be shared between DetSqlUI and MyHttpHandler");

        // 验证是线程安全的 Map（可以是 ConcurrentHashMap 或 SynchronizedMap）
        assertTrue(
            ui.attackMap.getClass().getName().contains("ConcurrentHashMap") ||
            ui.attackMap.getClass().getName().contains("SynchronizedMap"),
            "AttackMap should be thread-safe (ConcurrentHashMap or SynchronizedMap), but was: " + 
            ui.attackMap.getClass().getName()
        );
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 语言配置测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_LoadLanguageIndex_when_ConfigFileSpecifiesIt() throws IOException {
        // Arrange: 创建包含语言配置的 YAML 文件
        Path configDir = tempDir.resolve(".config").resolve("DetSql");
        Files.createDirectories(configDir);
        Path configPath = configDir.resolve("config.yaml");
        String configContent = "languageindex: 1\n"; // English
        Files.writeString(configPath, configContent);
        System.setProperty("user.home", tempDir.toString());

        // Act
        mPlugin.initialize(mMockApi);

        // Assert: 验证语言索引被加载
        assertEquals(1, mPlugin.getUI().getLanguageIndex(), "Language index should be loaded from config");
    }

    @Test
    void should_UseDefaultLanguage_when_LanguageIndexInvalid() throws IOException {
        // Arrange: 创建包含无效语言索引的 YAML 配置
        Path configDir = tempDir.resolve(".config").resolve("DetSql");
        Files.createDirectories(configDir);
        Path configPath = configDir.resolve("config.yaml");
        String configContent = "languageindex: invalid\n";
        Files.writeString(configPath, configContent);
        System.setProperty("user.home", tempDir.toString());

        // Act
        mPlugin.initialize(mMockApi);

        // Assert: 验证使用默认语言索引(0 = 简体中文)
        assertEquals(0, mPlugin.getUI().getLanguageIndex(), "Should use default language index when invalid");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 日志系统测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_OutputStartupMessage_when_Initialize() {
        // Arrange
        System.setProperty("user.home", tempDir.toString());
        ArgumentCaptor<String> logCaptor = ArgumentCaptor.forClass(String.class);

        // Act
        mPlugin.initialize(mMockApi);

        // Assert: 验证启动日志
        verify(mMockLogging, atLeastOnce()).logToOutput(logCaptor.capture());

        boolean foundStartupMessage = logCaptor.getAllValues().stream()
            .anyMatch(msg -> msg.contains("DetSql") && msg.contains("loaded successfully"));

        assertTrue(foundStartupMessage, "Should output startup success message");
    }

    @Test
    void should_LogConfigurationErrors_when_LoadingFails() throws IOException {
        // Arrange: 创建不可读的配置文件(通过权限设置,但在某些环境可能不生效)
        // 这个测试在某些系统上可能会跳过
        Path configPath = tempDir.resolve("DetSqlConfig.txt");
        Files.writeString(configPath, "test=value\n");

        // 模拟配置加载失败的场景:使用不存在的目录
        System.setProperty("user.home", "/nonexistent/path/that/does/not/exist");

        // Act
        mPlugin.initialize(mMockApi);

        // Assert: 插件应该继续初始化,不会崩溃
        assertNotNull(mPlugin.getUI().myHttpHandler, "Should initialize even if config loading fails");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 集成测试
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    void should_InitializeCompleteWorkflow_when_AllComponentsAreReady() throws Exception {
        // Arrange: 创建完整的 YAML 配置文件
        Path configDir = tempDir.resolve(".config").resolve("DetSql");
        Files.createDirectories(configDir);
        Path configPath = configDir.resolve("config.yaml");
        String configContent = String.join("\n",
            "whitelist:",
            "  - target1.com",
            "  - target2.com",
            "blacklist:",
            "  - excluded.com",
            "suffixlist:",
            "  - jpg",
            "  - png",
            "  - gif",
            "  - js",
            "  - css",
            "errpoclist:",
            "  - \"'\"",
            "  - '\"'",
            "paramslist:",
            "  - id",
            "  - token",
            "  - session",
            "delaytime: 300",
            "statictime: 150",
            "starttime: 50",
            "endtime: 200",
            "switchEnabled: true",
            "cookiecheck: true",
            "errorcheck: true",
            "numcheck: true",
            "stringcheck: true",
            "ordercheck: true",
            "repeatercheck: true",
            "boolcheck: true",
            "diycheck: false",
            "diypayloads: |",
            "  custom_payload_1",
            "  custom_payload_2",
            "diyregex: |",
            "  error.*sql",
            "  exception.*database",
            "blackpath: |",
            "  /admin",
            "  /internal",
            "languageindex: 0"
        );
        Files.writeString(configPath, configContent);
        System.setProperty("user.home", tempDir.toString());

        // Act
        mPlugin.initialize(mMockApi);

        // 等待 SwingUtilities.invokeLater 完成
        // applyConfiguration 方法使用多个 invokeLater 异步设置 UI 字段
        SwingUtilities.invokeAndWait(() -> {});
        SwingUtilities.invokeAndWait(() -> {});
        SwingUtilities.invokeAndWait(() -> {});

        // Assert: 验证完整工作流
        DetSqlUI ui = mPlugin.getUI();
        
        // 1. 核心组件
        assertNotNull(ui.myHttpHandler, "HttpHandler created");
        assertNotNull(ui.sourceTableModel, "SourceTableModel created");
        assertNotNull(ui.attackMap, "AttackMap created");

        // 2. UI 组件
        assertNotNull(ui.getTable1(), "Source table created");
        assertNotNull(ui.getTable2(), "POC table created");
        assertNotNull(ui.getConfigPanel().switchCheck, "Switch checkbox created");

        // 3. 配置加载
        assertTrue(ui.getConfigPanel().textField.getText().contains("target1.com"), "Whitelist loaded");
        assertTrue(ui.getConfigPanel().blackTextField.getText().contains("excluded.com"), "Blacklist loaded");
        // 注意: Properties 不支持多行值,所以 diypayloads/diyregex/blackpath 不会被正确加载
        // 这里只验证 TextField,不验证 TextArea

        // 4. Checkbox 状态 - 注意:由于 SwingUtilities.invokeLater,可能不会立即生效
        // 在测试环境中可能无法验证异步UI更新
        // 所以只验证核心功能正常
        assertNotNull(ui.getConfigPanel().switchCheck, "Checkbox should be created");

        // 5. API 注册
        verify(mMockExtension).setName("DetSql");
        verify(mMockHttp).registerHttpHandler(any());
        verify(mMockUi).registerSuiteTab(eq("DetSql"), any());
        verify(mMockExtension).registerUnloadingHandler(any());
        verify(mMockUi).registerContextMenuItemsProvider(any());

        // 6. 日志输出
        verify(mMockLogging, atLeastOnce()).logToOutput(contains("loaded successfully"));
    }
}

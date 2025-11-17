/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.utilities.CryptoUtils;
import burp.api.montoya.utilities.DigestAlgorithm;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang3.StringEscapeUtils;

import javax.swing.*;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

import javax.swing.event.MouseInputListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Element;

public class DetSql implements BurpExtension, ContextMenuItemsProvider{
    MontoyaApi api;
    public MyHttpHandler myHttpHandler;
    public SourceTableModel sourceTableModel;
    public ConcurrentHashMap<String, List<PocLogEntry>> attackMap;
    private DetSqlConfig config; // 统一配置管理对象
    private DetSqlLogger logger; // 日志系统
    private Statistics statistics; // 统计系统
    private BindingContext bindingContext; // UI绑定上下文
    public static JCheckBox switchCheck;
    public static JCheckBox cookieCheck;
    public static JCheckBox errorCheck;//
    public static JCheckBox vulnCheck;
    public static JTable table1;
    public static JTable table2;
    // Stats labels
    private JLabel statsTestedLabel;
    private JLabel statsVulnLabel;
    private javax.swing.Timer statsTimer;
    //补充4个
    public static JCheckBox numCheck;//
    public static JCheckBox stringCheck;//
    public static JCheckBox orderCheck;//
    public static JCheckBox boolCheck;//

    public static JCheckBox diyCheck;//

    public static JTextField textField;
    public static JTextField blackTextField;
    public static JTextField suffixTextField;
    public static JTextField errorPocTextField;
    //新加参数黑名单框
    public static JTextField blackParamsField;
    public static JTextField whiteParamsField;
    public static JTextField configTextField;
    public static JTextArea diyTextArea;
    public static JTextArea regexTextArea;
    public static JTextArea blackPathTextArea;
    public static JTextField timeTextField;
    public static JTextField staticTimeTextField;
    public static JTextField startTimeTextField;
    public static JTextField endTimeTextField;
    public ResourceBundle messages;
    public JComboBox<String> languageComboBox;
    private static final String[] LANGUAGES = {"简体中文","English" };
    private static final Locale[] LOCALES = {new Locale("zh", "CN"),new Locale("en", "US") };
    public static int index;

    // UI Layout Constants
    private static final int FILE_CHOOSER_WIDTH = 800;
    private static final int FILE_CHOOSER_HEIGHT = 600;

    // Top Bar and Tab Layout Constants
    private static final int TOP_BAR_MAX_HEIGHT = 40;     // Maximum height of the top bar containing tabs and stats
    private static final int TAB_STRIP_HEIGHT = 36;        // Height of the tab strip to ensure single-row layout

    // SpringLayout Padding Constants
    private static final int PADDING_SMALL = 10;           // Standard small padding
    private static final int PADDING_MEDIUM = 15;          // Medium padding (tool component)
    private static final int PADDING_COMPONENT = 35;       // Spacing between components
    private static final int PADDING_SPECIAL = 25;         // Special case horizontal spacing
    private static final int PADDING_CENTER_OFFSET = 90;   // Horizontal center offset
    private static final int PADDING_BUTTON = 100;         // Button spacing
    private static final int PADDING_LARGE = 200;          // Large spacing (config buttons)

    // Component Size Constants
    private static final int TEXTFIELD_COLUMNS = 30;       // Standard TextField column count
    private static final int TEXTAREA_ROWS_SMALL = 5;      // Small TextArea row count
    private static final int TEXTAREA_ROWS_MEDIUM = 6;     // Medium TextArea row count
    private static final int TEXTAREA_ROWS_REGULAR = 10;   // Regular TextArea row count
    private static final int TEXTAREA_ROWS_LARGE = 14;     // Large TextArea row count
    private static final int TEXTAREA_ROWS_XLARGE = 20;    // Extra large TextArea row count
    private static final int TEXTAREA_ROWS_XXLARGE = 30;   // Extra extra large TextArea row count

    // JSplitPane Constants
    private static final double SPLITPANE_RESIZE_WEIGHT = 0.5;

    private Set<String> readLinesFromTextArea(JTextArea textArea) {
        Set<String> result = new HashSet<>();
        Element paragraph = textArea.getDocument().getDefaultRootElement();
        int contentCount = paragraph.getElementCount();
        for (int i = 0; i < contentCount; i++) {
            Element ee = paragraph.getElement(i);
            int rangeStart = ee.getStartOffset();
            int rangeEnd = ee.getEndOffset();
            try {
                String line = textArea.getText(rangeStart, rangeEnd - rangeStart)
                        .replaceFirst("[\n\r]+$", "");
                if (!line.isBlank()) {
                    result.add(line);
                }
            } catch (BadLocationException ex) {
                throw new RuntimeException(ex);
            }
        }
        return result;
    }

    private int parseIntWithDefault(String value, int defaultValue) {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    // Derive JSON-safe error payloads from user-provided list
    private static String[] deriveJsonErrPocs(String[] base) {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        for (String s : base) {
            if (s == null) continue;

            // 1. 原始payload
            out.add(s);

            // 2. 转义双引号（JSON字符串内安全）
            if (s.contains("\"")) {
                out.add(s.replace("\"", "\\\""));
            }

            // 3. Unicode编码（绕过某些WAF）
            if (s.contains("\"")) {
                out.add(s.replace("\"", "\\u0022"));
            }
            if (s.contains("'")) {
                out.add(s.replace("'", "\\u0027"));
            }
        }
        return out.toArray(new String[0]);
    }

    /**
     * Parse Set property from Properties
     * @param prop Properties object
     * @param key Property key
     * @param defaultValue Default value if property is blank
     * @return Parsed Set
     */
    private Set<String> parseSetProperty(Properties prop, String key, Set<String> defaultValue) {
        String value = prop.getProperty(key, "");
        if (value.isBlank()) {
            return defaultValue;
        }
        return parseDelimitedString(value);
    }

    /**
     * Parse delimited string into Set (with trim and empty filter)
     * SECURITY: This method ensures no trailing/leading spaces in parsed tokens
     * to prevent filter bypass vulnerabilities.
     *
     * @param input Input string with pipe-delimited tokens (e.g., "jpg | png | gif")
     * @return Set of trimmed, non-empty tokens
     */
    private static Set<String> parseDelimitedString(String input) {
        if (input == null || input.isBlank()) {
            return new HashSet<>();
        }
        return Arrays.stream(input.split("\\|"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(java.util.stream.Collectors.toSet());
    }

    /**
     * Update all UI component labels with current language bundle
     * @param topicLabel Domain whitelist label
     * @param blackLabel Domain blacklist label
     * @param suffixLabel Suffix label
     * @param errorPocLabel Error POC label
     * @param blackParams Parameter blacklist label
     * @param diyLabel DIY payloads label
     * @param resRegexLabel Response regex label
     * @param timeLabel Delay time label
     * @param staticTimeLabel Static time label
     * @param startTimeLabel Start time label
     * @param blackPathLabel Black path label
     * @param conBt Confirm button
     * @param loadBt Load button
     * @param saveBt Save button
     * @param languageLabel Language label
     * @param configLabel Config directory label
     */
    private void updateLanguageLabels(
            JLabel topicLabel, JLabel blackLabel, JLabel suffixLabel, JLabel errorPocLabel,
            JLabel blackParams, JLabel diyLabel, JLabel resRegexLabel, JLabel timeLabel,
            JLabel staticTimeLabel, JLabel startTimeLabel, JLabel blackPathLabel,
            JButton conBt, JButton loadBt, JButton saveBt,
            JLabel languageLabel, JLabel configLabel) {

        topicLabel.setText(messages.getString("Domainwhitelisting"));
        blackLabel.setText(messages.getString("Domainblacklisting"));
        suffixLabel.setText(messages.getString("Prohibitsuffixing"));
        errorPocLabel.setText(messages.getString("ErrorTypePOCing"));
        blackParams.setText(messages.getString("Parameterblacklisting"));
        switchCheck.setText(messages.getString("checkbox.switch"));
        cookieCheck.setText(messages.getString("checkbox.Testcookies"));
        vulnCheck.setText(messages.getString("checkbox.Acceptrepeater"));
        errorCheck.setText(messages.getString("checkbox.Testerrortype"));
        numCheck.setText(messages.getString("checkbox.Testnumericaltypes"));
        stringCheck.setText(messages.getString("checkbox.Teststringtype"));
        orderCheck.setText(messages.getString("checkbox.Testordertype"));
        boolCheck.setText(messages.getString("checkbox.Testbooleantype"));
        diyCheck.setText(messages.getString("checkbox.Testdiypayloads"));
        diyLabel.setText(messages.getString("CustomizePayloadsing"));
        resRegexLabel.setText(messages.getString("ResponsetoRegularmatchingrulesing"));
        timeLabel.setText(messages.getString("ResponsetoDelaytimeing"));
        staticTimeLabel.setText(messages.getString("Fixedintervalbetweenrequestsing"));
        startTimeLabel.setText(messages.getString("Requestsintervalrangeing"));
        blackPathLabel.setText(messages.getString("Pathblacklisting"));
        conBt.setText(messages.getString("button.confirm"));
        loadBt.setText(messages.getString("button.load"));
        saveBt.setText(messages.getString("button.save"));
        languageLabel.setText(messages.getString("languageing"));
        configLabel.setText(messages.getString("configuredirectorying"));
    }

    /**
     * Build Properties object from current UI configuration
     * @return Properties object containing all configuration values
     */
    static Properties buildConfigProperties() {
        Properties prop = new Properties();
        prop.setProperty("whitelist", DetSql.textField.getText());
        prop.setProperty("blacklist", DetSql.blackTextField.getText());
        prop.setProperty("suffixlist", DetSql.suffixTextField.getText());
        prop.setProperty("errpoclist", DetSql.errorPocTextField.getText());
        prop.setProperty("paramslist", DetSql.blackParamsField.getText());
        prop.setProperty("delaytime", DetSql.timeTextField.getText());
        prop.setProperty("statictime", DetSql.staticTimeTextField.getText());
        prop.setProperty("starttime", DetSql.startTimeTextField.getText());
        prop.setProperty("endtime", DetSql.endTimeTextField.getText());
        prop.setProperty("switch", String.valueOf(DetSql.switchCheck.isSelected()));
        prop.setProperty("cookiecheck", String.valueOf(DetSql.cookieCheck.isSelected()));
        prop.setProperty("errorcheck", String.valueOf(DetSql.errorCheck.isSelected()));
        prop.setProperty("numcheck", String.valueOf(DetSql.numCheck.isSelected()));
        prop.setProperty("stringcheck", String.valueOf(DetSql.stringCheck.isSelected()));
        prop.setProperty("ordercheck", String.valueOf(DetSql.orderCheck.isSelected()));
        prop.setProperty("repeatercheck", String.valueOf(DetSql.vulnCheck.isSelected()));
        prop.setProperty("boolcheck", String.valueOf(DetSql.boolCheck.isSelected()));
        prop.setProperty("diycheck", String.valueOf(DetSql.diyCheck.isSelected()));
        prop.setProperty("diypayloads", DetSql.diyTextArea.getText());
        prop.setProperty("diyregex", DetSql.regexTextArea.getText());
        prop.setProperty("blackpath", DetSql.blackPathTextArea.getText());
        prop.setProperty("languageindex", String.valueOf(DetSql.index));
        return prop;
    }

    /**
     * Load configuration from file
     * @param configFile Configuration file
     */
    private void loadConfiguration(File configFile) {
        if (!configFile.exists()) {
            return;
        }

        try (java.io.InputStreamReader fileReader = new java.io.InputStreamReader(new java.io.FileInputStream(configFile), java.nio.charset.StandardCharsets.UTF_8)) {
            Properties prop = new Properties();
            prop.load(fileReader);
            applyConfiguration(prop);
        } catch (IOException ex) {
            api.logging().logToError("Configuration loading failed: " + ex.getMessage());
        }
    }

    /**
     * Apply Properties configuration to UI and static variables
     * @param prop Properties object
     */
    private void applyConfiguration(Properties prop) {
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 1. List-type configuration (separated by "|")
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        MyFilterRequest.whiteListSet = parseSetProperty(prop, "whitelist", new HashSet<>());
        MyFilterRequest.blackListSet = parseSetProperty(prop, "blacklist", new HashSet<>());
        MyFilterRequest.blackParamsSet = parseSetProperty(prop, "paramslist", new HashSet<>());

        String suffixProp = prop.getProperty("suffixlist", "").trim();
        if (suffixProp.isBlank()) {
            MyFilterRequest.unLegalExtensionSet = new HashSet<>(DefaultConfig.DEFAULT_SUFFIX_SET);
        } else {
            MyFilterRequest.unLegalExtensionSet = parseDelimitedString(suffixProp);
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 2. UI text field configuration
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        javax.swing.SwingUtilities.invokeLater(() -> {
            if (textField != null) textField.setText(prop.getProperty("whitelist", ""));
            if (blackTextField != null) blackTextField.setText(prop.getProperty("blacklist", ""));
            if (suffixTextField != null) suffixTextField.setText(prop.getProperty("suffixlist", DefaultConfig.DEFAULT_SUFFIX_LIST));
            if (errorPocTextField != null) errorPocTextField.setText(prop.getProperty("errpoclist", ""));
            if (blackParamsField != null) blackParamsField.setText(prop.getProperty("paramslist", ""));
            if (timeTextField != null) timeTextField.setText(prop.getProperty("delaytime", ""));
            if (staticTimeTextField != null) staticTimeTextField.setText(prop.getProperty("statictime", "100"));
            if (startTimeTextField != null) startTimeTextField.setText(prop.getProperty("starttime", "0"));
            if (endTimeTextField != null) endTimeTextField.setText(prop.getProperty("endtime", "0"));
            if (diyTextArea != null) diyTextArea.setText(prop.getProperty("diypayloads", ""));
            if (regexTextArea != null) regexTextArea.setText(prop.getProperty("diyregex", ""));
            if (blackPathTextArea != null) blackPathTextArea.setText(prop.getProperty("blackpath", ""));
        });

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 3. Integer configuration - 迁移到 DetSqlConfig
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        config.setDelayTimeMs(parseIntWithDefault(prop.getProperty("delaytime", ""), DefaultConfig.DEFAULT_DELAY_TIME_MS));
        config.setStaticTimeMs(parseIntWithDefault(prop.getProperty("statictime", ""), DefaultConfig.DEFAULT_STATIC_TIME_MS));
        config.setStartTimeMs(parseIntWithDefault(prop.getProperty("starttime", ""), DefaultConfig.DEFAULT_START_TIME_MS));
        config.setEndTimeMs(parseIntWithDefault(prop.getProperty("endtime", ""), DefaultConfig.DEFAULT_END_TIME_MS));

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 4. Checkbox configuration
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        javax.swing.SwingUtilities.invokeLater(() -> {
            if (switchCheck != null) switchCheck.setSelected(Boolean.parseBoolean(prop.getProperty("switch")));
            if (cookieCheck != null) cookieCheck.setSelected(Boolean.parseBoolean(prop.getProperty("cookiecheck")));
            if (errorCheck != null) errorCheck.setSelected(Boolean.parseBoolean(prop.getProperty("errorcheck")));
            if (vulnCheck != null) vulnCheck.setSelected(Boolean.parseBoolean(prop.getProperty("repeatercheck")));
            if (numCheck != null) numCheck.setSelected(Boolean.parseBoolean(prop.getProperty("numcheck")));
            if (stringCheck != null) stringCheck.setSelected(Boolean.parseBoolean(prop.getProperty("stringcheck")));
            if (orderCheck != null) orderCheck.setSelected(Boolean.parseBoolean(prop.getProperty("ordercheck")));
            if (boolCheck != null) boolCheck.setSelected(Boolean.parseBoolean(prop.getProperty("boolcheck")));
            if (diyCheck != null) diyCheck.setSelected(Boolean.parseBoolean(prop.getProperty("diycheck")));
        });

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 5. Error Payload configuration - 迁移到 DetSqlConfig
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        String errPocList = prop.getProperty("errpoclist", "");
        if (errPocList.isBlank()) {
            config.setErrorPayloads(DefaultConfig.DEFAULT_ERR_POCS.clone());
            config.setErrorPayloadsJson(DefaultConfig.DEFAULT_ERR_POCS_JSON.clone());
        } else {
            config.setErrorPayloads(errPocList.split("\\|"));
            // 对 JSON/XML 使用安全变体
            config.setErrorPayloadsJson(deriveJsonErrPocs(config.getErrorPayloads()));
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 6. TextArea configuration (requires special handling) - 迁移到 DetSqlConfig
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if (!prop.getProperty("diypayloads", "").isBlank()) {
            config.setDiyPayloads(readLinesFromTextArea(diyTextArea));
        } else {
            config.setDiyPayloads(new HashSet<>());
        }

        if (!prop.getProperty("diyregex", "").isBlank()) {
            config.setDiyRegexs(readLinesFromTextArea(regexTextArea));
        } else {
            config.setDiyRegexs(new HashSet<>());
        }

        if (!prop.getProperty("blackpath", "").isBlank()) {
            MyFilterRequest.blackPathSet = readLinesFromTextArea(blackPathTextArea);
        } else {
            MyFilterRequest.blackPathSet.clear();
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 7. Language index (optional, only load if present)
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        String languageIndexStr = prop.getProperty("languageindex", null);
        if (languageIndexStr != null) {
            index = parseIntWithDefault(languageIndexStr, 0);
        }
    }

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        api.extension().setName("DetSql");

        // 创建配置对象并加载配置文件
        String configPath = System.getProperty("user.home") + File.separator + "DetSqlConfig.txt";
        File configFile = new File(configPath);
        this.config = new DetSqlConfig();

        try {
            config.load(configPath);
        } catch (Exception ex) {
            api.logging().logToError("Configuration loading failed: " + ex.getMessage());
        }

        // 加载语言索引 (用于UI显示)
        if (configFile.exists()) {
            Properties prop = new Properties();
            try (java.io.InputStreamReader fileReader = new java.io.InputStreamReader(
                    new java.io.FileInputStream(configPath), java.nio.charset.StandardCharsets.UTF_8)) {
                prop.load(fileReader);
                index = parseIntWithDefault(prop.getProperty("languageindex", "0"), 0);
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }

        // 创建日志和统计系统
        this.logger = new DetSqlLogger(api);
        // 日志级别由系统属性 detsql.log.level 控制，默认为 OFF
        // 可通过 -Ddetsql.log.level=INFO 在运行时启用
        this.statistics = new Statistics();

        sourceTableModel = new SourceTableModel();
        PocTableModel pocTableModel = new PocTableModel();
        Component component = getComponent(sourceTableModel, pocTableModel);
        api.userInterface().registerSuiteTab("DetSql", component);
        attackMap = new ConcurrentHashMap<>();
        myHttpHandler = new MyHttpHandler(api, sourceTableModel, pocTableModel, attackMap, config, logger, statistics);
        api.http().registerHttpHandler(myHttpHandler);
        api.extension().registerUnloadingHandler(new MyExtensionUnloadingHandler());
        api.userInterface().registerContextMenuItemsProvider(this);

        if (configFile.exists()) {
            configTextField.setText(configFile.getAbsolutePath());
        }
        loadConfiguration(configFile);

        // 使用新的日志系统 - 启动信息始终输出
        logger.always("################################################");
        logger.always("[#]  DetSql v3.3.0 loaded successfully");
        logger.always("[#]  Author: saoshao");
        logger.always("[#]  Email: 1224165231@qq.com");
        logger.always("[#]  Github: https://github.com/saoshao/DetSql");
        logger.always("[#]  Logging system: " + (logger.getLogLevel() == LogLevel.OFF ? "DISABLED" : "ENABLED (Level: " + logger.getLogLevel() + ")"));
        logger.always("[#]  Statistics tracking: ENABLED");
        logger.always("################################################");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> listMenuItems = new ArrayList<>();
        JMenu jMenu2 = new JMenu("DetSql");
        JMenuItem menuItem2 = new JMenuItem("End this data");
        JMenuItem menuItem3 = new JMenuItem("Send to DetSql");

        listMenuItems.add(jMenu2);
        jMenu2.add(menuItem3);
        jMenu2.add(menuItem2);
        menuItem2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                HttpRequestResponse selectHttpRequestResponse = event.messageEditorRequestResponse().get().requestResponse();
                CryptoUtils cryptoUtils = api.utilities().cryptoUtils();
                String requestSm3Hash = MyHttpHandler.byteToHex(cryptoUtils.generateDigest(ByteArray.byteArray(MyFilterRequest.getUnique(selectHttpRequestResponse)), DigestAlgorithm.SM3).getBytes());
                Thread currentThread = null;
                for (Map.Entry<Thread, StackTraceElement[]> entry : Thread.getAllStackTraces().entrySet()) {
                    if (entry.getKey().getName().equals(requestSm3Hash)) {
                        currentThread = entry.getKey();
                        currentThread.interrupt();
                        break;
                    }
                }
            }
        });
        menuItem3.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                HttpRequestResponse selectHttpRequestResponse = event.messageEditorRequestResponse().get().requestResponse();
                myHttpHandler.createProcessThread(selectHttpRequestResponse);
            }
        });
        return listMenuItems;
    }

    private Component getComponent(SourceTableModel tableModel, PocTableModel pocTableModel) {
        JPanel root = new JPanel();
        JTabbedPane tabbedPane1 = new JTabbedPane();
        tabbedPane1.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        JSplitPane splitPane1 = new JSplitPane();
        JSplitPane splitPane2 = new JSplitPane();
        JScrollPane scrollPane1 = new JScrollPane();
        JScrollPane scrollPane2 = new JScrollPane();
        JSplitPane splitPane3 = new JSplitPane();
        UserInterface userInterface = api.userInterface();
        HttpRequestEditor requestViewer = userInterface.createHttpRequestEditor(READ_ONLY);
        HttpResponseEditor responseViewer = userInterface.createHttpResponseEditor(READ_ONLY);
        JTabbedPane tabbedPane2 = new JTabbedPane();
        JPanel finRoot = new JPanel();
        SpringLayout springLayout = new SpringLayout();
        finRoot.setLayout(springLayout);
        finRoot.add(requestViewer.uiComponent());
        springLayout.putConstraint(SpringLayout.NORTH, requestViewer.uiComponent(), 0, SpringLayout.NORTH, finRoot);
        springLayout.putConstraint(SpringLayout.WEST, requestViewer.uiComponent(), 0, SpringLayout.WEST, finRoot);
        springLayout.putConstraint(SpringLayout.EAST, requestViewer.uiComponent(), 0, SpringLayout.EAST, finRoot);
        springLayout.putConstraint(SpringLayout.SOUTH, requestViewer.uiComponent(), 0, SpringLayout.SOUTH, finRoot);
        tabbedPane2.addTab("Request", finRoot);

        JTabbedPane tabbedPane3 = new JTabbedPane();
        JPanel rfinRoot = new JPanel();
        SpringLayout rspringLayout = new SpringLayout();
        rfinRoot.setLayout(rspringLayout);
        rfinRoot.add(responseViewer.uiComponent());
        rspringLayout.putConstraint(SpringLayout.NORTH, responseViewer.uiComponent(), 0, SpringLayout.NORTH, rfinRoot);
        rspringLayout.putConstraint(SpringLayout.WEST, responseViewer.uiComponent(), 0, SpringLayout.WEST, rfinRoot);
        rspringLayout.putConstraint(SpringLayout.EAST, responseViewer.uiComponent(), 0, SpringLayout.EAST, rfinRoot);
        rspringLayout.putConstraint(SpringLayout.SOUTH, responseViewer.uiComponent(), 0, SpringLayout.SOUTH, rfinRoot);
        tabbedPane3.addTab("Response", rfinRoot);
        table1 = new JTable(tableModel) {
            @Override
            public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
                SourceLogEntry logEntry = tableModel.get(DetSql.table1.convertRowIndexToModel(rowIndex));
                if (logEntry.getHttpRequestResponse() != null) {
                    requestViewer.setRequest(logEntry.getHttpRequestResponse().request());
                    responseViewer.setResponse(logEntry.getHttpRequestResponse().response());
                    super.changeSelection(rowIndex, columnIndex, toggle, extend);
                    String sm3Hash = logEntry.getMyHash();
                    List<PocLogEntry> pocLogEntries = myHttpHandler.attackMap.get(sm3Hash);
                    pocTableModel.replaceAll(pocLogEntries);
                }else{
                    requestViewer.setRequest(HttpRequest.httpRequest());
                    super.changeSelection(rowIndex, columnIndex, toggle, extend);
                }



            }
        };
        //table1.setRowSorter(null);
//        if(tableModel.getRowCount()>0){
//            table1.setAutoCreateRowSorter(true);
//            tableModel.fireTableDataChanged();
//        }

//        //设置点击表头，数据自动排序
        TableRowSorter<SourceTableModel> sorter = new TableRowSorter<>(tableModel);
//        //获得列的数量
//        //int columnCount = tableModel.getColumnCount();
//            //这里可以根据需要修改
        sorter.setComparator(0, new Comparator<Object>() {
            @Override
            public int compare(Object o1, Object o2) {
                String str1 = o1.toString();
                String str2 = o2.toString();
                return Integer.compare(parseIntWithDefault(str1, 0), parseIntWithDefault(str2, 0));
            }
        });
        sorter.setComparator(5, new Comparator<Object>() {
            @Override
            public int compare(Object o1, Object o2) {
                String str1 = o1.toString();
                String str2 = o2.toString();
                return Integer.compare(parseIntWithDefault(str1, 0), parseIntWithDefault(str2, 0));
            }
        });
//
        table1.setRowSorter(sorter);
        table1.setEnabled(true);
        table1.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        
        // 设置列宽自适应 - 为不同列设置合理的首选宽度
        table1.getColumnModel().getColumn(0).setPreferredWidth(50);   // # (ID)
        table1.getColumnModel().getColumn(1).setPreferredWidth(80);   // Tool
        table1.getColumnModel().getColumn(2).setPreferredWidth(80);   // Method
        table1.getColumnModel().getColumn(3).setPreferredWidth(150);  // Host
        table1.getColumnModel().getColumn(4).setPreferredWidth(300);  // URL
        table1.getColumnModel().getColumn(5).setPreferredWidth(100);  // BodyLength
        table1.getColumnModel().getColumn(6).setPreferredWidth(120);  // VulnState
        
        final JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem menuItem1 = new JMenuItem("delete selected rows");
        JMenuItem menuItem2 = new JMenuItem("delete novuln history");
        JMenuItem exportBurpLog = new JMenuItem("Export selected original requests (Burp log)");
        JMenuItem copyParams = new JMenuItem("Copy vulnerable parameters from selected");
        popupMenu.add(menuItem1);
        popupMenu.add(menuItem2);
        popupMenu.addSeparator();
        popupMenu.add(exportBurpLog);
        popupMenu.add(copyParams);
        
        // delete selected rows
        menuItem1.addActionListener(e -> {
            int[] selectedRows = table1.getSelectedRows();
            for (int i = selectedRows.length - 1; i >= 0; i--) {
                int viewIndex = selectedRows[i];
                int modelIndex = table1.convertRowIndexToModel(viewIndex);
                Object state = sourceTableModel.getValueAt(modelIndex, 6);
                if (!"run".equals(state)){
                    // remove attackMap entry for this row if present
                    try {
                        SourceLogEntry entry = sourceTableModel.get(modelIndex);
                        if (entry != null && entry.getMyHash() != null && myHttpHandler != null && myHttpHandler.attackMap != null) {
                            myHttpHandler.attackMap.remove(entry.getMyHash());
                        }
                    } catch (Exception ignore) {}
                    // remove row from model using indexed removal
                    sourceTableModel.remove(modelIndex);
                }
            }
        });
        // delete novuln history
        menuItem2.addActionListener(e -> {
            for (int i = sourceTableModel.getRowCount() - 1; i >= 0; i--) {
                int modelIndex = table1.convertRowIndexToModel(i);
                Object state = sourceTableModel.getValueAt(modelIndex,6);
                if (state != null && (state.toString().isEmpty() || "手动停止".equals(state))){
                    try {
                        SourceLogEntry entry = sourceTableModel.get(modelIndex);
                        if (entry != null && entry.getMyHash() != null && myHttpHandler != null && myHttpHandler.attackMap != null) {
                            myHttpHandler.attackMap.remove(entry.getMyHash());
                        }
                    } catch (Exception ignore) {}
                    sourceTableModel.remove(modelIndex);
                }
            }
        });

// export selected source requests as Burp log (from table1 selection)
exportBurpLog.addActionListener(e -> {
    int[] selectedRows = table1.getSelectedRows();
    if (selectedRows == null || selectedRows.length == 0) return;

    javax.swing.JFileChooser fileChooser = new javax.swing.JFileChooser();
    fileChooser.setSelectedFile(new java.io.File("burp_log.txt"));
    if (fileChooser.showSaveDialog(null) != javax.swing.JFileChooser.APPROVE_OPTION) {
        return;
    }
    java.io.File file = fileChooser.getSelectedFile();

    java.util.Set<String> processedHashes = new java.util.HashSet<>();
    java.util.List<burp.api.montoya.http.message.HttpRequestResponse> originalRequests = new java.util.ArrayList<>();

    for (int viewIndex : selectedRows) {
        int modelIndex = table1.convertRowIndexToModel(viewIndex);
        SourceLogEntry sourceEntry = sourceTableModel.get(modelIndex);
        if (sourceEntry == null) continue;
        String myHash = sourceEntry.getMyHash();
        if (myHash == null || !processedHashes.add(myHash)) continue;
        if (sourceEntry.getHttpRequestResponse() != null) {
            originalRequests.add(sourceEntry.getHttpRequestResponse());
        }
    }

    if (originalRequests.isEmpty()) {
        javax.swing.JOptionPane.showMessageDialog(null, "选中记录未包含可导出的原始请求", "提示", javax.swing.JOptionPane.WARNING_MESSAGE);
        return;
    }

    String separator = "======================================================";
    try (java.io.FileOutputStream out = new java.io.FileOutputStream(file)) {
        byte[] sepBytes = (separator + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        for (burp.api.montoya.http.message.HttpRequestResponse req : originalRequests) {
            out.write(sepBytes);
            // 直接写入原始HTTP请求字节，保留CRLF等原始格式，兼容sqlmap
            out.write(req.request().toByteArray().getBytes());
            out.write('\n');
        }
        out.write(sepBytes);

        String message = String.format(
                "已导出 %d 个原始请求\n文件：%s\n\n使用方法：sqlmap -l %s --batch",
                originalRequests.size(), file.getAbsolutePath(), file.getName());
        javax.swing.JOptionPane.showMessageDialog(null, message, "导出成功", javax.swing.JOptionPane.INFORMATION_MESSAGE);
    } catch (java.io.IOException ex) {
        javax.swing.JOptionPane.showMessageDialog(null, "导出失败：" + ex.getMessage(), "错误", javax.swing.JOptionPane.ERROR_MESSAGE);
    }
});

// copy vulnerable parameters from selected (table1 selection aggregates attackMap)
copyParams.addActionListener(e -> {
    int[] selectedRows = table1.getSelectedRows();
    if (selectedRows == null || selectedRows.length == 0) return;
    java.util.Set<String> params = new java.util.TreeSet<>();
    for (int viewIndex : selectedRows) {
        int modelIndex = table1.convertRowIndexToModel(viewIndex);
        SourceLogEntry sourceEntry = sourceTableModel.get(modelIndex);
        if (sourceEntry == null) continue;
        String myHash = sourceEntry.getMyHash();
        if (myHash == null) continue;
        java.util.List<PocLogEntry> entries = myHttpHandler.attackMap.get(myHash);
        if (entries == null) continue;
        for (PocLogEntry pe : entries) {
            String name = pe.getName();
            if (name != null && !name.isEmpty()) params.add(name);
        }
    }
    if (params.isEmpty()) {
        javax.swing.JOptionPane.showMessageDialog(null, "选中的记录中未找到参数", "提示", javax.swing.JOptionPane.WARNING_MESSAGE);
        return;
    }
    String result = String.join(",", params);
    java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(result);
    java.awt.datatransfer.Clipboard clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
    clipboard.setContents(selection, selection);
    String message = String.format("已复制 %d 个参数到剪贴板：\n%s", params.size(), result);
    javax.swing.JOptionPane.showMessageDialog(null, message, "复制成功", javax.swing.JOptionPane.INFORMATION_MESSAGE);
});

// 为弹出菜单添加事件监听器
        // Enable/disable menu items by selection
        popupMenu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                int selectedCount = table1.getSelectedRowCount();
                boolean hasSelection = selectedCount > 0;
                // enable/disable new actions based on selection
                exportBurpLog.setEnabled(hasSelection);
                copyParams.setEnabled(hasSelection);
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                // 当菜单即将不可见时的处理逻辑
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
                // 当右键点击但未显示菜单（例如点击其他地方）时的处理逻辑
            }
        });
// 为JTable添加鼠标监听器来显示弹出菜单
        table1.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupMenu.show(table1, e.getX(), e.getY());
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupMenu.show(table1, e.getX(), e.getY());
                }
            }
        });
        table2 = new JTable(pocTableModel) {
            @Override
            public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
                // show the log entry for the selected row
                PocLogEntry logEntry = pocTableModel.get(DetSql.table2.convertRowIndexToModel(rowIndex));
                if (logEntry.getHttpRequestResponse() != null) {
                    requestViewer.setRequest(logEntry.getHttpRequestResponse().request());
                    responseViewer.setResponse(logEntry.getHttpRequestResponse().response());
                    super.changeSelection(rowIndex, columnIndex, toggle, extend);
                }

            }
        };
        TableRowSorter<PocTableModel> sorter1 = new TableRowSorter<>(pocTableModel);
//        //获得列的数量
//        //int columnCount = tableModel.getColumnCount();
//            //这里可以根据需要修改

        sorter1.setComparator(5, new Comparator<Object>() {
            @Override
            public int compare(Object o1, Object o2) {
                String str1 = o1.toString();
                String str2 = o2.toString();
                try {
                    return (int) (Double.parseDouble(str1)*1000-Double.parseDouble(str2)*1000);
                } catch (NumberFormatException e) {
                    return 0;
                }
            }
        });
//
        table2.setRowSorter(sorter1);

        // ========= table2 (POC) context menu ========= (removed per new design)
        // no context menu for table2

        // removed: no context menu for table2

        // removed: table2 context menu mouse listener

        // removed: table2 export/copy actions now provided on table1 popup
        /*
        exportBurpLog.addActionListener(e -> {
            int[] selectedRows = table2.getSelectedRows();
            if (selectedRows == null || selectedRows.length == 0) return;

            javax.swing.JFileChooser fileChooser = new javax.swing.JFileChooser();
            fileChooser.setSelectedFile(new java.io.File("burp_log.txt"));
            if (fileChooser.showSaveDialog(null) != javax.swing.JFileChooser.APPROVE_OPTION) {
                return;
            }
            java.io.File file = fileChooser.getSelectedFile();

            java.util.Set<String> processedHashes = new java.util.HashSet<>();
            java.util.List<burp.api.montoya.http.message.HttpRequestResponse> originalRequests = new java.util.ArrayList<>();

            for (int viewIndex : selectedRows) {
                int modelIndex = table2.convertRowIndexToModel(viewIndex);
                PocLogEntry pocEntry = pocTableModel.get(modelIndex);
                String myHash = pocEntry.getMyHash();
                if (myHash == null) continue;
                if (!processedHashes.add(myHash)) continue; // dedup
                SourceLogEntry sourceEntry = sourceTableModel.findByHash(myHash);
                if (sourceEntry != null && sourceEntry.getHttpRequestResponse() != null) {
                    originalRequests.add(sourceEntry.getHttpRequestResponse());
                }
            }

            if (originalRequests.isEmpty()) {
                javax.swing.JOptionPane.showMessageDialog(null, "选中记录未包含可导出的原始请求", "提示", javax.swing.JOptionPane.WARNING_MESSAGE);
                return;
            }

            String separator = "======================================================";
            try (java.io.FileOutputStream out = new java.io.FileOutputStream(file)) {
                byte[] sepBytes = (separator + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                for (burp.api.montoya.http.message.HttpRequestResponse req : originalRequests) {
                    out.write(sepBytes);
                    // 直接写入原始HTTP请求字节，保留CRLF等原始格式，兼容sqlmap
                    out.write(req.request().toByteArray().getBytes());
                    out.write('\n');
                }
                out.write(sepBytes);

                String message = String.format(
                        "已导出 %d 个原始请求\n文件：%s\n\n使用方法：sqlmap -l %s --batch",
                        originalRequests.size(), file.getAbsolutePath(), file.getName());
                javax.swing.JOptionPane.showMessageDialog(null, message, "导出成功", javax.swing.JOptionPane.INFORMATION_MESSAGE);
            } catch (java.io.IOException ex) {
                javax.swing.JOptionPane.showMessageDialog(null, "导出失败：" + ex.getMessage(), "错误", javax.swing.JOptionPane.ERROR_MESSAGE);
            }
        });

        // Action: copy vulnerable parameter names (sorted & deduplicated)
        copyParams.addActionListener(e -> {
            int[] selectedRows = table2.getSelectedRows();
            if (selectedRows == null || selectedRows.length == 0) return;
            java.util.Set<String> params = new java.util.TreeSet<>();
            for (int viewIndex : selectedRows) {
                int modelIndex = table2.convertRowIndexToModel(viewIndex);
                PocLogEntry entry = pocTableModel.get(modelIndex);
                String paramName = entry.getName();
                if (paramName != null && !paramName.isEmpty()) params.add(paramName);
            }
            if (params.isEmpty()) {
                javax.swing.JOptionPane.showMessageDialog(null, "选中的记录中未找到参数", "提示", javax.swing.JOptionPane.WARNING_MESSAGE);
                return;
            }
            String result = String.join(",", params);
            java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(result);
            java.awt.datatransfer.Clipboard clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, selection);
            String message = String.format("已复制 %d 个参数到剪贴板：\n%s", params.size(), result);
            javax.swing.JOptionPane.showMessageDialog(null, message, "复制成功", javax.swing.JOptionPane.INFORMATION_MESSAGE);
        });

        // Action: delete selected POC rows from table2 view
        /* deleteSelectedPoc.addActionListener(e -> {
            int[] selected = table2.getSelectedRows();
            if (selected == null || selected.length == 0) return;
            int[] modelIdx = new int[selected.length];
            for (int i = 0; i < selected.length; i++) {
                modelIdx[i] = table2.convertRowIndexToModel(selected[i]);
            }
            java.util.Arrays.sort(modelIdx);
            for (int i = modelIdx.length - 1; i >= 0; i--) {
                pocTableModel.remove(modelIdx[i]);
            }
        });*/

        //======== root ========
        {
            root.setLayout(new BorderLayout());

            // top bar: tabs on the left, stats on the right (same row)
            JPanel topBar = new JPanel(new BorderLayout()) {
                @Override
                public Dimension getPreferredSize() {
                    Dimension d = super.getPreferredSize();
                    // cap the height to avoid large whitespace under the tab row
                    return new Dimension(d.width, Math.min(d.height, TOP_BAR_MAX_HEIGHT));
                }
            };
            JPanel statsRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 0));
            statsTestedLabel = new JLabel("Tested: 0");
            statsVulnLabel = new JLabel("Vulns: 0");
            statsRow.add(statsTestedLabel);
            statsRow.add(statsVulnLabel);
            topBar.add(tabbedPane1, BorderLayout.CENTER);
            topBar.add(statsRow, BorderLayout.EAST);
            root.add(topBar, BorderLayout.NORTH);

            // content area uses CardLayout, switched by tab selection
            JPanel contentCards = new JPanel(new CardLayout());

            //======== tabbedPane1 ========
            {

                //======== splitPane1 ========
                {
                    splitPane1.setOrientation(JSplitPane.VERTICAL_SPLIT);

                    //======== splitPane2 ========
                    {

                        //======== scrollPane1 ========
                        {
                            scrollPane1.setViewportView(table1);
                        }
                        splitPane2.setLeftComponent(scrollPane1);

                        //======== scrollPane2 ========
                        {
                            scrollPane2.setViewportView(table2);
                        }
                        splitPane2.setRightComponent(scrollPane2);
                    }
                    splitPane2.setResizeWeight(SPLITPANE_RESIZE_WEIGHT);
                    splitPane1.setTopComponent(splitPane2);

                    //======== splitPane3 ========
                    {
                        splitPane3.setLeftComponent(tabbedPane2);
                        splitPane3.setRightComponent(tabbedPane3);
                    }
                    splitPane3.setResizeWeight(SPLITPANE_RESIZE_WEIGHT);
                    splitPane1.setBottomComponent(splitPane3);
                }

                // Register contents to card layout
                contentCards.add("DashBoard", splitPane1);
                contentCards.add("Config", getConfigComponent());
                contentCards.add("CodeTool", getToolComponent());

                // Add tabs with light placeholders so only a single row is used
                tabbedPane1.addTab("DashBoard", new JPanel());
                tabbedPane1.addTab("Config", new JPanel());
                tabbedPane1.addTab("CodeTool", new JPanel());
                final String[] CARD_KEYS = {"DashBoard", "Config", "CodeTool"};
                // Sync selected tab to content card
                tabbedPane1.addChangeListener(e -> {
                    int idx = tabbedPane1.getSelectedIndex();
                    if (idx >= 0&& idx < CARD_KEYS.length) {
                        CardLayout cl = (CardLayout) contentCards.getLayout();
                        cl.show(contentCards, CARD_KEYS[idx]);
                    }
                });

                // show initial card
                ((CardLayout) contentCards.getLayout()).show(contentCards, "DashBoard");
            }
            // place content below the top bar: use contentCards instead of tab contents
            root.add(contentCards, BorderLayout.CENTER);
            // constrain tab strip height to a single line (approx.)
            tabbedPane1.setPreferredSize(new Dimension(Integer.MAX_VALUE, TAB_STRIP_HEIGHT));

            {
                Dimension preferredSize = new Dimension();
                for (int i = 0; i < root.getComponentCount(); i++) {
                    Rectangle bounds = root.getComponent(i).getBounds();
                    preferredSize.width = Math.max(bounds.x + bounds.width, preferredSize.width);
                    preferredSize.height = Math.max(bounds.y + bounds.height, preferredSize.height);
                }
                Insets insets = root.getInsets();
                preferredSize.width += insets.right;
                preferredSize.height += insets.bottom;
                root.setMinimumSize(preferredSize);
                root.setPreferredSize(preferredSize);
            }
        }
//        JPanel finRoot = new JPanel();
//        SpringLayout springLayout = new SpringLayout();
//        finRoot.setLayout(springLayout);
//        finRoot.add(root);
//        springLayout.putConstraint(SpringLayout.NORTH, root, 0, SpringLayout.NORTH, finRoot);
//        springLayout.putConstraint(SpringLayout.WEST, root, 0, SpringLayout.WEST, finRoot);
//        springLayout.putConstraint(SpringLayout.EAST, root, 0, SpringLayout.EAST, finRoot);
//        springLayout.putConstraint(SpringLayout.SOUTH, root, 40, SpringLayout.SOUTH, finRoot);

        // start stats timer after UI built
        startStatsTimer();
        return root;
    }

    private void startStatsTimer() {
        if (statsTimer != null) {
            statsTimer.stop();
        }
        statsTimer = new javax.swing.Timer(1000, e -> updateStats());
        statsTimer.setRepeats(true);
        statsTimer.start();
    }

    private void updateStats() {
        try {
            int tested = (statistics != null) ? statistics.getRequestsProcessed() : 0;
            int vulns = (statistics != null) ? statistics.getVulnerabilitiesFound() : 0;
            final int fTested = tested;
            final int fVulns = vulns;
            SwingUtilities.invokeLater(() -> {
                statsTestedLabel.setText("Tested: " + fTested);
                statsVulnLabel.setText("Vulns: " + fVulns);
            });
        } catch (Exception ignore) {
        }
    }



    private Component getConfigComponent() {
        Container container = new JPanel();
        SpringLayout springLayout = new SpringLayout();
        container.setLayout(springLayout);

        // Create all labels and buttons
        JLabel topicLabel = new JLabel();
        JLabel blackLabel = new JLabel();
        JLabel suffixLabel = new JLabel();
        JLabel errorPocLabel = new JLabel();
        JLabel blackParamsLabel = new JLabel();
        JLabel configLabel = new JLabel();
        JLabel blackPathLabel = new JLabel();
        JLabel diyLabel = new JLabel();
        JLabel resRegexLabel = new JLabel();
        JLabel timeLabel = new JLabel();
        JLabel staticTimeLabel = new JLabel();
        JLabel startTimeLabel = new JLabel();
        JLabel languageLabel = new JLabel();
        JButton conBt = new JButton();
        JButton loadBt = new JButton();
        JButton saveBt = new JButton();

        // Create Spring constants
        Spring st = Spring.constant(PADDING_SMALL);
        Spring st2 = Spring.constant(PADDING_COMPONENT);
        Spring st3 = Spring.constant(PADDING_BUTTON);
        Spring st4 = Spring.constant(PADDING_LARGE);

        // Setup UI sections
        setupDomainFilters(container, springLayout, topicLabel, blackLabel, suffixLabel, errorPocLabel, blackParamsLabel, st, st2);
        setupCheckboxes(container, springLayout, conBt, st, st2);
        setupConfigPath(container, springLayout, configLabel, loadBt, saveBt, blackLabel, st, st3, st4);
        JScrollPane blackPathScrollPane = setupBlackPath(container, springLayout, blackPathLabel, configLabel, st);
        JScrollPane diyScrollPane = setupPayloadsAndSettings(container, springLayout, diyLabel, resRegexLabel, timeLabel, staticTimeLabel, startTimeLabel, blackParamsLabel, blackPathScrollPane, st);
        setupLanguage(container, springLayout, languageLabel, blackParamsLabel, diyScrollPane, st);

        // Setup button event handlers
        conBt.addActionListener(e -> handleConfirmButton());
        loadBt.addActionListener(e -> handleLoadButton());
        saveBt.addActionListener(e -> handleSaveButton());
        languageComboBox.addActionListener(e -> handleLanguageChange(topicLabel, blackLabel, suffixLabel, errorPocLabel,
                blackParamsLabel, diyLabel, resRegexLabel, timeLabel, staticTimeLabel, startTimeLabel, blackPathLabel,
                conBt, loadBt, saveBt, languageLabel, configLabel));

        // Initialize language bundle and update all labels
        messages = ResourceBundle.getBundle("Messages", LOCALES[index]);
        updateLanguageLabels(topicLabel, blackLabel, suffixLabel, errorPocLabel,
                blackParamsLabel, diyLabel, resRegexLabel, timeLabel,
                staticTimeLabel, startTimeLabel, blackPathLabel,
                conBt, loadBt, saveBt, languageLabel, configLabel);

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 初始化UI双向绑定 (消除手动同步代码)
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if (config != null) {
            bindingContext = new BindingContext(config);

            // 绑定TextField (使用类型安全的新API)
            bindingContext.bindSetField(textField, "whiteListDomains");
            bindingContext.bindSetField(blackTextField, "blackListDomains");
            bindingContext.bindSetField(suffixTextField, "unLegalExtensions");
            bindingContext.bindSetField(blackParamsField, "blackListParams");

            // 绑定TextArea (使用类型安全的新API)
            bindingContext.bindSetArea(diyTextArea, "diyPayloads");
            bindingContext.bindSetArea(regexTextArea, "diyRegexs");
            bindingContext.bindSetArea(blackPathTextArea, "blackListPaths");

            // TODO: 时间字段绑定需要特殊处理(int类型)
            // TODO: errorPocTextField需要特殊处理(String[]类型)
        }

        return container;
    }

    private void setupDomainFilters(Container container, SpringLayout layout,
                                    JLabel topicLabel, JLabel blackLabel, JLabel suffixLabel,
                                    JLabel errorPocLabel, JLabel blackParamsLabel,
                                    Spring st, Spring st2) {
        // Create text fields
        textField = new JTextField(TEXTFIELD_COLUMNS);
        blackTextField = new JTextField(TEXTFIELD_COLUMNS);
        suffixTextField = new JTextField(TEXTFIELD_COLUMNS);
        suffixTextField.setText(DefaultConfig.DEFAULT_SUFFIX_LIST);
        errorPocTextField = new JTextField(TEXTFIELD_COLUMNS);
        blackParamsField = new JTextField(TEXTFIELD_COLUMNS);

        // Domain whitelist
        container.add(topicLabel);
        layout.putConstraint(SpringLayout.NORTH, topicLabel, st, SpringLayout.NORTH, container);
        layout.putConstraint(SpringLayout.WEST, topicLabel, st, SpringLayout.WEST, container);

        container.add(textField);
        layout.putConstraint(SpringLayout.WEST, textField, st2, SpringLayout.EAST, topicLabel);
        layout.putConstraint(SpringLayout.NORTH, textField, 0, SpringLayout.NORTH, topicLabel);
        layout.putConstraint(SpringLayout.EAST, textField, Spring.minus(st), SpringLayout.EAST, container);

        // Domain blacklist
        container.add(blackLabel);
        layout.putConstraint(SpringLayout.WEST, blackLabel, 0, SpringLayout.WEST, topicLabel);
        layout.putConstraint(SpringLayout.NORTH, blackLabel, st, SpringLayout.SOUTH, topicLabel);

        container.add(blackTextField);
        layout.putConstraint(SpringLayout.WEST, blackTextField, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, blackTextField, 0, SpringLayout.NORTH, blackLabel);
        layout.putConstraint(SpringLayout.EAST, blackTextField, Spring.minus(st), SpringLayout.EAST, container);

        // Suffix filter
        container.add(suffixLabel);
        layout.putConstraint(SpringLayout.WEST, suffixLabel, 0, SpringLayout.WEST, blackLabel);
        layout.putConstraint(SpringLayout.NORTH, suffixLabel, st, SpringLayout.SOUTH, blackLabel);

        container.add(suffixTextField);
        layout.putConstraint(SpringLayout.WEST, suffixTextField, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, suffixTextField, 0, SpringLayout.NORTH, suffixLabel);
        layout.putConstraint(SpringLayout.EAST, suffixTextField, Spring.minus(st), SpringLayout.EAST, container);

        // Error POC
        container.add(errorPocLabel);
        layout.putConstraint(SpringLayout.WEST, errorPocLabel, 0, SpringLayout.WEST, suffixLabel);
        layout.putConstraint(SpringLayout.NORTH, errorPocLabel, st, SpringLayout.SOUTH, suffixLabel);

        container.add(errorPocTextField);
        layout.putConstraint(SpringLayout.WEST, errorPocTextField, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, errorPocTextField, 0, SpringLayout.NORTH, errorPocLabel);
        layout.putConstraint(SpringLayout.EAST, errorPocTextField, Spring.minus(st), SpringLayout.EAST, container);

        // Parameter blacklist
        container.add(blackParamsLabel);
        layout.putConstraint(SpringLayout.WEST, blackParamsLabel, 0, SpringLayout.WEST, errorPocLabel);
        layout.putConstraint(SpringLayout.NORTH, blackParamsLabel, st, SpringLayout.SOUTH, errorPocLabel);

        container.add(blackParamsField);
        layout.putConstraint(SpringLayout.WEST, blackParamsField, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, blackParamsField, 0, SpringLayout.NORTH, blackParamsLabel);
        layout.putConstraint(SpringLayout.EAST, blackParamsField, Spring.minus(st), SpringLayout.EAST, container);
    }

    private void setupCheckboxes(Container container, SpringLayout layout, JButton conBt, Spring st, Spring st2) {
        // Create checkboxes
        switchCheck = new JCheckBox();
        cookieCheck = new JCheckBox();
        errorCheck = new JCheckBox();
        vulnCheck = new JCheckBox();
        numCheck = new JCheckBox();
        stringCheck = new JCheckBox();
        orderCheck = new JCheckBox();
        boolCheck = new JCheckBox();
        diyCheck = new JCheckBox();

        // Layout checkboxes in horizontal row
        container.add(switchCheck);
        layout.putConstraint(SpringLayout.WEST, switchCheck, 0, SpringLayout.WEST, blackParamsField);
        layout.putConstraint(SpringLayout.NORTH, switchCheck, st, SpringLayout.SOUTH, blackParamsField);

        container.add(cookieCheck);
        layout.putConstraint(SpringLayout.WEST, cookieCheck, st2, SpringLayout.EAST, switchCheck);
        layout.putConstraint(SpringLayout.NORTH, cookieCheck, 0, SpringLayout.NORTH, switchCheck);

        container.add(vulnCheck);
        layout.putConstraint(SpringLayout.WEST, vulnCheck, st2, SpringLayout.EAST, cookieCheck);
        layout.putConstraint(SpringLayout.NORTH, vulnCheck, 0, SpringLayout.NORTH, switchCheck);

        container.add(errorCheck);
        layout.putConstraint(SpringLayout.WEST, errorCheck, st2, SpringLayout.EAST, vulnCheck);
        layout.putConstraint(SpringLayout.NORTH, errorCheck, 0, SpringLayout.NORTH, switchCheck);

        container.add(numCheck);
        layout.putConstraint(SpringLayout.WEST, numCheck, st2, SpringLayout.EAST, errorCheck);
        layout.putConstraint(SpringLayout.NORTH, numCheck, 0, SpringLayout.NORTH, switchCheck);

        container.add(stringCheck);
        layout.putConstraint(SpringLayout.WEST, stringCheck, st2, SpringLayout.EAST, numCheck);
        layout.putConstraint(SpringLayout.NORTH, stringCheck, 0, SpringLayout.NORTH, switchCheck);

        container.add(orderCheck);
        layout.putConstraint(SpringLayout.WEST, orderCheck, st2, SpringLayout.EAST, stringCheck);
        layout.putConstraint(SpringLayout.NORTH, orderCheck, 0, SpringLayout.NORTH, switchCheck);

        container.add(boolCheck);
        layout.putConstraint(SpringLayout.WEST, boolCheck, st2, SpringLayout.EAST, orderCheck);
        layout.putConstraint(SpringLayout.NORTH, boolCheck, 0, SpringLayout.NORTH, switchCheck);

        container.add(diyCheck);
        layout.putConstraint(SpringLayout.WEST, diyCheck, st2, SpringLayout.EAST, boolCheck);
        layout.putConstraint(SpringLayout.NORTH, diyCheck, 0, SpringLayout.NORTH, switchCheck);

        // Confirm button
        container.add(conBt);
        layout.putConstraint(SpringLayout.WEST, conBt, st2, SpringLayout.EAST, diyCheck);
        layout.putConstraint(SpringLayout.NORTH, conBt, 0, SpringLayout.NORTH, switchCheck);
    }

    private void setupConfigPath(Container container, SpringLayout layout, JLabel configLabel,
                                 JButton loadBt, JButton saveBt, JLabel blackLabel,
                                 Spring st, Spring st3, Spring st4) {
        // Create config path text field
        configTextField = new JTextField(TEXTFIELD_COLUMNS);
        configTextField.setEditable(false);

        container.add(configLabel);
        layout.putConstraint(SpringLayout.WEST, configLabel, 0, SpringLayout.WEST, blackLabel);
        layout.putConstraint(SpringLayout.NORTH, configLabel, st, SpringLayout.SOUTH, switchCheck);

        container.add(configTextField);
        layout.putConstraint(SpringLayout.WEST, configTextField, 0, SpringLayout.WEST, blackTextField);
        layout.putConstraint(SpringLayout.NORTH, configTextField, 0, SpringLayout.NORTH, configLabel);
        layout.putConstraint(SpringLayout.EAST, configTextField, Spring.minus(st4), SpringLayout.EAST, container);

        container.add(loadBt);
        layout.putConstraint(SpringLayout.NORTH, loadBt, 0, SpringLayout.NORTH, configLabel);
        layout.putConstraint(SpringLayout.EAST, loadBt, Spring.minus(st3), SpringLayout.EAST, container);

        container.add(saveBt);
        layout.putConstraint(SpringLayout.NORTH, saveBt, 0, SpringLayout.NORTH, configLabel);
        layout.putConstraint(SpringLayout.EAST, saveBt, Spring.minus(st), SpringLayout.EAST, container);
    }

    private JScrollPane setupBlackPath(Container container, SpringLayout layout, JLabel blackPathLabel,
                                       JLabel configLabel, Spring st) {
        // Create black path text area
        blackPathTextArea = new JTextArea(TEXTAREA_ROWS_SMALL, TEXTAREA_ROWS_MEDIUM);
        JScrollPane blackPathScrollPane = new JScrollPane();
        blackPathScrollPane.setViewportView(blackPathTextArea);
        blackPathTextArea.setLineWrap(true);

        container.add(blackPathLabel);
        layout.putConstraint(SpringLayout.WEST, blackPathLabel, 0, SpringLayout.WEST, configLabel);
        layout.putConstraint(SpringLayout.NORTH, blackPathLabel, st, SpringLayout.SOUTH, configLabel);

        container.add(blackPathScrollPane);
        layout.putConstraint(SpringLayout.WEST, blackPathScrollPane, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, blackPathScrollPane, 0, SpringLayout.NORTH, blackPathLabel);
        layout.putConstraint(SpringLayout.EAST, blackPathScrollPane, Spring.minus(st), SpringLayout.EAST, container);

        return blackPathScrollPane;
    }

    private JScrollPane setupPayloadsAndSettings(Container container, SpringLayout layout,
                                                 JLabel diyLabel, JLabel resRegexLabel,
                                                 JLabel timeLabel, JLabel staticTimeLabel, JLabel startTimeLabel,
                                                 JLabel blackParamsLabel, Component blackPathScrollPane,
                                                 Spring st) {
        // Create DIY payloads text area
        diyTextArea = new JTextArea(TEXTAREA_ROWS_XLARGE, TEXTAREA_ROWS_MEDIUM);
        JScrollPane diyScrollPane = new JScrollPane();
        diyScrollPane.setViewportView(diyTextArea);
        diyTextArea.setLineWrap(true);

        // Create response regex text area
        regexTextArea = new JTextArea(TEXTAREA_ROWS_REGULAR, TEXTAREA_ROWS_MEDIUM);
        JScrollPane regexScrollPane = new JScrollPane();
        regexScrollPane.setViewportView(regexTextArea);
        regexTextArea.setLineWrap(true);

        // Create time settings text fields
        timeTextField = new JTextField(TEXTAREA_ROWS_MEDIUM);
        staticTimeTextField = new JTextField(TEXTAREA_ROWS_MEDIUM);
        staticTimeTextField.setText("100");
        startTimeTextField = new JTextField(TEXTAREA_ROWS_MEDIUM);
        startTimeTextField.setText("0");
        JLabel endTimeLabel = new JLabel("-");
        endTimeTextField = new JTextField(TEXTAREA_ROWS_MEDIUM);
        endTimeTextField.setText("0");

        // Layout left column (DIY payloads)
        container.add(diyLabel);
        layout.putConstraint(SpringLayout.NORTH, diyLabel, st, SpringLayout.SOUTH, blackPathScrollPane);
        layout.putConstraint(SpringLayout.WEST, diyLabel, 0, SpringLayout.WEST, blackParamsLabel);

        container.add(diyScrollPane);
        layout.putConstraint(SpringLayout.WEST, diyScrollPane, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, diyScrollPane, 0, SpringLayout.NORTH, diyLabel);
        layout.putConstraint(SpringLayout.EAST, diyScrollPane, -PADDING_SMALL, SpringLayout.HORIZONTAL_CENTER, container);

        // Layout right column (Response regex and time settings)
        container.add(resRegexLabel);
        layout.putConstraint(SpringLayout.WEST, resRegexLabel, PADDING_SMALL, SpringLayout.HORIZONTAL_CENTER, container);
        layout.putConstraint(SpringLayout.NORTH, resRegexLabel, st, SpringLayout.SOUTH, blackPathScrollPane);

        container.add(regexScrollPane);
        layout.putConstraint(SpringLayout.WEST, regexScrollPane, PADDING_SPECIAL, SpringLayout.EAST, resRegexLabel);
        layout.putConstraint(SpringLayout.NORTH, regexScrollPane, 0, SpringLayout.NORTH, diyLabel);
        layout.putConstraint(SpringLayout.EAST, regexScrollPane, Spring.minus(st), SpringLayout.EAST, container);

        // Time settings
        container.add(timeLabel);
        layout.putConstraint(SpringLayout.WEST, timeLabel, 0, SpringLayout.WEST, resRegexLabel);
        layout.putConstraint(SpringLayout.NORTH, timeLabel, st, SpringLayout.SOUTH, regexScrollPane);

        container.add(timeTextField);
        layout.putConstraint(SpringLayout.WEST, timeTextField, 0, SpringLayout.WEST, regexScrollPane);
        layout.putConstraint(SpringLayout.NORTH, timeTextField, 0, SpringLayout.NORTH, timeLabel);

        container.add(staticTimeLabel);
        layout.putConstraint(SpringLayout.WEST, staticTimeLabel, 0, SpringLayout.WEST, resRegexLabel);
        layout.putConstraint(SpringLayout.NORTH, staticTimeLabel, st, SpringLayout.SOUTH, timeLabel);

        container.add(staticTimeTextField);
        layout.putConstraint(SpringLayout.WEST, staticTimeTextField, 0, SpringLayout.WEST, regexScrollPane);
        layout.putConstraint(SpringLayout.NORTH, staticTimeTextField, 0, SpringLayout.NORTH, staticTimeLabel);

        container.add(startTimeLabel);
        layout.putConstraint(SpringLayout.WEST, startTimeLabel, 0, SpringLayout.WEST, resRegexLabel);
        layout.putConstraint(SpringLayout.NORTH, startTimeLabel, st, SpringLayout.SOUTH, staticTimeLabel);

        container.add(startTimeTextField);
        layout.putConstraint(SpringLayout.WEST, startTimeTextField, 0, SpringLayout.WEST, regexScrollPane);
        layout.putConstraint(SpringLayout.NORTH, startTimeTextField, 0, SpringLayout.NORTH, startTimeLabel);

        container.add(endTimeLabel);
        layout.putConstraint(SpringLayout.WEST, endTimeLabel, st, SpringLayout.EAST, startTimeTextField);
        layout.putConstraint(SpringLayout.NORTH, endTimeLabel, 0, SpringLayout.NORTH, startTimeLabel);

        container.add(endTimeTextField);
        layout.putConstraint(SpringLayout.WEST, endTimeTextField, st, SpringLayout.EAST, endTimeLabel);
        layout.putConstraint(SpringLayout.NORTH, endTimeTextField, 0, SpringLayout.NORTH, startTimeLabel);

        return diyScrollPane;
    }

    private void setupLanguage(Container container, SpringLayout layout, JLabel languageLabel,
                               JLabel blackParamsLabel, JScrollPane diyScrollPane, Spring st) {
        // Create language combo box
        languageComboBox = new JComboBox<>(LANGUAGES);
        languageComboBox.setSelectedIndex(index);

        container.add(languageLabel);
        layout.putConstraint(SpringLayout.NORTH, languageLabel, st, SpringLayout.SOUTH, diyScrollPane);
        layout.putConstraint(SpringLayout.WEST, languageLabel, 0, SpringLayout.WEST, blackParamsLabel);

        container.add(languageComboBox);
        layout.putConstraint(SpringLayout.WEST, languageComboBox, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, languageComboBox, 0, SpringLayout.NORTH, languageLabel);
    }

    private void handleConfirmButton() {
        String whiteList = textField.getText();
        if (!whiteList.isBlank()) {
            MyFilterRequest.whiteListSet = parseDelimitedString(whiteList);
        } else {
            MyFilterRequest.whiteListSet.clear();
        }

        String blackList = blackTextField.getText();
        if (!blackList.isBlank()) {
            MyFilterRequest.blackListSet = parseDelimitedString(blackList);
        } else {
            MyFilterRequest.blackListSet.clear();
        }

        String blackParamsList = blackParamsField.getText();
        if (!blackParamsList.isBlank()) {
            MyFilterRequest.blackParamsSet = parseDelimitedString(blackParamsList);
        } else {
            MyFilterRequest.blackParamsSet.clear();
        }

        String unLegalExtension = suffixTextField.getText();
        if (!unLegalExtension.isBlank()) {
            MyFilterRequest.unLegalExtensionSet = parseDelimitedString(unLegalExtension);
        } else {
            MyFilterRequest.unLegalExtensionSet = new HashSet<>(DefaultConfig.DEFAULT_SUFFIX_SET);
        }

        String errorPocList = errorPocTextField.getText();
        if (!errorPocList.isBlank()) {
            config.setErrorPayloads(errorPocList.trim().split("\\|"));
            config.setErrorPayloadsJson(deriveJsonErrPocs(config.getErrorPayloads()));
        } else {
            config.setErrorPayloads(DefaultConfig.DEFAULT_ERR_POCS.clone());
            config.setErrorPayloadsJson(DefaultConfig.DEFAULT_ERR_POCS_JSON.clone());
        }

        String diyPayloadsStr = diyTextArea.getText();
        if (!diyPayloadsStr.isBlank()) {
            config.setDiyPayloads(readLinesFromTextArea(diyTextArea));
        } else {
            config.getDiyPayloads().clear();
        }

        String diyRegexsStr = regexTextArea.getText();
        if (!diyRegexsStr.isBlank()) {
            config.setDiyRegexs(readLinesFromTextArea(regexTextArea));
        } else {
            config.getDiyRegexs().clear();
        }

        config.setDelayTimeMs(parseIntWithDefault(timeTextField.getText(), DefaultConfig.DEFAULT_DELAY_TIME_MS));
        config.setStaticTimeMs(parseIntWithDefault(staticTimeTextField.getText(), DefaultConfig.DEFAULT_STATIC_TIME_MS));
        config.setStartTimeMs(parseIntWithDefault(startTimeTextField.getText(), DefaultConfig.DEFAULT_START_TIME_MS));
        config.setEndTimeMs(parseIntWithDefault(endTimeTextField.getText(), DefaultConfig.DEFAULT_END_TIME_MS));

        String blackPathStr = blackPathTextArea.getText();
        if (!blackPathStr.isBlank()) {
            MyFilterRequest.blackPathSet = readLinesFromTextArea(blackPathTextArea);
        } else {
            MyFilterRequest.blackPathSet.clear();
        }
    }

    /**
     * Show file chooser dialog
     * @param dialogTitle Dialog title
     * @param isOpen true for open dialog, false for save dialog
     * @return Selected file or null if cancelled
     */
    private File showFileChooser(String dialogTitle, boolean isOpen) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle(dialogTitle);
        fileChooser.setCurrentDirectory(new File("."));
        fileChooser.setPreferredSize(new Dimension(FILE_CHOOSER_WIDTH, FILE_CHOOSER_HEIGHT));

        int result = isOpen
                ? fileChooser.showOpenDialog(null)
                : fileChooser.showSaveDialog(null);

        return (result == JFileChooser.APPROVE_OPTION)
                ? fileChooser.getSelectedFile()
                : null;
    }

    private void handleLoadButton() {
        File file = showFileChooser("Load", true);
        String message;
        if (file != null) {
            message = "Load success";
            configTextField.setText(file.getAbsolutePath());
            loadConfiguration(file);
        } else {
            message = "Load cancel";
        }
        JOptionPane.showMessageDialog(null, message, "Load", JOptionPane.INFORMATION_MESSAGE);
    }

    private void handleSaveButton() {
        File file = showFileChooser("Save", false);
        String message;
        if (file != null) {
            message = "Save success";
            Properties prop = buildConfigProperties();
            try (java.io.OutputStreamWriter fw = new java.io.OutputStreamWriter(
                    new java.io.FileOutputStream(file), java.nio.charset.StandardCharsets.UTF_8)) {
                prop.store(fw, null);
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        } else {
            message = "Save cancel";
        }
        JOptionPane.showMessageDialog(null, message, "Save", JOptionPane.INFORMATION_MESSAGE);
    }

    private void handleLanguageChange(JLabel topicLabel, JLabel blackLabel, JLabel suffixLabel, JLabel errorPocLabel,
                                      JLabel blackParamsLabel, JLabel diyLabel, JLabel resRegexLabel, JLabel timeLabel,
                                      JLabel staticTimeLabel, JLabel startTimeLabel, JLabel blackPathLabel,
                                      JButton conBt, JButton loadBt, JButton saveBt,
                                      JLabel languageLabel, JLabel configLabel) {
        index = languageComboBox.getSelectedIndex();
        Locale locale = LOCALES[index];
        messages = ResourceBundle.getBundle("Messages", locale);
        updateLanguageLabels(topicLabel, blackLabel, suffixLabel, errorPocLabel,
                blackParamsLabel, diyLabel, resRegexLabel, timeLabel,
                staticTimeLabel, startTimeLabel, blackPathLabel,
                conBt, loadBt, saveBt, languageLabel, configLabel);
    }

    public String myBase64Decode(String base64Str) {
        byte[] decodedBytes = Base64.getDecoder().decode(base64Str);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }

    public String myBase64Encode(String text) {
        byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
        return Base64.getEncoder().encodeToString(textBytes);
    }

    public String decodeUnicode(String unicodeStr) {
        StringBuilder sb = new StringBuilder();
        Matcher matcher = Pattern.compile("\\\\u([0-9a-fA-F]{4})").matcher(unicodeStr);
        while (matcher.find()) {
            try {
                String ch = String.valueOf((char) Integer.parseInt(matcher.group(1), 16));
                sb.append(ch);
            } catch (NumberFormatException e) {
                // If parsing fails, skip this unicode sequence
                sb.append(matcher.group(0));
            }
        }
        return sb.toString();
    }

    public String unicodeEncode(String string) {
        char[] utfBytes = string.toCharArray();
        String unicodeBytes = "";
        for (int i = 0; i < utfBytes.length; i++) {
            String hexB = Integer.toHexString(utfBytes[i]);
            if (hexB.length() <= 2) {
                hexB = "00" + hexB;
            }
            unicodeBytes = unicodeBytes + "\\u" + hexB;
        }
        return unicodeBytes;
    }

    public String encodeUrl(String text) {
        return URLEncoder.encode(text, StandardCharsets.UTF_8);
    }

    public String decodeUrl(String urlStr) {
        return URLDecoder.decode(urlStr, StandardCharsets.UTF_8);
    }

    private String toPrettyFormat(String json) {
        JsonObject jsonObject = JsonParser.parseString(json).getAsJsonObject();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(jsonObject);
    }

    /**
     * Add text transformation listener to button
     * @param button Button to attach listener
     * @param source Source JTextArea to read from
     * @param target Target JTextArea to write to
     * @param transformer Transformation function
     */
    private void addTextTransformListener(
            JButton button,
            JTextArea source,
            JTextArea target,
            java.util.function.Function<String, String> transformer
    ) {
        button.addActionListener(e -> {
            String text = source.getText();
            if (!text.isEmpty()) {
                target.setText(transformer.apply(text));
            }
        });
    }

    private Component getToolComponent() {

        Container container = new JPanel();
        SpringLayout springLayout = new SpringLayout();
        container.setLayout(springLayout);
        JLabel topicLabel = new JLabel("base64编码值:");
        JLabel contentLabel = new JLabel("base64解码值:");
        JLabel unicodeLabel = new JLabel("unicode编解码:");
        JLabel urlLabel = new JLabel("url中文编解码:");

        JTextArea textArea = new JTextArea(14, 6);
        JScrollPane scrollPane = new JScrollPane();
        scrollPane.setViewportView(textArea);
        textArea.setLineWrap(true);

        JTextArea textArea2 = new JTextArea(30, 6);
        JScrollPane scrollPane2 = new JScrollPane();
        scrollPane2.setViewportView(textArea2);
        textArea2.setLineWrap(true);

        JTextArea textArea3 = new JTextArea(6, 6);
        JScrollPane scrollPane3 = new JScrollPane();
        scrollPane3.setViewportView(textArea3);
        textArea3.setLineWrap(true);

        JTextArea textArea5 = new JTextArea(6, 6);
        JScrollPane scrollPane5 = new JScrollPane();
        scrollPane5.setViewportView(textArea5);
        textArea5.setLineWrap(true);

        JButton encBt = new JButton("base64解码->");
        int offsetx = Spring.width(encBt).getValue() / 2;
        JButton dedBt = new JButton("<-base64编码");
        JButton unBt = new JButton("unicode解码");
        JButton unxBt = new JButton("unicode编码");
        JButton urlBt = new JButton("url编码");
        JButton urlxBt = new JButton("url解码");
        JButton formatbt = new JButton("JSON格式化");

        // Attach text transformation listeners
        addTextTransformListener(encBt, textArea, textArea2, this::myBase64Decode);
        addTextTransformListener(dedBt, textArea2, textArea, this::myBase64Encode);
        addTextTransformListener(unBt, textArea3, textArea3, this::decodeUnicode);
        addTextTransformListener(unxBt, textArea3, textArea3, this::unicodeEncode);
        addTextTransformListener(urlBt, textArea5, textArea5, this::encodeUrl);
        addTextTransformListener(urlxBt, textArea5, textArea5, this::decodeUrl);
        addTextTransformListener(formatbt, textArea2, textArea2,
                text -> toPrettyFormat(org.apache.commons.text.StringEscapeUtils.unescapeJava(text)));
        Spring st = Spring.constant(PADDING_MEDIUM);
        Spring st2 = Spring.constant(PADDING_COMPONENT);


        container.add(topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, topicLabel, st, SpringLayout.NORTH, container);
        springLayout.putConstraint(SpringLayout.WEST, topicLabel, st, SpringLayout.WEST, container);
        container.add(contentLabel);
        SpringLayout.Constraints contentLabeln = springLayout.getConstraints(contentLabel);
        springLayout.putConstraint(SpringLayout.WEST, contentLabel, PADDING_CENTER_OFFSET, SpringLayout.HORIZONTAL_CENTER, container);
        contentLabeln.setY(st);

        container.add(scrollPane);
        springLayout.putConstraint(SpringLayout.WEST, scrollPane, 0, SpringLayout.WEST, topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, scrollPane, st, SpringLayout.SOUTH, topicLabel);
        springLayout.putConstraint(SpringLayout.EAST, scrollPane, -PADDING_CENTER_OFFSET, SpringLayout.HORIZONTAL_CENTER, container);

        container.add(scrollPane2);
        springLayout.putConstraint(SpringLayout.WEST, scrollPane2, 0, SpringLayout.WEST, contentLabel);
        springLayout.putConstraint(SpringLayout.NORTH, scrollPane2, 0, SpringLayout.NORTH, scrollPane);
        springLayout.putConstraint(SpringLayout.EAST, scrollPane2, Spring.minus(st), SpringLayout.EAST, container);
        container.add(encBt);
        springLayout.putConstraint(SpringLayout.WEST, encBt, -offsetx, SpringLayout.HORIZONTAL_CENTER, container);
        springLayout.putConstraint(SpringLayout.NORTH, encBt, st2, SpringLayout.NORTH, scrollPane);
        container.add(dedBt);
        springLayout.putConstraint(SpringLayout.WEST, dedBt, 0, SpringLayout.WEST, encBt);
        springLayout.putConstraint(SpringLayout.NORTH, dedBt, st, SpringLayout.SOUTH, encBt);

        container.add(unicodeLabel);
        springLayout.putConstraint(SpringLayout.WEST, unicodeLabel, 0, SpringLayout.WEST, topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, unicodeLabel, st, SpringLayout.SOUTH, scrollPane);
        container.add(scrollPane3);
        springLayout.putConstraint(SpringLayout.WEST, scrollPane3, 0, SpringLayout.WEST, scrollPane);
        springLayout.putConstraint(SpringLayout.NORTH, scrollPane3, st, SpringLayout.SOUTH, unicodeLabel);
        springLayout.putConstraint(SpringLayout.EAST, scrollPane3, 0, SpringLayout.EAST, scrollPane);
        container.add(unBt);
        springLayout.putConstraint(SpringLayout.WEST, unBt, 0, SpringLayout.WEST, encBt);
        springLayout.putConstraint(SpringLayout.NORTH, unBt, st2, SpringLayout.NORTH, scrollPane3);

        container.add(unxBt);
        springLayout.putConstraint(SpringLayout.WEST, unxBt, 0, SpringLayout.WEST, unBt);
        springLayout.putConstraint(SpringLayout.NORTH, unxBt, st, SpringLayout.SOUTH, unBt);
        container.add(urlLabel);
        springLayout.putConstraint(SpringLayout.WEST, urlLabel, 0, SpringLayout.WEST, topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, urlLabel, st, SpringLayout.SOUTH, scrollPane3);
        container.add(scrollPane5);
        springLayout.putConstraint(SpringLayout.WEST, scrollPane5, 0, SpringLayout.WEST, scrollPane);
        springLayout.putConstraint(SpringLayout.NORTH, scrollPane5, st, SpringLayout.SOUTH, urlLabel);
        springLayout.putConstraint(SpringLayout.EAST, scrollPane5, 0, SpringLayout.EAST, scrollPane);
        container.add(urlBt);
        springLayout.putConstraint(SpringLayout.WEST, urlBt, 0, SpringLayout.WEST, encBt);
        springLayout.putConstraint(SpringLayout.NORTH, urlBt, st2, SpringLayout.NORTH, scrollPane5);
        container.add(urlxBt);
        springLayout.putConstraint(SpringLayout.WEST, urlxBt, 0, SpringLayout.WEST, urlBt);
        springLayout.putConstraint(SpringLayout.NORTH, urlxBt, st, SpringLayout.SOUTH, urlBt);
        container.add(formatbt);
        springLayout.putConstraint(SpringLayout.EAST, formatbt, 0, SpringLayout.EAST, scrollPane2);
        springLayout.putConstraint(SpringLayout.NORTH, formatbt, st, SpringLayout.SOUTH, scrollPane2);

        return container;
    }


}
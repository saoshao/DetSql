package DetSql.ui;

import DetSql.config.ConfigManager;
import DetSql.config.DefaultConfig;
import DetSql.config.DetSqlConfig;
import DetSql.config.DetSqlYamlConfig;
import DetSql.logging.DetSqlLogger;
import DetSql.logging.LogLevel;
import DetSql.ui.Messages;
import DetSql.util.StringUtils;
import burp.api.montoya.MontoyaApi;
import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.*;

/**
 * 配置面板 - 负责所有配置相关的 UI 组件
 * 从 DetSqlUI 中提取出来，遵循单一职责原则
 */
public class ConfigPanel extends JPanel {
    private final DetSqlConfig config;
    private final DetSqlLogger logger;
    private final MontoyaApi api;
    private final DetSqlUI ui;

    // UI 组件（公开访问以支持测试）
    public JTextField textField;
    public JTextField blackTextField;
    public JTextField suffixTextField;
    public JTextField errorPocTextField;
    public JTextField blackParamsField;
    public JTextField configTextField;
    public JTextField timeTextField;
    public JTextField staticTimeTextField;
    public JTextField startTimeTextField;
    public JTextField endTimeTextField;

    public JTextArea diyTextArea;
    public JTextArea regexTextArea;
    public JTextArea blackPathTextArea;

    public JCheckBox switchCheck;
    public JCheckBox cookieCheck;
    public JCheckBox errorCheck;
    public JCheckBox vulnCheck;
    public JCheckBox numCheck;
    public JCheckBox stringCheck;
    public JCheckBox orderCheck;
    public JCheckBox boolCheck;
    public JCheckBox diyCheck;

    private JComboBox<String> languageComboBox;
    private ResourceBundle messages;
    private int languageIndex;

    private static final String[] LANGUAGES = { "简体中文", "English" };
    private static final Locale[] LOCALES = { new Locale("zh", "CN"), new Locale("en", "US") };

    // 布局常量
    private static final int PADDING_SMALL = 10;
    private static final int PADDING_COMPONENT = 35;
    private static final int PADDING_BUTTON = 100;
    private static final int PADDING_LARGE = 200;
    private static final int TEXTFIELD_COLUMNS = 30;
    private static final int TEXTAREA_ROWS_SMALL = 5;
    private static final int TEXTAREA_ROWS_MEDIUM = 6;
    private static final int TEXTAREA_ROWS_XLARGE = 20;
    private static final int FILE_CHOOSER_WIDTH = 800;
    private static final int FILE_CHOOSER_HEIGHT = 600;

    public ConfigPanel(MontoyaApi api, DetSqlConfig config, DetSqlLogger logger, int languageIndex, DetSqlUI ui) {
        this.api = api;
        this.config = config;
        this.logger = logger;
        this.languageIndex = languageIndex;
        this.ui = ui;
        this.messages = ResourceBundle.getBundle("i18n/messages", LOCALES[languageIndex]);

        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        Container container = new JPanel();
        SpringLayout springLayout = new SpringLayout();
        container.setLayout(springLayout);

        // 创建所有标签和按钮
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

        // 创建 Spring 常量
        Spring st = Spring.constant(PADDING_SMALL);
        Spring st2 = Spring.constant(PADDING_COMPONENT);
        Spring st3 = Spring.constant(PADDING_BUTTON);
        Spring st4 = Spring.constant(PADDING_LARGE);

        // 设置 UI 各部分
        setupDomainFilters(container, springLayout, topicLabel, blackLabel, suffixLabel,
                errorPocLabel, blackParamsLabel, st, st2);
        setupCheckboxes(container, springLayout, conBt, st, st2);
        setupConfigPath(container, springLayout, configLabel, loadBt, saveBt, blackLabel, st, st3, st4);
        JScrollPane blackPathScrollPane = setupBlackPath(container, springLayout, blackPathLabel,
                configLabel, st);
        JScrollPane diyScrollPane = setupPayloadsAndSettings(container, springLayout, diyLabel,
                resRegexLabel, timeLabel, staticTimeLabel,
                startTimeLabel, blackParamsLabel,
                blackPathScrollPane, st);
        setupLanguage(container, springLayout, languageLabel, blackParamsLabel, diyScrollPane, st);

        // 设置按钮事件处理器
        conBt.addActionListener(e -> handleConfirmButton());
        loadBt.addActionListener(e -> handleLoadButton());
        saveBt.addActionListener(e -> handleSaveButton());
        languageComboBox.addActionListener(e -> handleLanguageChange(topicLabel, blackLabel, suffixLabel,
                errorPocLabel, blackParamsLabel, diyLabel,
                resRegexLabel, timeLabel, staticTimeLabel,
                startTimeLabel, blackPathLabel, conBt,
                loadBt, saveBt, languageLabel, configLabel));

        // 更新所有标签
        updateLanguageLabels(topicLabel, blackLabel, suffixLabel, errorPocLabel, blackParamsLabel,
                diyLabel, resRegexLabel, timeLabel, staticTimeLabel, startTimeLabel,
                blackPathLabel, conBt, loadBt, saveBt, languageLabel, configLabel);

        add(new JScrollPane(container), BorderLayout.CENTER);
    }

    private void setupDomainFilters(Container container, SpringLayout layout,
            JLabel topicLabel, JLabel blackLabel, JLabel suffixLabel,
            JLabel errorPocLabel, JLabel blackParamsLabel,
            Spring st, Spring st2) {
        // 创建文本框
        textField = new JTextField(TEXTFIELD_COLUMNS);
        blackTextField = new JTextField(TEXTFIELD_COLUMNS);
        suffixTextField = new JTextField(TEXTFIELD_COLUMNS);
        suffixTextField.setText(DefaultConfig.DEFAULT_SUFFIX_LIST);
        errorPocTextField = new JTextField(TEXTFIELD_COLUMNS);
        blackParamsField = new JTextField(TEXTFIELD_COLUMNS);

        // 域名白名单
        container.add(topicLabel);
        layout.putConstraint(SpringLayout.NORTH, topicLabel, st, SpringLayout.NORTH, container);
        layout.putConstraint(SpringLayout.WEST, topicLabel, st, SpringLayout.WEST, container);

        container.add(textField);
        layout.putConstraint(SpringLayout.WEST, textField, st2, SpringLayout.EAST, topicLabel);
        layout.putConstraint(SpringLayout.NORTH, textField, 0, SpringLayout.NORTH, topicLabel);
        layout.putConstraint(SpringLayout.EAST, textField, Spring.minus(st), SpringLayout.EAST, container);

        // 域名黑名单
        container.add(blackLabel);
        layout.putConstraint(SpringLayout.WEST, blackLabel, 0, SpringLayout.WEST, topicLabel);
        layout.putConstraint(SpringLayout.NORTH, blackLabel, st, SpringLayout.SOUTH, topicLabel);

        container.add(blackTextField);
        layout.putConstraint(SpringLayout.WEST, blackTextField, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, blackTextField, 0, SpringLayout.NORTH, blackLabel);
        layout.putConstraint(SpringLayout.EAST, blackTextField, Spring.minus(st), SpringLayout.EAST, container);

        // 后缀过滤
        container.add(suffixLabel);
        layout.putConstraint(SpringLayout.WEST, suffixLabel, 0, SpringLayout.WEST, blackLabel);
        layout.putConstraint(SpringLayout.NORTH, suffixLabel, st, SpringLayout.SOUTH, blackLabel);

        container.add(suffixTextField);
        layout.putConstraint(SpringLayout.WEST, suffixTextField, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, suffixTextField, 0, SpringLayout.NORTH, suffixLabel);
        layout.putConstraint(SpringLayout.EAST, suffixTextField, Spring.minus(st), SpringLayout.EAST, container);

        // 错误 POC
        container.add(errorPocLabel);
        layout.putConstraint(SpringLayout.WEST, errorPocLabel, 0, SpringLayout.WEST, suffixLabel);
        layout.putConstraint(SpringLayout.NORTH, errorPocLabel, st, SpringLayout.SOUTH, suffixLabel);

        container.add(errorPocTextField);
        layout.putConstraint(SpringLayout.WEST, errorPocTextField, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, errorPocTextField, 0, SpringLayout.NORTH, errorPocLabel);
        layout.putConstraint(SpringLayout.EAST, errorPocTextField, Spring.minus(st), SpringLayout.EAST, container);

        // 参数黑名单
        container.add(blackParamsLabel);
        layout.putConstraint(SpringLayout.WEST, blackParamsLabel, 0, SpringLayout.WEST, errorPocLabel);
        layout.putConstraint(SpringLayout.NORTH, blackParamsLabel, st, SpringLayout.SOUTH, errorPocLabel);

        container.add(blackParamsField);
        layout.putConstraint(SpringLayout.WEST, blackParamsField, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, blackParamsField, 0, SpringLayout.NORTH, blackParamsLabel);
        layout.putConstraint(SpringLayout.EAST, blackParamsField, Spring.minus(st), SpringLayout.EAST, container);
    }

    private void setupCheckboxes(Container container, SpringLayout layout, JButton conBt,
            Spring st, Spring st2) {
        // 创建复选框
        switchCheck = new JCheckBox();
        cookieCheck = new JCheckBox();
        errorCheck = new JCheckBox();
        vulnCheck = new JCheckBox();
        numCheck = new JCheckBox();
        stringCheck = new JCheckBox();
        orderCheck = new JCheckBox();
        boolCheck = new JCheckBox();
        diyCheck = new JCheckBox();

        // 水平排列复选框
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

        // 确认按钮
        container.add(conBt);
        layout.putConstraint(SpringLayout.WEST, conBt, st2, SpringLayout.EAST, diyCheck);
        layout.putConstraint(SpringLayout.NORTH, conBt, 0, SpringLayout.NORTH, switchCheck);
    }

    private void setupConfigPath(Container container, SpringLayout layout, JLabel configLabel,
            JButton loadBt, JButton saveBt, JLabel blackLabel,
            Spring st, Spring st3, Spring st4) {
        // 创建配置路径文本框
        configTextField = new JTextField(TEXTFIELD_COLUMNS);
        configTextField.setEditable(false);
        // 显示配置文件路径
        ConfigManager configManager = new ConfigManager();
        configTextField.setText(configManager.getConfigPath().toString());

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
        // 创建黑名单路径文本区域
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
            JLabel timeLabel, JLabel staticTimeLabel,
            JLabel startTimeLabel, JLabel blackParamsLabel,
            Component blackPathScrollPane, Spring st) {
        // 创建 DIY payloads 文本区域
        diyTextArea = new JTextArea(TEXTAREA_ROWS_XLARGE, TEXTAREA_ROWS_MEDIUM);
        JScrollPane diyScrollPane = new JScrollPane();
        diyScrollPane.setViewportView(diyTextArea);
        diyTextArea.setLineWrap(true);

        // 创建响应正则文本区域
        regexTextArea = new JTextArea(10, TEXTAREA_ROWS_MEDIUM);
        JScrollPane regexScrollPane = new JScrollPane();
        regexScrollPane.setViewportView(regexTextArea);
        regexTextArea.setLineWrap(true);

        // 创建时间设置文本框
        timeTextField = new JTextField(TEXTAREA_ROWS_MEDIUM);
        staticTimeTextField = new JTextField(TEXTAREA_ROWS_MEDIUM);
        staticTimeTextField.setText("100");
        startTimeTextField = new JTextField(TEXTAREA_ROWS_MEDIUM);
        startTimeTextField.setText("0");
        JLabel endTimeLabel = new JLabel("-");
        endTimeTextField = new JTextField(TEXTAREA_ROWS_MEDIUM);
        endTimeTextField.setText("0");

        // 布局左列（DIY payloads）
        container.add(diyLabel);
        layout.putConstraint(SpringLayout.NORTH, diyLabel, st, SpringLayout.SOUTH, blackPathScrollPane);
        layout.putConstraint(SpringLayout.WEST, diyLabel, 0, SpringLayout.WEST, blackParamsLabel);

        container.add(diyScrollPane);
        layout.putConstraint(SpringLayout.WEST, diyScrollPane, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, diyScrollPane, 0, SpringLayout.NORTH, diyLabel);
        layout.putConstraint(SpringLayout.EAST, diyScrollPane, -PADDING_SMALL, SpringLayout.HORIZONTAL_CENTER,
                container);

        // 布局右列（响应正则和时间设置）
        container.add(resRegexLabel);
        layout.putConstraint(SpringLayout.WEST, resRegexLabel, PADDING_SMALL, SpringLayout.HORIZONTAL_CENTER,
                container);
        layout.putConstraint(SpringLayout.NORTH, resRegexLabel, st, SpringLayout.SOUTH, blackPathScrollPane);

        container.add(regexScrollPane);
        layout.putConstraint(SpringLayout.WEST, regexScrollPane, 25, SpringLayout.EAST, resRegexLabel);
        layout.putConstraint(SpringLayout.NORTH, regexScrollPane, 0, SpringLayout.NORTH, diyLabel);
        layout.putConstraint(SpringLayout.EAST, regexScrollPane, Spring.minus(st), SpringLayout.EAST, container);

        // 时间设置
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
        // 创建语言下拉框
        languageComboBox = new JComboBox<>(LANGUAGES);
        languageComboBox.setSelectedIndex(languageIndex);

        container.add(languageLabel);
        layout.putConstraint(SpringLayout.NORTH, languageLabel, st, SpringLayout.SOUTH, diyScrollPane);
        layout.putConstraint(SpringLayout.WEST, languageLabel, 0, SpringLayout.WEST, blackParamsLabel);

        container.add(languageComboBox);
        layout.putConstraint(SpringLayout.WEST, languageComboBox, 0, SpringLayout.WEST, textField);
        layout.putConstraint(SpringLayout.NORTH, languageComboBox, 0, SpringLayout.NORTH, languageLabel);
    }

    /**
     * 更新所有 UI 组件标签为当前语言
     */
    private void updateLanguageLabels(JLabel topicLabel, JLabel blackLabel, JLabel suffixLabel,
            JLabel errorPocLabel, JLabel blackParams, JLabel diyLabel,
            JLabel resRegexLabel, JLabel timeLabel, JLabel staticTimeLabel,
            JLabel startTimeLabel, JLabel blackPathLabel, JButton conBt,
            JButton loadBt, JButton saveBt, JLabel languageLabel,
            JLabel configLabel) {
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
     * 应用配置到运行时（不保存文件）
     * 提取的通用方法，供 handleConfirmButton 和 handleSaveButton 调用
     */
    private void applyConfigToRuntime() {
        String whiteList = textField.getText();
        if (!whiteList.isBlank()) {
            MyFilterRequest.whiteListSet = parseDelimitedString(whiteList);
        } else {
            MyFilterRequest.whiteListSet.clear();
        }

        String blackList = blackTextField.getText();
        if (!blackList.isBlank()) {
            MyFilterRequest.blackListSet = parseDelimitedString(blackList);
            // 重置诊断标志,以便下次过滤时输出新的配置
            MyFilterRequest.resetDiagnosticFlags();
            // 诊断日志: 显示配置更新
            api.logging().logToOutput("[DetSQL 配置更新] 域名黑名单已应用: " + MyFilterRequest.blackListSet);
        } else {
            MyFilterRequest.blackListSet.clear();
            MyFilterRequest.resetDiagnosticFlags();
            api.logging().logToOutput("[DetSQL 配置更新] 域名黑名单已清空");
        }

        String blackParamsList = blackParamsField.getText();
        if (!blackParamsList.isBlank()) {
            MyFilterRequest.blackParamsSet = parseDelimitedString(blackParamsList);
            MyFilterRequest.resetDiagnosticFlags();
            api.logging().logToOutput("[DetSQL 配置更新] 参数黑名单已应用: " + MyFilterRequest.blackParamsSet);
        } else {
            MyFilterRequest.blackParamsSet.clear();
            MyFilterRequest.resetDiagnosticFlags();
            api.logging().logToOutput("[DetSQL 配置更新] 参数黑名单已清空");
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
            config.setDiyPayloads(new HashSet<>());
        }

        String diyRegexsStr = regexTextArea.getText();
        if (!diyRegexsStr.isBlank()) {
            config.setDiyRegexs(readLinesFromTextArea(regexTextArea));
        } else {
            config.setDiyRegexs(new HashSet<>());
        }

        config.setDelayTimeMs(parseIntWithDefault(timeTextField.getText(), DefaultConfig.DEFAULT_DELAY_TIME_MS));
        config.setStaticTimeMs(
                parseIntWithDefault(staticTimeTextField.getText(), DefaultConfig.DEFAULT_STATIC_TIME_MS));
        config.setStartTimeMs(parseIntWithDefault(startTimeTextField.getText(), DefaultConfig.DEFAULT_START_TIME_MS));
        config.setEndTimeMs(parseIntWithDefault(endTimeTextField.getText(), DefaultConfig.DEFAULT_END_TIME_MS));

        String blackPathStr = blackPathTextArea.getText();
        if (!blackPathStr.isBlank()) {
            MyFilterRequest.blackPathSet = readLinesFromTextArea(blackPathTextArea);
            MyFilterRequest.resetDiagnosticFlags();
            api.logging().logToOutput("[INFO] ✓ 路径黑名单已应用到运行时 (" + MyFilterRequest.blackPathSet.size() + " 条规则)");
            if (MyFilterRequest.blackPathSet.size() <= 10) {
                for (String rule : MyFilterRequest.blackPathSet) {
                    api.logging().logToOutput("       • " + rule);
                }
            }
        } else {
            MyFilterRequest.blackPathSet.clear();
            MyFilterRequest.resetDiagnosticFlags();
            api.logging().logToOutput("[INFO] ℹ 路径黑名单已清空（所有路径将被检测）");
        }

        logger.info("配置已应用到运行时");
    }

    /**
     * 处理确认按钮点击事件
     * 仅应用配置到运行时，不保存到文件
     */
    private void handleConfirmButton() {
        try {
            // 应用配置到运行时
            applyConfigToRuntime();

            // 显示简洁的成功提示
            int blacklistCount = MyFilterRequest.blackListSet.size();
            int whitelistCount = MyFilterRequest.whiteListSet.size();
            int blackPathCount = MyFilterRequest.blackPathSet.size();
            int blackParamsCount = MyFilterRequest.blackParamsSet.size();
            int suffixCount = MyFilterRequest.unLegalExtensionSet.size();

            StringBuilder summary = new StringBuilder();
            summary.append("✓ 配置已应用到运行时\n\n");
            summary.append("═══════════════════════════════\n");
            summary.append(String.format("域名白名单: %d 个\n", whitelistCount));
            summary.append(String.format("域名黑名单: %d 个  %s\n", blacklistCount, blacklistCount > 0 ? "✓" : ""));
            summary.append(String.format("路径黑名单: %d 个  %s\n", blackPathCount, blackPathCount > 0 ? "✓" : ""));
            summary.append(String.format("参数黑名单: %d 个  %s\n", blackParamsCount, blackParamsCount > 0 ? "✓" : ""));
            summary.append(String.format("禁止后缀: %d 个\n", suffixCount));
            summary.append("═══════════════════════════════\n");
            summary.append("\n💡 提示: 如需永久保存，请点击\"保存\"按钮");

            javax.swing.JOptionPane.showMessageDialog(null, summary.toString(),
                    "✓ DetSQL 配置已应用",
                    javax.swing.JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            logger.error("应用配置失败: " + e.getMessage(), e);
            javax.swing.JOptionPane.showMessageDialog(null,
                    "❌ 应用配置失败: " + e.getMessage(),
                    "❌ DetSQL 配置错误",
                    javax.swing.JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 保存配置到文件（先应用后保存）
     * 从原 handleConfirmButton 中提取的保存逻辑
     */
    private void saveConfigToFile() {
        try {
            // 先应用配置到运行时
            applyConfigToRuntime();

            // 同步保存到 YAML 配置文件,确保重启后配置不丢失
            // 在保存前输出详细的配置状态日志（使用统一格式）
            api.logging().logToOutput("\n═══════════════════════════════════════");
            api.logging().logToOutput("  DetSQL 配置保存");
            api.logging().logToOutput("═══════════════════════════════════════");
            api.logging().logToOutput("[INFO] 准备保存配置到文件...");
            api.logging().logToOutput("[INFO] 当前运行时配置状态:");
            api.logging().logToOutput("  ├─ 域名白名单: " + MyFilterRequest.whiteListSet.size() + " 个");
            api.logging().logToOutput("  ├─ 域名黑名单: " + MyFilterRequest.blackListSet.size() + " 个" + 
                    (MyFilterRequest.blackListSet.isEmpty() ? "" : " " + MyFilterRequest.blackListSet));
            api.logging().logToOutput("  ├─ 路径黑名单: " + MyFilterRequest.blackPathSet.size() + " 个" +
                    (MyFilterRequest.blackPathSet.isEmpty() ? "" : " " + MyFilterRequest.blackPathSet));
            api.logging().logToOutput("  ├─ 参数黑名单: " + MyFilterRequest.blackParamsSet.size() + " 个" +
                    (MyFilterRequest.blackParamsSet.isEmpty() ? "" : " " + MyFilterRequest.blackParamsSet));
            api.logging().logToOutput("  └─ 禁止后缀: " + MyFilterRequest.unLegalExtensionSet.size() + " 个");

            // 直接使用 DetSqlUI 的 buildYamlConfig 方法构建配置对象，确保与卸载时保存的逻辑完全一致
            api.logging().logToOutput("[DEBUG] 开始构建 YAML 配置对象 (使用 DetSqlUI.buildYamlConfig)");
            DetSql.config.DetSqlYamlConfig yamlConfig = ui.buildYamlConfig();

            // 保存到文件
            api.logging().logToOutput("[INFO] 开始保存到文件...");
            ConfigManager configManager = new ConfigManager();
            configManager.saveConfig(yamlConfig);
            api.logging().logToOutput("[INFO] ✓ 配置已成功保存到文件");
            api.logging().logToOutput("       文件路径: " + configManager.getConfigPath());
            api.logging().logToOutput("═══════════════════════════════════════\n");

            // 显示简洁的成功提示，突出关键信息
            int blacklistCount = MyFilterRequest.blackListSet.size();
            int whitelistCount = MyFilterRequest.whiteListSet.size();
            int blackPathCount = MyFilterRequest.blackPathSet.size();
            int blackParamsCount = MyFilterRequest.blackParamsSet.size();
            int suffixCount = MyFilterRequest.unLegalExtensionSet.size();

            StringBuilder summary = new StringBuilder();
            summary.append("✓ 配置已成功应用并保存到文件\n\n");
            summary.append("═══════════════════════════════\n");
            summary.append(String.format("域名白名单: %d 个\n", whitelistCount));
            summary.append(String.format("域名黑名单: %d 个  %s\n", blacklistCount, blacklistCount > 0 ? "✓" : ""));
            summary.append(String.format("路径黑名单: %d 个  %s\n", blackPathCount, blackPathCount > 0 ? "✓" : ""));
            summary.append(String.format("参数黑名单: %d 个  %s\n", blackParamsCount, blackParamsCount > 0 ? "✓" : ""));
            summary.append(String.format("禁止后缀: %d 个\n", suffixCount));
            summary.append("═══════════════════════════════\n");

            // 添加空配置警告
            if (blacklistCount == 0 && whitelistCount == 0 && blackPathCount == 0 && blackParamsCount == 0) {
                summary.append("\n⚠️ 警告: 所有过滤规则均为空\n");
                summary.append("这意味着所有请求都会被检测。\n");
                summary.append("如果这不是您的预期，请检查输入框内容。\n");
            } else {
                summary.append("\n配置文件位置:\n");
                summary.append(configManager.getConfigPath().toString()).append("\n");
            }

            // 显示详细配置（折叠）
            if (blacklistCount > 0 && blacklistCount <= 5) {
                summary.append("\n域名黑名单: ");
                summary.append(String.join(", ", MyFilterRequest.blackListSet));
            }
            if (blackPathCount > 0 && blackPathCount <= 5) {
                summary.append("\n路径黑名单: ");
                summary.append(String.join(", ", MyFilterRequest.blackPathSet));
            }
            if (blackParamsCount > 0 && blackParamsCount <= 5) {
                summary.append("\n参数黑名单: ");
                summary.append(String.join(", ", MyFilterRequest.blackParamsSet));
            }

            // 使用更醒目的成功图标
            javax.swing.JOptionPane.showMessageDialog(null, summary.toString(),
                    "✓ DetSQL 配置已保存",
                    javax.swing.JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            // 记录详细错误信息到日志
            logger.error("保存配置文件失败: " + e.getMessage(), e);
            api.logging().logToError("\n═══════════════════════════════════════");
            api.logging().logToError("  DetSQL 配置保存失败");
            api.logging().logToError("═══════════════════════════════════════");
            api.logging().logToError("[ERROR] 配置保存失败: " + e.getMessage());
            api.logging().logToError("[ERROR] 异常类型: " + e.getClass().getName());
            api.logging().logToError("[ERROR] 堆栈跟踪:");
            for (StackTraceElement element : e.getStackTrace()) {
                api.logging().logToError("       at " + element.toString());
            }
            api.logging().logToError("═══════════════════════════════════════\n");

            e.printStackTrace(); // 输出完整堆栈跟踪以便调试

            // 显示用户友好的错误提示
            StringBuilder errorMsg = new StringBuilder();
            errorMsg.append("❌ 配置保存失败\n\n");
            errorMsg.append("错误信息: ").append(e.getMessage()).append("\n\n");
            errorMsg.append("可能的原因:\n");
            errorMsg.append("1. 配置文件没有写入权限\n");
            errorMsg.append("2. 磁盘空间不足\n");
            errorMsg.append("3. 配置内容包含无效字符\n\n");
            errorMsg.append("请在 Burp 的 Extensions → Output 标签页查看详细日志。");

            javax.swing.JOptionPane.showMessageDialog(null,
                    errorMsg.toString(),
                    "❌ DetSQL 配置错误",
                    javax.swing.JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 处理加载按钮点击事件
     */
    private void handleLoadButton() {
        File file = showFileChooser("Load", true);
        if (file == null) {
            JOptionPane.showMessageDialog(null, "Load cancel", "Load", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // 使用 SwingWorker 在后台线程执行 I/O 操作
        new javax.swing.SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                loadConfiguration(file);
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    configTextField.setText(file.getAbsolutePath());
                    JOptionPane.showMessageDialog(null, "Load success", "Load", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Load failed: " + ex.getMessage(), "Load",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    /**
     * 处理保存按钮点击事件
     *
     * 工作流程:
     * 1. 先应用配置到运行时并保存到默认 YAML 文件
     * 2. 提示用户配置已保存
     * 3. 询问是否需要导出到其他路径 (可选)
     */
    private void handleSaveButton() {
        // 应用配置到运行时并保存到文件
        saveConfigToFile();
        // 移除第二个弹窗：不再询问是否导出到其他路径
        // 用户如果需要导出，可以使用其他方式（如右键菜单或专门的导出按钮）
    }

    /**
     * 处理语言切换事件
     * 使用全局 LanguageManager 通知所有监听器
     */
    private void handleLanguageChange(JLabel topicLabel, JLabel blackLabel, JLabel suffixLabel,
            JLabel errorPocLabel, JLabel blackParamsLabel, JLabel diyLabel,
            JLabel resRegexLabel, JLabel timeLabel, JLabel staticTimeLabel,
            JLabel startTimeLabel, JLabel blackPathLabel, JButton conBt,
            JButton loadBt, JButton saveBt, JLabel languageLabel,
            JLabel configLabel) {
        int newLanguageIndex = languageComboBox.getSelectedIndex();

        // 使用全局 LanguageManager 通知所有监听器
        LanguageManager.getInstance().setLanguage(newLanguageIndex);

        // 更新本地状态
        languageIndex = newLanguageIndex;
        Locale locale = LOCALES[languageIndex];
        messages = ResourceBundle.getBundle("i18n/messages", locale);

        // 更新 ConfigPanel 自身的 UI 组件
        updateLanguageLabels(topicLabel, blackLabel, suffixLabel, errorPocLabel, blackParamsLabel,
                diyLabel, resRegexLabel, timeLabel, staticTimeLabel, startTimeLabel,
                blackPathLabel, conBt, loadBt, saveBt, languageLabel, configLabel);
    }

    /**
     * 显示文件选择对话框
     */
    private File showFileChooser(String dialogTitle, boolean isOpen) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle(dialogTitle);
        fileChooser.setCurrentDirectory(new File("."));
        fileChooser.setPreferredSize(new Dimension(FILE_CHOOSER_WIDTH, FILE_CHOOSER_HEIGHT));

        int result = isOpen ? fileChooser.showOpenDialog(null) : fileChooser.showSaveDialog(null);
        return (result == JFileChooser.APPROVE_OPTION) ? fileChooser.getSelectedFile() : null;
    }

    /**
     * 从配置文件加载配置
     */
    private void loadConfiguration(File configFile) {
        if (!configFile.exists()) {
            api.logging().logToError("配置文件不存在: " + configFile.getAbsolutePath());
            return;
        }

        try {
            // 使用 ConfigManager 正确加载 YAML 格式配置文件
            ConfigManager configManager = new ConfigManager();
            DetSqlYamlConfig yamlConfig = configManager.loadConfigFromFile(configFile.toPath());

            if (yamlConfig == null) {
                api.logging().logToError("配置加载失败: 无法解析配置文件");
                return;
            }

            // 转换为 Properties 格式以兼容现有 UI 逻辑
            Properties prop = yamlConfig.toProperties();
            applyConfiguration(prop);

            api.logging().logToOutput("配置已成功从 YAML 文件加载: " + configFile.getAbsolutePath());
        } catch (Exception ex) {
            api.logging().logToError("配置加载失败: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    /**
     * 应用配置到 UI 和运行时
     */
    private void applyConfiguration(Properties prop) {
        // 应用列表类型配置
        MyFilterRequest.whiteListSet = parseSetProperty(prop, "whitelist", new HashSet<>());
        MyFilterRequest.blackListSet = parseSetProperty(prop, "blacklist", new HashSet<>());
        MyFilterRequest.blackParamsSet = parseSetProperty(prop, "paramslist", new HashSet<>());

        // 重置诊断标志
        MyFilterRequest.resetDiagnosticFlags();

        // 诊断日志: 显示加载的配置
        if (!MyFilterRequest.blackListSet.isEmpty()) {
            api.logging().logToOutput("[DetSQL 配置加载] 域名黑名单: " + MyFilterRequest.blackListSet);
        } else {
            api.logging().logToOutput("[DetSQL 配置加载] 域名黑名单为空");
        }

        String suffixProp = prop.getProperty("suffixlist", "").trim();
        if (suffixProp.isBlank()) {
            MyFilterRequest.unLegalExtensionSet = new HashSet<>(DefaultConfig.DEFAULT_SUFFIX_SET);
        } else {
            MyFilterRequest.unLegalExtensionSet = parseDelimitedString(suffixProp);
        }

        // 更新 UI 文本框
        javax.swing.SwingUtilities.invokeLater(() -> {
            if (textField != null)
                textField.setText(prop.getProperty("whitelist", ""));
            if (blackTextField != null)
                blackTextField.setText(prop.getProperty("blacklist", ""));
            if (suffixTextField != null)
                suffixTextField.setText(prop.getProperty("suffixlist", DefaultConfig.DEFAULT_SUFFIX_LIST));
            if (errorPocTextField != null)
                errorPocTextField.setText(prop.getProperty("errpoclist", ""));
            if (blackParamsField != null)
                blackParamsField.setText(prop.getProperty("paramslist", ""));
            if (timeTextField != null)
                timeTextField.setText(prop.getProperty("delaytime", ""));
            if (staticTimeTextField != null)
                staticTimeTextField.setText(prop.getProperty("statictime", "100"));
            if (startTimeTextField != null)
                startTimeTextField.setText(prop.getProperty("starttime", "0"));
            if (endTimeTextField != null)
                endTimeTextField.setText(prop.getProperty("endtime", "0"));
            if (diyTextArea != null)
                diyTextArea.setText(prop.getProperty("diypayloads", ""));
            if (regexTextArea != null)
                regexTextArea.setText(prop.getProperty("diyregex", ""));
            if (blackPathTextArea != null)
                blackPathTextArea.setText(prop.getProperty("blackpath", ""));
        });

        // 应用整数配置
        config.setDelayTimeMs(
                parseIntWithDefault(prop.getProperty("delaytime", ""), DefaultConfig.DEFAULT_DELAY_TIME_MS));
        config.setStaticTimeMs(
                parseIntWithDefault(prop.getProperty("statictime", ""), DefaultConfig.DEFAULT_STATIC_TIME_MS));
        config.setStartTimeMs(
                parseIntWithDefault(prop.getProperty("starttime", ""), DefaultConfig.DEFAULT_START_TIME_MS));
        config.setEndTimeMs(parseIntWithDefault(prop.getProperty("endtime", ""), DefaultConfig.DEFAULT_END_TIME_MS));

        // 应用复选框配置
        javax.swing.SwingUtilities.invokeLater(() -> {
            if (switchCheck != null)
                switchCheck.setSelected(Boolean.parseBoolean(prop.getProperty("switch")));
            if (cookieCheck != null)
                cookieCheck.setSelected(Boolean.parseBoolean(prop.getProperty("cookiecheck")));
            if (errorCheck != null)
                errorCheck.setSelected(Boolean.parseBoolean(prop.getProperty("errorcheck")));
            if (vulnCheck != null)
                vulnCheck.setSelected(Boolean.parseBoolean(prop.getProperty("repeatercheck")));
            if (numCheck != null)
                numCheck.setSelected(Boolean.parseBoolean(prop.getProperty("numcheck")));
            if (stringCheck != null)
                stringCheck.setSelected(Boolean.parseBoolean(prop.getProperty("stringcheck")));
            if (orderCheck != null)
                orderCheck.setSelected(Boolean.parseBoolean(prop.getProperty("ordercheck")));
            if (boolCheck != null)
                boolCheck.setSelected(Boolean.parseBoolean(prop.getProperty("boolcheck")));
            if (diyCheck != null)
                diyCheck.setSelected(Boolean.parseBoolean(prop.getProperty("diycheck")));
        });

        // 应用错误 Payload 配置
        String errPocList = prop.getProperty("errpoclist", "");
        if (errPocList.isBlank()) {
            config.setErrorPayloads(DefaultConfig.DEFAULT_ERR_POCS.clone());
            config.setErrorPayloadsJson(DefaultConfig.DEFAULT_ERR_POCS_JSON.clone());
        } else {
            config.setErrorPayloads(errPocList.split("\\|"));
            config.setErrorPayloadsJson(deriveJsonErrPocs(config.getErrorPayloads()));
        }

        // 应用文本区域配置
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

        // 应用语言索引
        String languageIndexStr = prop.getProperty("languageindex", null);
        if (languageIndexStr != null) {
            languageIndex = parseIntWithDefault(languageIndexStr, 0);
        }
    }

    /**
     * 构建配置 Properties 对象
     */
    private Properties buildConfigProperties() {
        Properties prop = new Properties();
        prop.setProperty("whitelist", textField.getText());
        prop.setProperty("blacklist", blackTextField.getText());
        prop.setProperty("suffixlist", suffixTextField.getText());
        prop.setProperty("errpoclist", errorPocTextField.getText());
        prop.setProperty("paramslist", blackParamsField.getText());
        prop.setProperty("delaytime", timeTextField.getText());
        prop.setProperty("statictime", staticTimeTextField.getText());
        prop.setProperty("starttime", startTimeTextField.getText());
        prop.setProperty("endtime", endTimeTextField.getText());
        prop.setProperty("switch", String.valueOf(switchCheck.isSelected()));
        prop.setProperty("cookiecheck", String.valueOf(cookieCheck.isSelected()));
        prop.setProperty("errorcheck", String.valueOf(errorCheck.isSelected()));
        prop.setProperty("numcheck", String.valueOf(numCheck.isSelected()));
        prop.setProperty("stringcheck", String.valueOf(stringCheck.isSelected()));
        prop.setProperty("ordercheck", String.valueOf(orderCheck.isSelected()));
        prop.setProperty("repeatercheck", String.valueOf(vulnCheck.isSelected()));
        prop.setProperty("boolcheck", String.valueOf(boolCheck.isSelected()));
        prop.setProperty("diycheck", String.valueOf(diyCheck.isSelected()));
        prop.setProperty("diypayloads", diyTextArea.getText());
        prop.setProperty("diyregex", regexTextArea.getText());
        prop.setProperty("blackpath", blackPathTextArea.getText());
        prop.setProperty("languageindex", String.valueOf(languageIndex));
        return prop;
    }

    // ========== 辅助方法 ==========

    private Set<String> parseSetProperty(Properties prop, String key, Set<String> defaultValue) {
        String value = prop.getProperty(key, "");
        if (value.isBlank()) {
            return defaultValue;
        }
        return parseDelimitedString(value);
    }

    private static Set<String> parseDelimitedString(String input) {
        return StringUtils.parseDelimitedString(input);
    }

    private Set<String> readLinesFromTextArea(JTextArea textArea) {
        Set<String> result = new HashSet<>();
        javax.swing.text.Element paragraph = textArea.getDocument().getDefaultRootElement();
        int contentCount = paragraph.getElementCount();
        for (int i = 0; i < contentCount; i++) {
            javax.swing.text.Element ee = paragraph.getElement(i);
            int rangeStart = ee.getStartOffset();
            int rangeEnd = ee.getEndOffset();
            try {
                String line = textArea.getText(rangeStart, rangeEnd - rangeStart)
                        .replaceFirst("[\n\r]+$", "");
                if (!line.isBlank()) {
                    result.add(line);
                }
            } catch (javax.swing.text.BadLocationException ex) {
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

    private static String[] deriveJsonErrPocs(String[] base) {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        for (String s : base) {
            if (s == null)
                continue;
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

    // ========== Getter 方法（供外部访问 UI 组件状态）==========

    public boolean isSwitchEnabled() {
        return switchCheck.isSelected();
    }

    public boolean isCookieCheckEnabled() {
        return cookieCheck.isSelected();
    }

    public boolean isErrorCheckEnabled() {
        return errorCheck.isSelected();
    }

    public boolean isVulnCheckEnabled() {
        return vulnCheck.isSelected();
    }

    public boolean isNumCheckEnabled() {
        return numCheck.isSelected();
    }

    public boolean isStringCheckEnabled() {
        return stringCheck.isSelected();
    }

    public boolean isOrderCheckEnabled() {
        return orderCheck.isSelected();
    }

    public boolean isBoolCheckEnabled() {
        return boolCheck.isSelected();
    }

    public boolean isDiyCheckEnabled() {
        return diyCheck.isSelected();
    }

    public int getLanguageIndex() {
        return languageIndex;
    }
}

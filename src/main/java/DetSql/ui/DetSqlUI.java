/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import DetSql.ui.ConfigPanel;
import DetSql.ui.CodeToolPanel;
import DetSql.util.LRUCache;

import javax.swing.*;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;
import DetSql.config.DefaultConfig;
import DetSql.config.DetSqlConfig;
import DetSql.config.DetSqlYamlConfig;
import DetSql.core.MyHttpHandler;
import DetSql.logging.DetSqlLogger;
import DetSql.model.PocLogEntry;
import DetSql.model.PocTableModel;
import DetSql.model.SourceLogEntry;
import DetSql.model.SourceTableModel;
import DetSql.util.Statistics;

/**
 * DetSql 主 UI 面板
 * 重构后：只负责组装各个子面板,不包含具体业务逻辑
 * 
 * 实现 LanguageChangeListener 以响应全局语言变更事件
 */
public class DetSqlUI implements LanguageChangeListener {
    MontoyaApi api;
    public MyHttpHandler myHttpHandler;
    public SourceTableModel sourceTableModel;
    public Map<String, List<PocLogEntry>> attackMap;
    private DetSqlConfig config;
    private DetSqlLogger logger;
    private Statistics statistics;
    private DetSqlYamlConfig yamlConfig;

    // UI 组件
    private JTabbedPane tabbedPane1; // 保存引用以便更新 Tab 标题
    private JButton clearButton; // 清理历史按钮
    private JTable table1;
    private JTable table2;
    private JLabel statsTestedLabel;
    private JLabel statsVulnLabel;
    private javax.swing.Timer statsTimer;

    // 子面板（公开访问以支持测试）
    private ConfigPanel configPanel;
    private CodeToolPanel codeToolPanel;

    // 布局常量
    private static final int TOP_BAR_MAX_HEIGHT = 40;
    private static final int TAB_STRIP_HEIGHT = 36;
    private static final double SPLITPANE_RESIZE_WEIGHT = 0.5;

    // ========== Getter 方法（供其他类访问 UI 组件状态）==========

    public boolean isSwitchCheckSelected() {
        return configPanel != null && configPanel.isSwitchEnabled();
    }

    public boolean isCookieCheckSelected() {
        return configPanel != null && configPanel.isCookieCheckEnabled();
    }

    public boolean isErrorCheckSelected() {
        return configPanel != null && configPanel.isErrorCheckEnabled();
    }

    public boolean isVulnCheckSelected() {
        return configPanel != null && configPanel.isVulnCheckEnabled();
    }

    public boolean isNumCheckSelected() {
        return configPanel != null && configPanel.isNumCheckEnabled();
    }

    public boolean isStringCheckSelected() {
        return configPanel != null && configPanel.isStringCheckEnabled();
    }

    public boolean isOrderCheckSelected() {
        return configPanel != null && configPanel.isOrderCheckEnabled();
    }

    public boolean isBoolCheckSelected() {
        return configPanel != null && configPanel.isBoolCheckEnabled();
    }

    public boolean isDiyCheckSelected() {
        return configPanel != null && configPanel.isDiyCheckEnabled();
    }

    public int getLanguageIndex() {
        return configPanel != null ? configPanel.getLanguageIndex() : 0;
    }

    // ========== Getter 方法（为 UI 组件提供访问）==========

    public JTable getTable1() {
        return table1;
    }

    public JTable getTable2() {
        return table2;
    }

    public ConfigPanel getConfigPanel() {
        return configPanel;
    }

    public CodeToolPanel getCodeToolPanel() {
        return codeToolPanel;
    }

    /**
     * 构建配置 Properties 对象（供保存配置使用）
     * 
     * @deprecated 使用 buildYamlConfig() 替代,统一为 YAML 格式
     */
    @Deprecated
    public Properties buildConfigProperties() {
        Properties prop = new Properties();
        // 从 config 对象获取配置值
        prop.setProperty("whitelist", String.join("|", MyFilterRequest.whiteListSet));
        prop.setProperty("blacklist", String.join("|", MyFilterRequest.blackListSet));
        prop.setProperty("suffixlist", String.join("|", MyFilterRequest.unLegalExtensionSet));
        prop.setProperty("errpoclist", String.join("|", config.getErrorPayloads()));
        prop.setProperty("paramslist", String.join("|", MyFilterRequest.blackParamsSet));
        prop.setProperty("delaytime", String.valueOf(config.getDelayTimeMs()));
        prop.setProperty("statictime", String.valueOf(config.getStaticTimeMs()));
        prop.setProperty("starttime", String.valueOf(config.getStartTimeMs()));
        prop.setProperty("endtime", String.valueOf(config.getEndTimeMs()));
        prop.setProperty("switch", String.valueOf(isSwitchCheckSelected()));
        prop.setProperty("cookiecheck", String.valueOf(isCookieCheckSelected()));
        prop.setProperty("errorcheck", String.valueOf(isErrorCheckSelected()));
        prop.setProperty("numcheck", String.valueOf(isNumCheckSelected()));
        prop.setProperty("stringcheck", String.valueOf(isStringCheckSelected()));
        prop.setProperty("ordercheck", String.valueOf(isOrderCheckSelected()));
        prop.setProperty("repeatercheck", String.valueOf(isVulnCheckSelected()));
        prop.setProperty("boolcheck", String.valueOf(isBoolCheckSelected()));
        prop.setProperty("diycheck", String.valueOf(isDiyCheckSelected()));
        prop.setProperty("diypayloads", String.join("\\n", config.getDiyPayloads()));
        prop.setProperty("diyregex", String.join("\\n", config.getDiyRegexs()));
        prop.setProperty("blackpath", String.join("\\n", MyFilterRequest.blackPathSet));
        prop.setProperty("languageindex", String.valueOf(getLanguageIndex()));
        return prop;
    }

    /**
     * 构建 YAML 配置对象(供保存配置使用)
     * 从 UI 组件收集当前配置并创建 DetSqlYamlConfig 对象
     */
    public DetSqlYamlConfig buildYamlConfig() {
        DetSqlYamlConfig yamlConfig = new DetSqlYamlConfig();

        // 域名过滤配置
        yamlConfig.setWhitelist(new ArrayList<>(MyFilterRequest.whiteListSet));
        yamlConfig.setBlacklist(new ArrayList<>(MyFilterRequest.blackListSet));
        yamlConfig.setSuffixlist(new ArrayList<>(MyFilterRequest.unLegalExtensionSet));
        yamlConfig.setParamslist(new ArrayList<>(MyFilterRequest.blackParamsSet));

        // 路径黑名单(多行文本)
        yamlConfig.setBlackpath(String.join("\n", MyFilterRequest.blackPathSet));

        // Payload 配置
        yamlConfig.setErrpoclist(Arrays.asList(config.getErrorPayloads()));
        yamlConfig.setDiypayloads(String.join("\n", config.getDiyPayloads()));
        yamlConfig.setDiyregex(String.join("\n", config.getDiyRegexs()));

        // 时间配置
        yamlConfig.setDelaytime((int) config.getDelayTimeMs());
        yamlConfig.setStatictime((int) config.getStaticTimeMs());
        yamlConfig.setStarttime((int) config.getStartTimeMs());
        yamlConfig.setEndtime((int) config.getEndTimeMs());

        // 检测开关配置
        yamlConfig.setSwitchEnabled(isSwitchCheckSelected());
        yamlConfig.setCookiecheck(isCookieCheckSelected());
        yamlConfig.setErrorcheck(isErrorCheckSelected());
        yamlConfig.setNumcheck(isNumCheckSelected());
        yamlConfig.setStringcheck(isStringCheckSelected());
        yamlConfig.setOrdercheck(isOrderCheckSelected());
        yamlConfig.setRepeatercheck(isVulnCheckSelected());
        yamlConfig.setBoolcheck(isBoolCheckSelected());
        yamlConfig.setDiycheck(isDiyCheckSelected());

        // 语言配置
        yamlConfig.setLanguageindex(getLanguageIndex());

        return yamlConfig;
    }

    /**
     * 构造函数：初始化 UI 组件
     */
    public DetSqlUI(MontoyaApi api, DetSqlConfig config, DetSqlLogger logger,
            Statistics statistics, DetSqlYamlConfig yamlConfig) {
        this.api = api;
        this.config = config;
        this.logger = logger;
        this.statistics = statistics;
        this.yamlConfig = yamlConfig;

        // 创建数据模型
        sourceTableModel = new SourceTableModel();
        PocTableModel pocTableModel = new PocTableModel();

        // 使用 LRU 缓存限制内存使用（最多保留 10000 个请求）
        attackMap = Collections.synchronizedMap(new LRUCache<>(10000));
        myHttpHandler = new MyHttpHandler(api, sourceTableModel, pocTableModel, attackMap,
                config, logger, statistics, this);

        // 注册语言变更监听器
        LanguageManager.getInstance().addListener(this);
    }

    /**
     * 创建主 UI 组件
     */
    public Component createMainComponent() {
        Component component = getComponent(sourceTableModel, new PocTableModel());

        // UI 组件创建完成后，应用 YAML 配置
        if (yamlConfig != null && configPanel != null) {
            applyYamlConfigurationToPanel(yamlConfig);
        }

        return component;
    }

    /**
     * 获取 MyHttpHandler 实例
     */
    public MyHttpHandler getHttpHandler() {
        return myHttpHandler;
    }

    private Component getComponent(SourceTableModel tableModel, PocTableModel pocTableModel) {
        JPanel root = new JPanel();
        tabbedPane1 = new JTabbedPane(); // 使用类字段而非局部变量
        tabbedPane1.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);

        JSplitPane splitPane1 = new JSplitPane();
        JSplitPane splitPane2 = new JSplitPane();
        JScrollPane scrollPane1 = new JScrollPane();
        JScrollPane scrollPane2 = new JScrollPane();
        JSplitPane splitPane3 = new JSplitPane();

        UserInterface userInterface = api.userInterface();
        final HttpRequestEditor requestViewer = userInterface.createHttpRequestEditor(READ_ONLY);
        final HttpResponseEditor responseViewer = userInterface.createHttpResponseEditor(READ_ONLY);

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

        // 创建表格1（源请求表）
        table1 = new JTable(tableModel) {
            @Override
            public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
                SourceLogEntry logEntry = tableModel.get(table1.convertRowIndexToModel(rowIndex));

                // 优先获取完整的 HttpRequestResponse
                HttpRequestResponse fullResponse = logEntry.getHttpRequestResponse();

                if (fullResponse != null) {
                    // 有完整的请求和响应
                    requestViewer.setRequest(fullResponse.request());
                    responseViewer.setResponse(fullResponse.response());
                } else {
                    // Response 已被释放，尝试获取仅保留的 Request
                    HttpRequest requestOnly = logEntry.getRequest();
                    if (requestOnly != null) {
                        requestViewer.setRequest(requestOnly);
                        // 显示提示信息
                        String hint = "【响应已释放】\n\n为节省内存，无漏洞请求的响应已被回收。\n请求包内容如上所示。";
                        responseViewer.setResponse(
                            burp.api.montoya.http.message.responses.HttpResponse.httpResponse(hint));
                    } else {
                        // 完全没有数据
                        requestViewer.setRequest(HttpRequest.httpRequest());
                        responseViewer.setResponse(
                            burp.api.montoya.http.message.responses.HttpResponse.httpResponse());
                    }
                }

                super.changeSelection(rowIndex, columnIndex, toggle, extend);

                // 更新 table2 显示 POC 详情
                String sm3Hash = logEntry.getMyHash();
                List<PocLogEntry> pocLogEntries = myHttpHandler.attackMap.get(sm3Hash);

                // 检查是否有漏洞详情数据
                if (pocLogEntries == null || pocLogEntries.isEmpty()) {
                    // 清空 table2 并显示提示信息
                    pocTableModel.replaceAll(null);

                    // 检查状态,显示相应提示
                    String vulnState = logEntry.getVulnState();
                    if ("run".equals(vulnState)) {
                        // 正在检测中
                        api.logging().logToOutput("正在检测中,请稍候...");
                    } else if (vulnState == null || vulnState.isEmpty() || "手动停止".equals(vulnState)) {
                        // 未发现漏洞
                        api.logging().logToOutput("该请求未发现漏洞");
                    } else {
                        // 其他状态
                        api.logging().logToOutput("暂无漏洞详情数据");
                    }
                } else {
                    pocTableModel.replaceAll(pocLogEntries);
                }
            }
        };

        // 设置表格排序
        TableRowSorter<SourceTableModel> sorter = new TableRowSorter<>(tableModel);
        sorter.setComparator(0, (o1, o2) -> {
            String str1 = o1.toString();
            String str2 = o2.toString();
            return Integer.compare(parseIntWithDefault(str1, 0), parseIntWithDefault(str2, 0));
        });
        sorter.setComparator(5, (o1, o2) -> {
            String str1 = o1.toString();
            String str2 = o2.toString();
            return Integer.compare(parseIntWithDefault(str1, 0), parseIntWithDefault(str2, 0));
        });
        table1.setRowSorter(sorter);
        table1.setEnabled(true);
        table1.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        // 设置列宽
        table1.getColumnModel().getColumn(0).setPreferredWidth(50);
        table1.getColumnModel().getColumn(1).setPreferredWidth(80);
        table1.getColumnModel().getColumn(2).setPreferredWidth(80);
        table1.getColumnModel().getColumn(3).setPreferredWidth(150);
        table1.getColumnModel().getColumn(4).setPreferredWidth(300);
        table1.getColumnModel().getColumn(5).setPreferredWidth(100);
        table1.getColumnModel().getColumn(6).setPreferredWidth(120);

        // 添加右键菜单
        setupTable1ContextMenu(table1, tableModel);

        // 创建表格2（POC 表）
        table2 = new JTable(pocTableModel) {
            @Override
            public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
                // 智能回退逻辑: WeakReference 命中时显示完整响应, GC 回收后显示预览
                PocLogEntry entry = pocTableModel.get(table2.convertRowIndexToModel(rowIndex));
                HttpRequestResponse resp = entry.getHttpRequestResponse();

                if (resp != null) {
                    // ✅ 成功获取完整响应（WeakReference 命中）
                    requestViewer.setRequest(resp.request());
                    responseViewer.setResponse(resp.response());
                } else {
                    // ⚠️ 响应已被 GC 清理,显示降级预览
                    requestViewer.setRequest(HttpRequest.httpRequest());

                    // 构造降级响应体,包含预览和提示信息
                    String fallbackBody = String.format(
                            "【响应已清理】\n\n" +
                                    "为节省内存,完整响应已被回收。\n" +
                                    "以下是保留的预览内容（前 500 字符）：\n\n" +
                                    "----------------------------------------\n" +
                                    "%s\n" +
                                    "----------------------------------------\n\n" +
                                    "如需查看完整响应,请在 Burp HTTP History 中查找:\n" +
                                    "URL: %s\n" +
                                    "Method: %s",
                            entry.getResponsePreview(),
                            entry.getUrl(),
                            entry.getMethod());

                    responseViewer.setResponse(
                            burp.api.montoya.http.message.responses.HttpResponse.httpResponse(fallbackBody));

                    // 同时在日志中提示
                    api.logging().logToOutput(
                            String.format(
                                    "[Table2] 响应已被清理 - URL: %s, Method: %s\n预览: %s",
                                    entry.getUrl(),
                                    entry.getMethod(),
                                    entry.getResponsePreview().substring(0,
                                            Math.min(100, entry.getResponsePreview().length())) + "..."));
                }
                super.changeSelection(rowIndex, columnIndex, toggle, extend);
            }
        };

        TableRowSorter<PocTableModel> sorter1 = new TableRowSorter<>(pocTableModel);
        sorter1.setComparator(5, (o1, o2) -> {
            String str1 = o1.toString();
            String str2 = o2.toString();
            try {
                return (int) (Double.parseDouble(str1) * 1000 - Double.parseDouble(str2) * 1000);
            } catch (NumberFormatException e) {
                return 0;
            }
        });
        table2.setRowSorter(sorter1);

        // 设置根面板布局
        root.setLayout(new BorderLayout());

        // 顶部栏：选项卡和统计信息
        JPanel topBar = new JPanel(new BorderLayout()) {
            @Override
            public Dimension getPreferredSize() {
                Dimension d = super.getPreferredSize();
                return new Dimension(d.width, Math.min(d.height, TOP_BAR_MAX_HEIGHT));
            }
        };

        // 左侧：清理按钮
        clearButton = new JButton(Messages.getString("button.clear_history"));
        clearButton.addActionListener(e -> handleClearHistory());
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        leftPanel.add(clearButton);

        // 右侧：统计信息
        JPanel statsRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 0));
        statsTestedLabel = new JLabel(Messages.getString("label.tested") + ": 0");
        statsVulnLabel = new JLabel(Messages.getString("label.vulns") + ": 0");
        statsRow.add(statsTestedLabel);
        statsRow.add(statsVulnLabel);

        topBar.add(leftPanel, BorderLayout.WEST);
        topBar.add(tabbedPane1, BorderLayout.CENTER);
        topBar.add(statsRow, BorderLayout.EAST);
        root.add(topBar, BorderLayout.NORTH);

        // 内容区域使用 CardLayout
        JPanel contentCards = new JPanel(new CardLayout());

        // 设置分割面板
        splitPane1.setOrientation(JSplitPane.VERTICAL_SPLIT);
        scrollPane1.setViewportView(table1);
        splitPane2.setLeftComponent(scrollPane1);
        scrollPane2.setViewportView(table2);
        splitPane2.setRightComponent(scrollPane2);
        splitPane2.setResizeWeight(SPLITPANE_RESIZE_WEIGHT);
        splitPane1.setTopComponent(splitPane2);

        splitPane3.setLeftComponent(tabbedPane2);
        splitPane3.setRightComponent(tabbedPane3);
        splitPane3.setResizeWeight(SPLITPANE_RESIZE_WEIGHT);
        splitPane1.setBottomComponent(splitPane3);

        // 创建子面板
        configPanel = new ConfigPanel(api, config, logger, yamlConfig.getLanguageindex(), this);
        codeToolPanel = new CodeToolPanel();

        // 注册内容到卡片布局
        contentCards.add("DashBoard", splitPane1);
        contentCards.add("Config", configPanel);
        contentCards.add("CodeTool", codeToolPanel);

        // 添加选项卡
        tabbedPane1.addTab("DashBoard", new JPanel());
        tabbedPane1.addTab("Config", new JPanel());
        tabbedPane1.addTab("CodeTool", new JPanel());

        final String[] CARD_KEYS = { "DashBoard", "Config", "CodeTool" };
        tabbedPane1.addChangeListener(e -> {
            int idx = tabbedPane1.getSelectedIndex();
            if (idx >= 0 && idx < CARD_KEYS.length) {
                CardLayout cl = (CardLayout) contentCards.getLayout();
                cl.show(contentCards, CARD_KEYS[idx]);
            }
        });

        ((CardLayout) contentCards.getLayout()).show(contentCards, "DashBoard");
        root.add(contentCards, BorderLayout.CENTER);
        tabbedPane1.setPreferredSize(new Dimension(Integer.MAX_VALUE, TAB_STRIP_HEIGHT));

        // 启动统计定时器
        startStatsTimer();

        return root;
    }

    /**
     * 设置表格1的右键菜单
     */
    private void setupTable1ContextMenu(JTable table, SourceTableModel tableModel) {
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

        // 删除选中行
        menuItem1.addActionListener(e -> {
            int[] selectedRows = table.getSelectedRows();
            for (int i = selectedRows.length - 1; i >= 0; i--) {
                int viewIndex = selectedRows[i];
                int modelIndex = table.convertRowIndexToModel(viewIndex);
                Object state = tableModel.getValueAt(modelIndex, 6);
                if (!"run".equals(state)) {
                    try {
                        SourceLogEntry entry = tableModel.get(modelIndex);
                        if (entry != null && entry.getMyHash() != null && myHttpHandler != null
                                && myHttpHandler.attackMap != null) {
                            myHttpHandler.attackMap.remove(entry.getMyHash());
                        }
                    } catch (Exception ignore) {
                    }
                    tableModel.remove(modelIndex);
                }
            }
        });

        // 删除无漏洞历史
        menuItem2.addActionListener(e -> {
            for (int i = tableModel.getRowCount() - 1; i >= 0; i--) {
                int modelIndex = table.convertRowIndexToModel(i);
                Object state = tableModel.getValueAt(modelIndex, 6);
                if (state != null && (state.toString().isEmpty() || "手动停止".equals(state))) {
                    try {
                        SourceLogEntry entry = tableModel.get(modelIndex);
                        if (entry != null && entry.getMyHash() != null && myHttpHandler != null
                                && myHttpHandler.attackMap != null) {
                            myHttpHandler.attackMap.remove(entry.getMyHash());
                        }
                    } catch (Exception ignore) {
                    }
                    tableModel.remove(modelIndex);
                }
            }
        });

        // 导出 Burp 日志
        exportBurpLog.addActionListener(e -> {
            int[] selectedRows = table.getSelectedRows();
            if (selectedRows == null || selectedRows.length == 0)
                return;

            javax.swing.JFileChooser fileChooser = new javax.swing.JFileChooser();
            fileChooser.setSelectedFile(new java.io.File("burp_log.txt"));
            if (fileChooser.showSaveDialog(null) != javax.swing.JFileChooser.APPROVE_OPTION) {
                return;
            }
            java.io.File file = fileChooser.getSelectedFile();

            java.util.List<HttpRequestResponse> originalRequests = new java.util.ArrayList<>();
            for (int viewIndex : selectedRows) {
                int modelIndex = table.convertRowIndexToModel(viewIndex);
                SourceLogEntry sourceEntry = tableModel.get(modelIndex);
                if (sourceEntry == null)
                    continue;
                if (sourceEntry.getHttpRequestResponse() != null) {
                    originalRequests.add(sourceEntry.getHttpRequestResponse());
                }
            }

            if (originalRequests.isEmpty()) {
                javax.swing.JOptionPane.showMessageDialog(null, "选中记录未包含可导出的原始请求", "提示",
                        javax.swing.JOptionPane.WARNING_MESSAGE);
                return;
            }

            new javax.swing.SwingWorker<String, Void>() {
                @Override
                protected String doInBackground() throws Exception {
                    String separator = "======================================================";
                    try (java.io.FileOutputStream out = new java.io.FileOutputStream(file)) {
                        byte[] sepBytes = (separator + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        for (HttpRequestResponse req : originalRequests) {
                            out.write(sepBytes);
                            String timestamp = java.time.LocalTime.now()
                                    .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"));
                            String url = req.request().url();
                            byte[] requestBytes = req.request().toByteArray().getBytes();
                            String ipAddress = req.httpService().ipAddress();
                            String metadataLine = String.format("%s  %s  [%s]\n", timestamp, url, ipAddress);
                            out.write(metadataLine.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                            out.write(sepBytes);
                            out.write(requestBytes);
                            out.write('\n');
                            out.write(sepBytes);
                            out.write("\n\n\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        }
                    }
                    return String.format("已导出 %d 个原始请求\n文件：%s\n\n使用方法：sqlmap -l %s --batch",
                            originalRequests.size(), file.getAbsolutePath(), file.getName());
                }

                @Override
                protected void done() {
                    try {
                        String message = get();
                        javax.swing.JOptionPane.showMessageDialog(null, message, "导出成功",
                                javax.swing.JOptionPane.INFORMATION_MESSAGE);
                    } catch (Exception ex) {
                        javax.swing.JOptionPane.showMessageDialog(null, "导出失败：" + ex.getMessage(), "错误",
                                javax.swing.JOptionPane.ERROR_MESSAGE);
                    }
                }
            }.execute();
        });

        // 复制漏洞参数
        copyParams.addActionListener(e -> {
            int[] selectedRows = table.getSelectedRows();
            if (selectedRows == null || selectedRows.length == 0)
                return;

            // 使用 SwingWorker 避免 UI 阻塞
            new javax.swing.SwingWorker<String, Void>() {
                @Override
                protected String doInBackground() throws Exception {
                    // 后台线程：执行耗时的数据处理
                    java.util.Set<String> params = new java.util.TreeSet<>();
                    for (int viewIndex : selectedRows) {
                        int modelIndex = table.convertRowIndexToModel(viewIndex);
                        SourceLogEntry sourceEntry = tableModel.get(modelIndex);
                        if (sourceEntry == null)
                            continue;
                        String myHash = sourceEntry.getMyHash();
                        if (myHash == null)
                            continue;
                        java.util.List<PocLogEntry> entries = myHttpHandler.attackMap.get(myHash);
                        if (entries == null)
                            continue;
                        for (PocLogEntry pe : entries) {
                            String name = pe.getName();
                            if (name != null && !name.isEmpty())
                                params.add(name);
                        }
                    }

                    if (params.isEmpty()) {
                        return null; // 特殊值表示未找到参数
                    }
                    return String.join(",", params);
                }

                @Override
                protected void done() {
                    // EDT 线程：执行 UI 更新
                    try {
                        String result = get();
                        if (result == null) {
                            javax.swing.JOptionPane.showMessageDialog(null,
                                    "选中的记录中未找到参数", "提示",
                                    javax.swing.JOptionPane.WARNING_MESSAGE);
                        } else {
                            // 设置剪贴板
                            java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(
                                    result);
                            java.awt.datatransfer.Clipboard clipboard = java.awt.Toolkit.getDefaultToolkit()
                                    .getSystemClipboard();
                            clipboard.setContents(selection, selection);

                            // 计算参数数量
                            int paramCount = result.split(",").length;
                            String message = String.format("已复制 %d 个参数到剪贴板：\n%s", paramCount, result);
                            javax.swing.JOptionPane.showMessageDialog(null, message,
                                    "复制成功", javax.swing.JOptionPane.INFORMATION_MESSAGE);
                        }
                    } catch (Exception ex) {
                        javax.swing.JOptionPane.showMessageDialog(null,
                                "复制失败：" + ex.getMessage(), "错误",
                                javax.swing.JOptionPane.ERROR_MESSAGE);
                    }
                }
            }.execute();
        });

        // 弹出菜单监听器
        popupMenu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                int selectedCount = table.getSelectedRowCount();
                boolean hasSelection = selectedCount > 0;
                exportBurpLog.setEnabled(hasSelection);
                copyParams.setEnabled(hasSelection);
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
            }
        });

        // 鼠标监听器
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupMenu.show(table, e.getX(), e.getY());
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupMenu.show(table, e.getX(), e.getY());
                }
            }
        });
    }

    /**
     * 启动统计定时器
     */
    private void startStatsTimer() {
        if (statsTimer != null) {
            statsTimer.stop();
        }
        statsTimer = new javax.swing.Timer(1000, e -> updateStats());
        statsTimer.setRepeats(true);
        statsTimer.start();
    }

    /**
     * 更新统计信息
     */
    private void updateStats() {
        try {
            int tested = (statistics != null) ? statistics.getRequestsProcessed() : 0;
            int vulns = (statistics != null) ? statistics.getVulnerabilitiesFound() : 0;
            final int fTested = tested;
            final int fVulns = vulns;
            SwingUtilities.invokeLater(() -> {
                statsTestedLabel.setText(Messages.getString("label.tested") + ": " + fTested);
                statsVulnLabel.setText(Messages.getString("label.vulns") + ": " + fVulns);
            });
        } catch (Exception ignore) {
        }
    }

    /**
     * 处理清理历史记录
     */
    private void handleClearHistory() {
        int confirm = JOptionPane.showConfirmDialog(
                null,
                Messages.getString("confirm.clear_history"),
                Messages.getString("title.confirm"),
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            // 清理数据
            attackMap.clear();
            sourceTableModel.clear();
            if (statistics != null) {
                statistics.reset();
            }
            logger.info(Messages.getString("log.history_cleared"));
            JOptionPane.showMessageDialog(
                    null,
                    Messages.getString("message.history_cleared"),
                    Messages.getString("title.confirm"),
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * 将 YAML 配置应用到配置面板
     */
    private void applyYamlConfigurationToPanel(DetSqlYamlConfig yamlConfig) {
        // 应用过滤器配置到静态字段
        MyFilterRequest.whiteListSet = new HashSet<>(yamlConfig.getWhitelist());
        MyFilterRequest.blackListSet = new HashSet<>(yamlConfig.getBlacklist());
        MyFilterRequest.blackParamsSet = new HashSet<>(yamlConfig.getParamslist());

        if (yamlConfig.getSuffixlist().isEmpty()) {
            MyFilterRequest.unLegalExtensionSet = new HashSet<>(DefaultConfig.DEFAULT_SUFFIX_SET);
        } else {
            MyFilterRequest.unLegalExtensionSet = new HashSet<>(yamlConfig.getSuffixlist());
        }

        // 更新 ConfigPanel 的 UI 组件
        SwingUtilities.invokeLater(() -> {
            if (configPanel.textField != null)
                configPanel.textField.setText(String.join("|", yamlConfig.getWhitelist()));
            if (configPanel.blackTextField != null)
                configPanel.blackTextField.setText(String.join("|", yamlConfig.getBlacklist()));
            if (configPanel.suffixTextField != null) {
                String suffixText = yamlConfig.getSuffixlist().isEmpty() ? DefaultConfig.DEFAULT_SUFFIX_LIST
                        : String.join("|", yamlConfig.getSuffixlist());
                configPanel.suffixTextField.setText(suffixText);
            }
            if (configPanel.errorPocTextField != null)
                configPanel.errorPocTextField.setText(String.join("|", yamlConfig.getErrpoclist()));
            if (configPanel.blackParamsField != null)
                configPanel.blackParamsField.setText(String.join("|", yamlConfig.getParamslist()));
            if (configPanel.timeTextField != null)
                configPanel.timeTextField.setText(String.valueOf(yamlConfig.getDelaytime()));
            if (configPanel.staticTimeTextField != null)
                configPanel.staticTimeTextField.setText(String.valueOf(yamlConfig.getStatictime()));
            if (configPanel.startTimeTextField != null)
                configPanel.startTimeTextField.setText(String.valueOf(yamlConfig.getStarttime()));
            if (configPanel.endTimeTextField != null)
                configPanel.endTimeTextField.setText(String.valueOf(yamlConfig.getEndtime()));
            if (configPanel.diyTextArea != null)
                configPanel.diyTextArea.setText(yamlConfig.getDiypayloads());
            if (configPanel.regexTextArea != null)
                configPanel.regexTextArea.setText(yamlConfig.getDiyregex());
            if (configPanel.blackPathTextArea != null)
                configPanel.blackPathTextArea.setText(yamlConfig.getBlackpath());

            // 更新复选框
            if (configPanel.switchCheck != null)
                configPanel.switchCheck.setSelected(yamlConfig.isSwitchEnabled());
            if (configPanel.cookieCheck != null)
                configPanel.cookieCheck.setSelected(yamlConfig.isCookiecheck());
            if (configPanel.errorCheck != null)
                configPanel.errorCheck.setSelected(yamlConfig.isErrorcheck());
            if (configPanel.vulnCheck != null)
                configPanel.vulnCheck.setSelected(yamlConfig.isRepeatercheck());
            if (configPanel.numCheck != null)
                configPanel.numCheck.setSelected(yamlConfig.isNumcheck());
            if (configPanel.stringCheck != null)
                configPanel.stringCheck.setSelected(yamlConfig.isStringcheck());
            if (configPanel.orderCheck != null)
                configPanel.orderCheck.setSelected(yamlConfig.isOrdercheck());
            if (configPanel.boolCheck != null)
                configPanel.boolCheck.setSelected(yamlConfig.isBoolcheck());
            if (configPanel.diyCheck != null)
                configPanel.diyCheck.setSelected(yamlConfig.isDiycheck());
        });

        // 应用错误 Payload
        if (yamlConfig.getErrpoclist().isEmpty()) {
            config.setErrorPayloads(DefaultConfig.DEFAULT_ERR_POCS.clone());
            config.setErrorPayloadsJson(DefaultConfig.DEFAULT_ERR_POCS_JSON.clone());
        } else {
            String[] errPocs = yamlConfig.getErrpoclist().toArray(new String[0]);
            config.setErrorPayloads(errPocs);
            config.setErrorPayloadsJson(deriveJsonErrPocs(errPocs));
        }

        // 应用文本区域配置
        if (!yamlConfig.getDiypayloads().isBlank()) {
            Set<String> diyPayloads = new HashSet<>();
            for (String line : yamlConfig.getDiypayloads().split("\n")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    diyPayloads.add(trimmed);
                }
            }
            config.setDiyPayloads(diyPayloads);
        } else {
            config.setDiyPayloads(new HashSet<>());
        }

        if (!yamlConfig.getDiyregex().isBlank()) {
            Set<String> diyRegexs = new HashSet<>();
            for (String line : yamlConfig.getDiyregex().split("\n")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    diyRegexs.add(trimmed);
                }
            }
            config.setDiyRegexs(diyRegexs);
        } else {
            config.setDiyRegexs(new HashSet<>());
        }

        if (!yamlConfig.getBlackpath().isBlank()) {
            Set<String> blackPaths = new HashSet<>();
            for (String line : yamlConfig.getBlackpath().split("\n")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    blackPaths.add(trimmed);
                }
            }
            MyFilterRequest.blackPathSet = blackPaths;
        } else {
            MyFilterRequest.blackPathSet = new HashSet<>();
        }

        // 应用时间配置
        config.setDelayTimeMs(yamlConfig.getDelaytime());
        config.setStaticTimeMs(yamlConfig.getStatictime());
        config.setStartTimeMs(yamlConfig.getStarttime());
        config.setEndTimeMs(yamlConfig.getEndtime());

        // 输出配置加载诊断日志
        logConfigurationStatus();
    }

    /**
     * 输出当前配置状态的诊断日志
     * 帮助用户确认过滤规则是否正确加载
     */
    private void logConfigurationStatus() {
        StringBuilder status = new StringBuilder();
        status.append("\n========== DetSQL 配置状态 ==========\n");

        // 域名白名单
        status.append(String.format("域名白名单: %d 个", MyFilterRequest.whiteListSet.size()));
        if (!MyFilterRequest.whiteListSet.isEmpty()) {
            status.append("\n");
            MyFilterRequest.whiteListSet.forEach(domain -> status.append("  • ").append(domain).append("\n"));
        } else {
            status.append(" (未配置)\n");
        }

        // 域名黑名单
        status.append(String.format("域名黑名单: %d 个", MyFilterRequest.blackListSet.size()));
        if (!MyFilterRequest.blackListSet.isEmpty()) {
            status.append("\n");
            MyFilterRequest.blackListSet.forEach(domain -> status.append("  • ").append(domain).append("\n"));
        } else {
            status.append(" (未配置)\n");
        }

        // 路径黑名单
        status.append(String.format("路径黑名单: %d 个", MyFilterRequest.blackPathSet.size()));
        if (!MyFilterRequest.blackPathSet.isEmpty()) {
            status.append("\n");
            MyFilterRequest.blackPathSet.forEach(path -> status.append("  • ").append(path).append("\n"));
        } else {
            status.append(" (未配置)\n");
        }

        // 参数黑名单
        status.append(String.format("参数黑名单: %d 个", MyFilterRequest.blackParamsSet.size()));
        if (!MyFilterRequest.blackParamsSet.isEmpty()) {
            status.append("\n");
            MyFilterRequest.blackParamsSet.forEach(param -> status.append("  • ").append(param).append("\n"));
        } else {
            status.append(" (未配置)\n");
        }

        status.append("=====================================");

        api.logging().logToOutput(status.toString());
    }

    // ========== 辅助方法 ==========

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

    /**
     * 实现 LanguageChangeListener 接口
     * 响应全局语言变更事件,更新 Tab 标题和统计标签
     */
    @Override
    public void onLanguageChanged() {
        SwingUtilities.invokeLater(() -> {
            if (tabbedPane1 != null) {
                // 更新 Tab 标题
                tabbedPane1.setTitleAt(0, Messages.getString("tab.dashboard"));
                tabbedPane1.setTitleAt(1, Messages.getString("tab.config"));
                tabbedPane1.setTitleAt(2, Messages.getString("tab.codetool"));
            }

            // 更新清理历史按钮
            if (clearButton != null) {
                clearButton.setText(Messages.getString("button.clear_history"));
            }

            // 更新统计标签 (会在下次 updateStats() 时自动更新)
            // 这里无需手动更新,因为 Timer 每秒都会调用 updateStats()
        });
    }
}

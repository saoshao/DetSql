/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql.core;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.utilities.CryptoUtils;
import burp.api.montoya.utilities.DigestAlgorithm;
import DetSql.config.ConfigManager;
import DetSql.config.DetSqlConfig;
import DetSql.config.DetSqlYamlConfig;
import DetSql.logging.DetSqlLogger;
import DetSql.logging.LogLevel;
import DetSql.ui.DetSqlUI;
import DetSql.ui.Messages;
import DetSql.ui.MyFilterRequest;
import DetSql.util.Statistics;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Future;

/**
 * DetSql Burp 扩展入口类
 * Phase 3: 架构清理 - 只保留扩展生命周期管理
 */
public class DetSql implements BurpExtension, ContextMenuItemsProvider {
    private MontoyaApi api;
    private DetSqlUI ui;

    /**
     * 获取 UI 实例（用于测试）
     * 
     * @return DetSqlUI 实例
     */
    public DetSqlUI getUI() {
        return ui;
    }

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        api.extension().setName("DetSql");

        // Phase 2: 使用 ConfigManager 加载 YAML 配置
        ConfigManager configManager = new ConfigManager();
        DetSqlYamlConfig yamlConfig = configManager.loadConfig();

        // 创建日志和统计系统
        DetSqlLogger logger = new DetSqlLogger(api);
        Statistics statistics = new Statistics();

        // 创建运行时配置对象
        DetSqlConfig config = new DetSqlConfig();

        // 创建 UI
        ui = new DetSqlUI(api, config, logger, statistics, yamlConfig);

        // 注册 UI 组件
        Component component = ui.createMainComponent();
        api.userInterface().registerSuiteTab("DetSql", component);

        // 注册 HTTP 处理器
        api.http().registerHttpHandler(ui.getHttpHandler());

        // 注册卸载处理器（传递 httpHandler 和 logger 以便清理资源）
        api.extension().registerUnloadingHandler(
                new MyExtensionUnloadingHandler(ui, ui.getHttpHandler(), logger));

        // 注册右键菜单
        api.userInterface().registerContextMenuItemsProvider(this);

        // 使用新的日志系统 - 启动信息始终输出
        logger.always("################################################");
        logger.always("[#]  DetSql v3.3.0 loaded successfully");
        logger.always("[#]  Author: saoshao");
        logger.always("[#]  Email: 1224165231@qq.com");
        logger.always("[#]  Github: https://github.com/saoshao/DetSql");
        logger.always("[#]  Config file: " + configManager.getConfigPath());
        logger.always("[#]  Logging system: " + (logger.getLogLevel() == LogLevel.OFF ? "DISABLED"
                : "ENABLED (Level: " + logger.getLogLevel() + ")"));
        logger.always("[#]  Statistics tracking: ENABLED");
        logger.always("################################################");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        // 检查是否有可用的请求
        boolean hasRequest = event.messageEditorRequestResponse().isPresent()
                || !event.selectedRequestResponses().isEmpty();

        if (!hasRequest) {
            return Collections.emptyList(); // 没有请求时不显示菜单
        }

        List<Component> listMenuItems = new ArrayList<>();
        JMenu jMenu2 = new JMenu("DetSql");
        JMenuItem menuItem2 = new JMenuItem(Messages.getString("menu.end_data"));
        JMenuItem menuItem3 = new JMenuItem(Messages.getString("menu.send_to_detsql"));

        listMenuItems.add(jMenu2);
        jMenu2.add(menuItem3);
        jMenu2.add(menuItem2);

        menuItem2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                HttpRequestResponse selectHttpRequestResponse = getRequestResponse(event);
                if (selectHttpRequestResponse == null) {
                    api.logging().logToError("未选择任何请求");
                    return;
                }

                CryptoUtils cryptoUtils = api.utilities().cryptoUtils();
                String requestSm3Hash = MyHttpHandler.byteToHex(cryptoUtils
                        .generateDigest(ByteArray.byteArray(MyFilterRequest.getUnique(selectHttpRequestResponse)),
                                DigestAlgorithm.SM3)
                        .getBytes());

                // 使用 Future.cancel() 替代 Thread.getAllStackTraces() 反模式
                // 直接取消任务,快速且可靠
                Future<?> task = ui.getHttpHandler().getRunningTask(requestSm3Hash);
                if (task != null) {
                    boolean cancelled = task.cancel(true);
                    if (cancelled) {
                        api.logging().logToOutput("已取消任务: " + requestSm3Hash);
                    } else {
                        api.logging().logToOutput("任务已完成或无法取消: " + requestSm3Hash);
                    }
                } else {
                    api.logging().logToOutput("未找到运行中的任务: " + requestSm3Hash);
                }
            }
        });

        menuItem3.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 支持批量处理多选请求
                List<HttpRequestResponse> requests = getAllSelectedRequests(event);
                if (requests.isEmpty()) {
                    api.logging().logToError("未选择任何请求");
                    return;
                }

                // 诊断日志: 输出当前生效的过滤配置,帮助用户验证配置是否正确应用
                api.logging().logToOutput("════════════════════════════════════════");
                api.logging().logToOutput("DetSQL 过滤配置诊断信息:");
                api.logging().logToOutput("  域名白名单: " + (MyFilterRequest.whiteListSet.isEmpty() ? "未配置" : MyFilterRequest.whiteListSet));
                api.logging().logToOutput("  域名黑名单: " + (MyFilterRequest.blackListSet.isEmpty() ? "未配置" : MyFilterRequest.blackListSet));
                api.logging().logToOutput("  路径黑名单: " + (MyFilterRequest.blackPathSet.isEmpty() ? "未配置" : MyFilterRequest.blackPathSet));
                api.logging().logToOutput("  参数黑名单: " + (MyFilterRequest.blackParamsSet.isEmpty() ? "未配置" : MyFilterRequest.blackParamsSet));
                api.logging().logToOutput("  禁止扩展名: " + (MyFilterRequest.unLegalExtensionSet.isEmpty() ? "未配置" : MyFilterRequest.unLegalExtensionSet));
                api.logging().logToOutput("════════════════════════════════════════");

                // 批量发送到插件
                // 过滤规则检查保留在这里，以便提供反馈
                // 去重检查移至 submitManualRequest 以确保原子性和一致性
                int submittedCount = 0;
                int filteredCount = 0;
                int blacklistFiltered = 0;
                int blackpathFiltered = 0;
                int otherFiltered = 0;

                for (HttpRequestResponse request : requests) {
                    try {
                        // 1. 检查过滤规则 (保持与 Proxy 一致)
                        if (!MyFilterRequest.filterOneRequest(request)) {
                            String url = request.request().url();
                            String host = request.request().httpService().host();

                            // 显示详细的过滤原因,帮助用户排查问题
                            if (!MyFilterRequest.blackListSet.isEmpty() && MyFilterRequest.matchesBlackList(request)) {
                                // 找出匹配的具体黑名单规则
                                String matchedPattern = MyFilterRequest.blackListSet.stream()
                                    .filter(pattern -> {
                                        String hostLower = host.toLowerCase();
                                        String patternLower = pattern.toLowerCase();
                                        return hostLower.equals(patternLower) || hostLower.endsWith("." + patternLower);
                                    })
                                    .findFirst()
                                    .orElse("unknown");
                                api.logging().logToOutput("✗ 域名黑名单拦截: " + host + " (匹配规则: " + matchedPattern + ") - " + url);
                                blacklistFiltered++;
                            } else if (!MyFilterRequest.blackPathSet.isEmpty() && MyFilterRequest.matchesBlackPath(request)) {
                                api.logging().logToOutput("✗ 路径黑名单拦截: " + url);
                                blackpathFiltered++;
                            } else {
                                // 提供更详细的其他过滤原因
                                String reason = "";
                                if (!MyFilterRequest.whiteListSet.isEmpty() && !MyFilterRequest.matchesWhiteList(request)) {
                                    reason = "不在白名单中";
                                } else if (!MyFilterRequest.isGetOrPostRequest(request)) {
                                    reason = "HTTP方法不支持 (" + request.request().method() + ")";
                                } else if (!MyFilterRequest.hasAllowedExtension(request)) {
                                    reason = "文件扩展名被禁止 (." + request.request().fileExtension() + ")";
                                } else if (!MyFilterRequest.hasParameters(request)) {
                                    reason = "缺少有效参数";
                                }
                                api.logging().logToOutput("✗ 过滤规则拦截 (" + reason + "): " + url);
                                otherFiltered++;
                            }
                            filteredCount++;
                            continue;
                        }

                        // 2. 提交请求 (去重逻辑在内部处理)
                        ui.getHttpHandler().submitManualRequest(request);
                        submittedCount++;
                    } catch (Exception ex) {
                        api.logging().logToError("处理请求失败: " + ex.getMessage());
                    }
                }

                // 输出详细的处理统计
                StringBuilder logMessage = new StringBuilder();
                logMessage.append(String.format("✓ 已提交 %d/%d 个请求到 DetSql",
                        submittedCount, requests.size()));

                if (filteredCount > 0) {
                    logMessage.append(String.format("\n  过滤统计: 共 %d 个被拦截", filteredCount));
                    if (blacklistFiltered > 0) {
                        logMessage.append(String.format("\n    • 域名黑名单: %d 个", blacklistFiltered));
                    }
                    if (blackpathFiltered > 0) {
                        logMessage.append(String.format("\n    • 路径黑名单: %d 个", blackpathFiltered));
                    }
                    if (otherFiltered > 0) {
                        logMessage.append(String.format("\n    • 其他规则: %d 个", otherFiltered));
                    }
                }

                api.logging().logToOutput(logMessage.toString());
            }
        });

        return listMenuItems;
    }

    /**
     * 从ContextMenuEvent获取HttpRequestResponse
     * 支持从message editor和selected requests两种来源获取
     * 
     * @param event 上下文菜单事件
     * @return HttpRequestResponse 或 null
     */
    private HttpRequestResponse getRequestResponse(ContextMenuEvent event) {
        // 1. 优先从 message editor 获取 (Repeater, Message Editor等)
        if (event.messageEditorRequestResponse().isPresent()) {
            return event.messageEditorRequestResponse().get().requestResponse();
        }

        // 2. 从 selected requests 获取 (Proxy History, Scanner Results等)
        if (!event.selectedRequestResponses().isEmpty()) {
            return event.selectedRequestResponses().get(0);
        }

        // 3. 没有找到任何请求
        return null;
    }

    /**
     * 从ContextMenuEvent获取所有选中的请求
     * 支持批量处理多选场景
     * 
     * @param event 上下文菜单事件
     * @return 所有选中的请求列表
     */
    private List<HttpRequestResponse> getAllSelectedRequests(ContextMenuEvent event) {
        List<HttpRequestResponse> requests = new ArrayList<>();

        // 1. 优先从 message editor 获取 (Repeater, Message Editor等)
        if (event.messageEditorRequestResponse().isPresent()) {
            requests.add(event.messageEditorRequestResponse().get().requestResponse());
            return requests;
        }

        // 2. 从 selected requests 获取所有选中的请求 (Proxy History等)
        if (!event.selectedRequestResponses().isEmpty()) {
            requests.addAll(event.selectedRequestResponses());
        }

        return requests;
    }
}

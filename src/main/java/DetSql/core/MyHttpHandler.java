/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.utilities.CryptoUtils;
import burp.api.montoya.utilities.DigestAlgorithm;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import javax.swing.SwingUtilities;
import burp.api.montoya.utilities.URLUtils;

import DetSql.injection.InjectionStrategyManager;
import DetSql.config.DetSqlConfig;
import DetSql.logging.DetSqlLogger;
import DetSql.model.PocLogEntry;
import DetSql.model.SourceLogEntry;
import DetSql.ui.DetSqlUI;
import DetSql.ui.MyFilterRequest;
import DetSql.util.ParameterModifiers;
import DetSql.util.RegexUtils;
import DetSql.util.Statistics;
import DetSql.model.PocTableModel;
import DetSql.model.SourceTableModel;
import DetSql.util.ParameterModifier;

public class MyHttpHandler implements HttpHandler {
    // Response size thresholds
    private static final int SMALL_RESPONSE_THRESHOLD = 10_000;
    private static final int MEDIUM_RESPONSE_MAX = 80_000;
    // MAX_RESPONSE_SIZE 改为从配置读取
    // private static final int MAX_RESPONSE_SIZE = 50_000;

    /**
     * Similarity thresholds for SQL injection detection
     *
     * SIMILARITY_THRESHOLD (0.9 = 90%):
     * - Used to determine if two HTTP responses are "similar" or "different"
     * - Higher threshold = more strict (responses must be more identical to be
     * considered "similar")
     * - Lower threshold = more lenient (allows more variation)
     *
     * Why 0.9 (90%)?
     * - Balances false positives vs false negatives
     * - Allows for minor variations (timestamps, session IDs, random tokens) that
     * don't affect SQL behavior
     * - Strict enough to detect meaningful changes in SQL query results
     * - Tested empirically to work well across various databases and applications
     *
     * LENGTH_DIFF_THRESHOLD (100 bytes):
     * - If response length difference exceeds 100 bytes, immediately consider
     * responses "different"
     * - Optimization to skip expensive similarity calculations for obviously
     * different responses
     */
    // SIMILARITY_THRESHOLD 改为从配置读取
    // private static final double SIMILARITY_THRESHOLD = 0.9;
    // LENGTH_DIFF_THRESHOLD 改为从配置读取
    // private static final int LENGTH_DIFF_THRESHOLD = 100;

    // Timing defaults
    private static final int DEFAULT_STATIC_DELAY_MS = 100;
    private static final int DEFAULT_MAX_DELAY_MS = 1_000_000;
    private static final int MIN_SLEEP_TIME_MS = 100;

    // Vulnerability type identifiers
    private static final String VULN_TYPE_ERROR = "errsql";
    private static final String VULN_TYPE_STRING = "stringsql";
    private static final String VULN_TYPE_NUMERIC = "numsql";
    private static final String VULN_TYPE_ORDER = "ordersql";
    private static final String VULN_TYPE_BOOLEAN = "boolsql";
    private static final String VULN_TYPE_DIY = "diypoc";

    // HTTP method constants
    private static final String METHOD_POST = "POST";
    private static final String METHOD_PUT = "PUT";

    // Request retry constants
    private static final int DEFAULT_RETRY_COUNT = 2;

    public final MontoyaApi api;
    public final DetSqlConfig config; // 配置对象
    private final DetSqlLogger logger; // 日志系统
    private final Statistics statistics; // 统计系统
    public final SourceTableModel sourceTableModel;// 两张表
    public final PocTableModel pocTableModel;
    public final Map<String, List<PocLogEntry>> attackMap;

    // 任务跟踪 Map：用于取消正在运行的扫描任务
    // 替代 Thread.getAllStackTraces() 反模式
    private static final ConcurrentHashMap<String, Future<?>> runningTasks = new ConcurrentHashMap<>();

    // 队列 1：接收队列（快速处理：过滤、去重、创建记录）
    // 根据 CPU 性能动态调整线程数和队列大小，适配低配置环境（1c512M, 2c2G）
    private static final ThreadPoolExecutor RECEIVE_EXECUTOR = new ThreadPoolExecutor(
            Math.max(2, Runtime.getRuntime().availableProcessors()), // 核心线程数：至少 2 个
            Math.max(4, Runtime.getRuntime().availableProcessors() * 2), // 最大线程数：至少 4 个
            60L, TimeUnit.SECONDS,
            // 队列大小：根据 CPU 核心数动态调整，最小 1000，最大 5000
            new LinkedBlockingQueue<>(
                    Math.min(5000, Math.max(1000, Runtime.getRuntime().availableProcessors() * 1000))),
            new ThreadFactory() {
                private int counter = 0;

                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "DetSql-Receive-" + counter++);
                    t.setDaemon(true);
                    return t;
                }
            },
            new ThreadPoolExecutor.CallerRunsPolicy());

    // 队列 2：扫描队列（慢速处理：执行 SQL 注入测试）
    private static final ThreadPoolExecutor SCAN_EXECUTOR = new ThreadPoolExecutor(
            Runtime.getRuntime().availableProcessors(),
            Runtime.getRuntime().availableProcessors() * 2,
            60L, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(1000), // 使用 LinkedBlockingQueue 支持更大容量
            new ThreadFactory() {
                private int counter = 0;

                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "DetSql-Scan-" + counter++);
                    t.setDaemon(true);
                    return t;
                }
            },
            // P0-2 修复：避免 CallerRunsPolicy 导致 UI 冻结
            // 队列满时记录警告并丢弃任务，而不是在调用者线程（Burp UI）中执行
            new RejectedExecutionHandler() {
                @Override
                public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
                    // 注意：此时 logger 和 statistics 尚未初始化（静态字段）
                    // 使用 System.err 记录警告
                    System.err.println("[DetSql] WARNING: 扫描队列已满，任务被拒绝。考虑增加队列容量或减少并发。");
                }
            });

    public CryptoUtils cryptoUtils;
    public URLUtils urlUtils;

    // 策略管理器
    private final InjectionStrategyManager strategyManager;

    // Dashboard ID counter - thread-safe atomic increment
    private final AtomicInteger countId = new AtomicInteger(1);

    /**
     * Precompiled pattern for newline removal
     * Used in response body cleaning before regex matching
     */
    private static final Pattern NEWLINE_PATTERN;

    // Precompile newline removal pattern at class loading time
    static {
        NEWLINE_PATTERN = Pattern.compile("\\n|\\r|\\r\\n");
    }
    // 已迁移到 DetSqlConfig - 这些静态变量已废弃
    // 所有配置现在通过 this.config 访问
    // blackParamsSet -> config.getBlackListParams()
    // whiteParamsSet -> 未使用,已删除
    // staticTime -> config.getStaticTimeMs()
    // startTime -> config.getStartTimeMs()
    // endTime -> config.getEndTimeMs()

    private DetSqlUI ui; // UI 实例引用

    public MyHttpHandler(MontoyaApi mapi, SourceTableModel sourceTableModel, PocTableModel pocTableModel,
            Map<String, List<PocLogEntry>> attackMap, DetSqlConfig config,
            DetSqlLogger logger, Statistics statistics, DetSqlUI ui) {
        this.api = mapi;
        this.config = config;
        this.logger = logger;
        this.statistics = statistics;
        this.sourceTableModel = sourceTableModel;
        this.pocTableModel = pocTableModel;
        this.attackMap = attackMap;
        this.ui = ui;
        this.cryptoUtils = api.utilities().cryptoUtils();
        this.urlUtils = api.utilities().urlUtils();

        // 初始化策略管理器
        this.strategyManager = new InjectionStrategyManager(api, config, logger, statistics, attackMap, ui);
        logger.info("策略管理器已初始化");

        // 输出双队列配置信息
        int processors = Runtime.getRuntime().availableProcessors();
        int receiveCore = Math.max(2, processors);
        int receiveMax = Math.max(4, processors * 2);
        int receiveQueue = Math.min(5000, Math.max(1000, processors * 1000));

        logger.always("================================================");
        logger.always("[#] 双队列架构配置:");
        logger.always("[#]   CPU 核心数: " + processors);
        logger.always("[#]   RECEIVE_EXECUTOR: 核心=" + receiveCore + ", 最大=" + receiveMax + ", 队列=" + receiveQueue);
        logger.always("[#]   SCAN_EXECUTOR: 核心=" + processors + ", 最大=" + (processors * 2) + ", 队列=1000");
        logger.always("================================================");
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }

    /**
     * Request processing context - encapsulates the differences between request
     * types
     * Eliminates 4 duplicate code blocks by parameterizing the variations
     */
    private static class RequestContext {
        final boolean isSmallResponse;
        final boolean isFromProxy;
        final String hash;

        RequestContext(HttpResponseReceived response, CryptoUtils crypto) {
            int bodyLength = response.bodyToString().length();
            this.isSmallResponse = bodyLength < SMALL_RESPONSE_THRESHOLD;
            this.isFromProxy = MyFilterRequest.fromProxySource(response);

            // Proxy uses SM3 hash, Repeater uses timestamp
            this.hash = isFromProxy
                    ? MyHttpHandler.byteToHex(crypto.generateDigest(
                            ByteArray.byteArray(MyFilterRequest.getUnique(response)),
                            DigestAlgorithm.SM3).getBytes())
                    : String.valueOf(System.currentTimeMillis());
        }
    }

    /**
     * Checks if the request should be processed
     */
    private boolean shouldProcess(HttpResponseReceived response) {
        boolean isProxyMode = ui.isSwitchCheckSelected()
                && MyFilterRequest.fromProxySource(response)
                && MyFilterRequest.filterOneRequest(response);

        boolean isRepeaterMode = ui.isVulnCheckSelected()
                && MyFilterRequest.fromRepeaterSource(response)
                && MyFilterRequest.filterOneRequest(response);

        return isProxyMode || isRepeaterMode;
    }

    /**
     * Creates initial log entry and returns the log index
     * Thread-safe: uses AtomicInteger for ID generation and putIfAbsent for map
     * initialization
     * 
     * @param response              HTTP 响应
     * @param hash                  请求哈希
     * @param mapAlreadyInitialized 是否已经初始化了 attackMap（避免重复初始化）
     */
    private int createLogEntry(HttpResponseReceived response, String hash, boolean mapAlreadyInitialized) {
        // Atomically get and increment ID
        int logIndex = countId.getAndIncrement();

        // Thread-safe map initialization - only one thread will succeed
        // 如果调用者已经初始化了 map（通过 putIfAbsent），则跳过
        // Bug 2 修复：使用线程安全的 List，防止并发添加 POC 数据时丢失
        if (!mapAlreadyInitialized) {
            attackMap.putIfAbsent(hash, Collections.synchronizedList(new ArrayList<>()));
        }

        final int finalLogIndex = logIndex;
        SwingUtilities.invokeLater(() -> {
            sourceTableModel.add(new SourceLogEntry(
                    finalLogIndex,
                    response.toolSource().toolType().toolName(),
                    hash,
                    "run",
                    response.bodyToString().length(),
                    HttpRequestResponse.httpRequestResponse(
                            response.initiatingRequest(),
                            HttpResponse.httpResponse()),
                    response.initiatingRequest().httpService().toString(),
                    response.initiatingRequest().method(),
                    response.initiatingRequest().pathWithoutQuery()));
        });
        return logIndex;
    }

    // Package-private helper for concurrency smoke tests without instantiating
    // heavy dependencies
    static int allocateIdAndInitMapForTest(AtomicInteger countIdRef,
            java.util.concurrent.ConcurrentHashMap<String, java.util.List<PocLogEntry>> map,
            String hash) {
        int id = countIdRef.getAndIncrement();
        map.putIfAbsent(hash, new java.util.ArrayList<>());
        return id;
    }

    /**
     * Updates log entry with vulnerability type or empty/stopped status
     */
    private void updateLogEntry(HttpResponseReceived response, String hash,
            int logIndex, String vulnType) {
        final int finalLogIndex = logIndex;
        final String finalVulnType = (vulnType == null) ? "" : vulnType;

        // 内存优化：根据漏洞状态决定数据保留策略
        final boolean hasVulnerability = !finalVulnType.isBlank();

        if (hasVulnerability) {
            // 有漏洞：升级 PocLogEntry 的 WeakReference 为强引用，锁定证据
            List<PocLogEntry> entries = attackMap.get(hash);
            if (entries != null) {
                for (PocLogEntry entry : entries) {
                    entry.keepResponse(); // 升级为强引用，防止 GC 回收
                }
            }
        } else {
            // 无漏洞：清理攻击记录以释放内存
            List<PocLogEntry> entries = attackMap.get(hash);
            // 只有当列表为空或不存在时才移除
            if (entries == null || entries.isEmpty()) {
                attackMap.remove(hash);
            } else {
                // 有数据但 vulnType 为空,说明可能存在时序问题
                // 记录警告但不清理数据,让用户可以在 table2 中查看
                logger.warn("VulnType is blank but attackMap has " + entries.size() +
                        " entries for hash: " + hash + ". Keeping data for debugging.");
            }
        }

        SwingUtilities.invokeLater(() -> {
            // Bug 1 修复：始终保留原始响应，不使用空响应
            // 用户需要查看完整的请求和响应来判断是否真的无漏洞
            HttpRequestResponse httpRR = HttpRequestResponse.httpRequestResponse(
                    response.initiatingRequest(),
                    HttpResponse.httpResponse(response.toByteArray()));

            SourceLogEntry newEntry = new SourceLogEntry(
                    finalLogIndex,
                    response.toolSource().toolType().toolName(),
                    hash,
                    finalVulnType,
                    response.bodyToString().length(),
                    httpRR,
                    response.initiatingRequest().httpService().toString(),
                    response.initiatingRequest().method(),
                    response.initiatingRequest().pathWithoutQuery());

            // Bug 1 修复：移除 discardResponse() 调用，保留完整响应供用户查看
            // 现代系统内存充足，保留响应的成本可接受，便于用户调试和分析

            int rowIndex = sourceTableModel.indexOf(
                    new SourceLogEntry(finalLogIndex, null, null, null, 0, null, null, null, null));
            sourceTableModel.updateVulnState(newEntry, rowIndex);
        });
    }

    /**
     * 执行 SQL 注入测试（在扫描队列中运行）
     * 
     * @param response HTTP 响应
     * @param ctx      请求上下文
     * @param logIndex 日志索引
     */
    private void performSqlInjectionTest(HttpResponseReceived response, RequestContext ctx, int logIndex) {
        Thread.currentThread().setName(ctx.hash);
        logger.info("Starting SQL injection test: " + ctx.hash + " (ID: " + logIndex + ")");
        statistics.incrementRequestsProcessed();

        try {
            String vulnType = "";
            if (!Thread.currentThread().isInterrupted()) {
                long startTime = System.currentTimeMillis();
                vulnType = processAutoResponse(response, ctx.hash);
                long duration = System.currentTimeMillis() - startTime;
                statistics.recordTestTime(duration);

                if (vulnType != null && !vulnType.isEmpty() && !vulnType.equals("手动停止")) {
                    logger.info("✓ Vulnerability found: " + vulnType + " in " + ctx.hash);
                    try {
                        java.util.List<PocLogEntry> entries = attackMap.get(ctx.hash);
                        if (entries != null) {
                            statistics.recordFromEntries(
                                    response.initiatingRequest().url(),
                                    response.initiatingRequest().method(),
                                    entries);
                        }
                    } catch (Exception ignore) {
                        // do not break flow on statistics aggregation error
                    }
                } else {
                    logger.debug("No vulnerability found in " + ctx.hash + " (took " + duration + "ms)");
                }
            }
            // Ensure vulnType is never null before passing to updateLogEntry
            if (vulnType == null) {
                vulnType = "";
            }
            updateLogEntry(response, ctx.hash, logIndex, vulnType);
        } catch (InterruptedException e) {
            updateLogEntry(response, ctx.hash, logIndex, "手动停止");
            logger.warn("SQL injection test interrupted: " + ctx.hash);
        } catch (Exception e) {
            logger.error("SQL injection test failed: " + ctx.hash, e);
            statistics.incrementDetectionErrors();
            updateLogEntry(response, ctx.hash, logIndex, "");
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        // 提交到接收队列（队列 1）：快速处理
        RECEIVE_EXECUTOR.execute(() -> {
            try {
                String url = httpResponseReceived.initiatingRequest().url();
                logger.debug("→ Received request: " + url);

                // Early return: not enabled or filtered out
                if (!ui.isSwitchCheckSelected() && !ui.isVulnCheckSelected()) {
                    logger.debug("✗ Filtered (switch disabled): " + url);
                    return;
                }

                // 修复: 先检查过滤规则(包括域名黑名单),再检查响应大小
                // 确保安全边界(黑名单)在所有路径下都优先生效,与主动发送保持一致
                // Early return: doesn't pass filter check
                if (!shouldProcess(httpResponseReceived)) {
                    statistics.incrementRequestsFiltered();
                    logger.debug("✗ Filtered (shouldProcess): " + url);
                    return;
                }

                int bodyLength = httpResponseReceived.bodyToString().length();

                // Early return: empty or oversized response (在过滤规则之后,避免绕过安全边界)
                if (bodyLength == 0 || bodyLength >= config.getMaxResponseSize()) {
                    statistics.incrementRequestsFiltered();
                    logger.debug("✗ Filtered (body size): " + url + " (" + bodyLength + " bytes)");
                    return;
                }

                // Create context for processing
                RequestContext ctx = new RequestContext(
                        httpResponseReceived,
                        cryptoUtils);

                // 使用原子操作消除 Check-Then-Act 竞态条件
                // 对于 Proxy 来源的请求，使用 putIfAbsent 原子性地检查并初始化
                // Bug 2 修复：使用线程安全的 List，防止并发添加 POC 数据时丢失
                if (ctx.isFromProxy) {
                    List<PocLogEntry> existing = attackMap.putIfAbsent(ctx.hash, Collections.synchronizedList(new ArrayList<>()));
                    if (existing != null) {
                        // 已存在，说明另一个线程已经在处理这个请求
                        logger.debug("✗ Skipped (duplicate): " + url + " [" + ctx.hash + "]");
                        return;
                    }
                }

                // 快速创建 table1 记录（立即显示给用户）
                long startTime = System.currentTimeMillis();
                int logIndex = createLogEntry(httpResponseReceived, ctx.hash, ctx.isFromProxy);
                long createTime = System.currentTimeMillis() - startTime;
                logger.info("✓ Request accepted: " + url + " (ID: " + logIndex + ", create: " + createTime + "ms)");

                // 提交到扫描队列（队列 2）：执行 SQL 注入测试
                Future<?> future = SCAN_EXECUTOR.submit(() -> {
                    try {
                        performSqlInjectionTest(httpResponseReceived, ctx, logIndex);
                    } catch (Exception e) {
                        logger.error("SQL injection test failed: " + ctx.hash, e);
                        statistics.incrementDetectionErrors();
                        updateLogEntry(httpResponseReceived, ctx.hash, logIndex, "");
                    } finally {
                        // 任务完成后移除跟踪
                        runningTasks.remove(ctx.hash);
                    }
                });
                // 保存 Future 引用用于任务取消
                runningTasks.put(ctx.hash, future);

            } catch (Exception e) {
                logger.error("HTTP response handling failed", e);
                statistics.incrementDetectionErrors();
            }
        });

        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }

    public String processAutoResponse(HttpResponseReceived httpResponseReceived, String requestSm3Hash)
            throws InterruptedException {
        // 修复文件泄漏：直接使用内存中的请求对象，不创建临时文件
        // copyToTempFile() 会创建临时文件但从不删除，导致磁盘空间被耗尽
        HttpRequest sourceHttpRequest = httpResponseReceived.initiatingRequest();
        String sourceBody = httpResponseReceived.body().toString();
        boolean html_flag = httpResponseReceived.mimeType().description().equals("HTML");
        return processRequestInternal(sourceHttpRequest, sourceBody, html_flag, requestSm3Hash);
    }

    /**
     * 统一的参数处理方法（使用策略模式）
     * 
     * @param sourceRequest 原始请求
     * @param sourceBody    原始响应体
     * @param htmlFlag      是否为 HTML 响应
     * @param params        要测试的参数列表
     * @param modifier      参数修改器
     * @param requestHash   请求哈希
     * @return 检测到的漏洞类型列表
     * @throws InterruptedException 线程中断异常
     */
    private List<String> processParametersWithStrategy(
            HttpRequest sourceRequest,
            String sourceBody,
            boolean htmlFlag,
            List<ParsedHttpParameter> params,
            ParameterModifier modifier,
            String requestHash) throws InterruptedException {

        if (params == null || params.isEmpty()) {
            return new ArrayList<>();
        }

        // 使用策略管理器测试所有参数
        List<String> detectedVulns = new ArrayList<>();
        for (ParsedHttpParameter param : params) {
            List<String> vulns = strategyManager.testParameter(
                    sourceRequest, sourceBody, htmlFlag,
                    param, modifier, requestHash);
            detectedVulns.addAll(vulns);
        }

        return detectedVulns;
    }

    /**
     * 从漏洞类型集合构建结果字符串
     */
    private String buildResultFromVulnTypes(Set<String> vulnTypes) {
        if (vulnTypes.isEmpty()) {
            return "";
        }

        StringBuilder result = new StringBuilder();
        for (String vulnType : vulnTypes) {
            result.append("-").append(vulnType);
        }
        return result.toString();
    }

    private String processRequestInternal(HttpRequest sourceHttpRequest, String sourceBody, boolean html_flag,
            String requestSm3Hash) throws InterruptedException {
        Set<String> detectedVulns = new HashSet<>();

        // 处理 URL 参数
        List<ParsedHttpParameter> urlParams = sourceHttpRequest.parameters(HttpParameterType.URL);
        if (!urlParams.isEmpty()) {
            List<String> vulns = processParametersWithStrategy(
                    sourceHttpRequest, sourceBody, html_flag,
                    urlParams, ParameterModifiers.URL, requestSm3Hash);
            detectedVulns.addAll(vulns);
        }

        // 处理 POST/PUT 请求的参数
        if (isPostOrPutRequest(sourceHttpRequest)) {
            // BODY 参数
            List<ParsedHttpParameter> bodyParams = sourceHttpRequest.parameters(HttpParameterType.BODY);
            if (!bodyParams.isEmpty()) {
                List<String> vulns = processParametersWithStrategy(
                        sourceHttpRequest, sourceBody, html_flag,
                        bodyParams, ParameterModifiers.BODY, requestSm3Hash);
                detectedVulns.addAll(vulns);
            }

            // JSON 参数
            List<ParsedHttpParameter> jsonParams = sourceHttpRequest.parameters(HttpParameterType.JSON);
            if (!jsonParams.isEmpty()) {
                List<String> vulns = processParametersWithStrategy(
                        sourceHttpRequest, sourceBody, html_flag,
                        jsonParams, ParameterModifiers.JSON, requestSm3Hash);
                detectedVulns.addAll(vulns);
            }

            // XML 参数
            List<ParsedHttpParameter> xmlParams = sourceHttpRequest.parameters(HttpParameterType.XML);
            if (!xmlParams.isEmpty()) {
                List<String> vulns = processParametersWithStrategy(
                        sourceHttpRequest, sourceBody, html_flag,
                        xmlParams, ParameterModifiers.XML, requestSm3Hash);
                detectedVulns.addAll(vulns);
            }
        }

        // 处理 COOKIE 参数
        if (ui.isCookieCheckSelected()) {
            List<ParsedHttpParameter> cookieParams = sourceHttpRequest.parameters(HttpParameterType.COOKIE);
            if (!cookieParams.isEmpty()) {
                List<String> vulns = processParametersWithStrategy(
                        sourceHttpRequest, sourceBody, html_flag,
                        cookieParams, ParameterModifiers.COOKIE, requestSm3Hash);
                detectedVulns.addAll(vulns);
            }
        }

        // 构建结果字符串
        return buildResultFromVulnTypes(detectedVulns);
    }

    /**
     * Builds result string from injection detection flags
     * 
     * @param errFlag    true if error-based injection detected
     * @param stringFlag true if string-based injection detected
     * @param numFlag    true if numeric injection detected
     * @param orderFlag  true if order-by injection detected
     * @param boolFlag   true if boolean-based injection detected
     * @param diyFlag    true if custom DIY injection detected
     * @return concatenated string of detected injection types
     */
    // Package-private for unit testing; retains original behavior
    static String buildResultStringExposed(boolean errFlag, boolean stringFlag, boolean numFlag,
            boolean orderFlag, boolean boolFlag, boolean diyFlag) {
        StringBuilder sb = new StringBuilder();
        if (errFlag)
            sb.append("-").append(VULN_TYPE_ERROR);
        if (stringFlag)
            sb.append("-").append(VULN_TYPE_STRING);
        if (numFlag)
            sb.append("-").append(VULN_TYPE_NUMERIC);
        if (orderFlag)
            sb.append("-").append(VULN_TYPE_ORDER);
        if (boolFlag)
            sb.append("-").append(VULN_TYPE_BOOLEAN);
        if (diyFlag)
            sb.append("-").append(VULN_TYPE_DIY);
        return sb.toString();
    }

    private String buildResultString(boolean errFlag, boolean stringFlag, boolean numFlag,
            boolean orderFlag, boolean boolFlag, boolean diyFlag) {
        return buildResultStringExposed(errFlag, stringFlag, numFlag, orderFlag, boolFlag, diyFlag);
    }

    /**
     * 辅助方法：检查是否为POST或PUT请求
     */
    private boolean isPostOrPutRequest(HttpRequest request) {
        String method = request.method();
        return METHOD_POST.equals(method) || METHOD_PUT.equals(method);
    }

    // Package-private for unit testing; retains original behavior
    public String processManualResponse(String requestSm3Hash, HttpRequestResponse httpRequestResponse)
            throws InterruptedException {
        // 修复文件泄漏：直接使用内存中的请求对象，不创建临时文件
        HttpRequest sourceHttpRequest = httpRequestResponse.request();
        String sourceBody = extractResponseBody(httpRequestResponse);
        boolean html_flag = httpRequestResponse.response().mimeType().description().equals("HTML");
        return processRequestInternal(sourceHttpRequest, sourceBody, html_flag, requestSm3Hash);
    }

    /**
     * Checks if DIY injection testing should run based on configuration
     * 
     * @return true if DIY checkbox is selected AND payloads exist AND (time
     *         threshold OR regex patterns exist)
     */
    private boolean shouldRunDiyInjection() {
        return ui.isDiyCheckSelected()
                && !config.getDiyPayloads().isEmpty()
                && (config.getDelayTimeMs() > 0 || !config.getDiyRegexs().isEmpty());
    }

    /**
     * Checks if text matches any regex pattern from a collection
     * Now with ReDoS protection using timeout
     * 
     * @param text     the text to check
     * @param patterns collection of regex patterns to match against
     * @return the first matching pattern, or null if no match
     */
    private static String checkRegexMatch(String text, Iterable<String> patterns) {
        String cleanedText = text.replaceAll("\\n|\\r|\\r\\n", "");
        for (String pattern : patterns) {
            // Use safe matching with timeout to prevent ReDoS
            if (RegexUtils.safeMatch(pattern, cleanedText)) {
                return pattern;
            }
        }
        return null;
    }

    /**
     * Optimized regex matching using precompiled patterns
     * Now with ReDoS protection using timeout
     *
     * @param text     the text to check
     * @param patterns precompiled Pattern objects
     * @return the first matching pattern string, or null if no match
     */
    private static String checkRegexMatch(String text, List<Pattern> patterns) {
        String cleanedText = NEWLINE_PATTERN.matcher(text).replaceAll("");
        for (Pattern pattern : patterns) {
            // Use safe matching with timeout for precompiled patterns
            if (RegexUtils.safeMatchPrecompiled(pattern, cleanedText)) {
                return pattern.pattern(); // Return original regex string
            }
        }
        return null;
    }

    public String diyRegexCheck(String text) {
        return checkRegexMatch(text, config.getDiyRegexs());
    }

    public static String byteToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Checks if a parameter should be skipped based on blacklist
     * 
     * @param paramName the parameter name to check
     * @return true if the parameter should be skipped, false otherwise
     */
    private boolean shouldSkipParameter(String paramName) {
        return !config.getBlackListParams().isEmpty() && config.getBlackListParams().contains(paramName);
    }

    /**
     * Extracts response body as string
     * 
     * @param response the HTTP response
     * @return response body as string
     */
    private static String extractResponseBody(HttpRequestResponse response) {
        return response.response().body().toString();
    }

    public HttpRequestResponse sendHttpRequest(HttpRequest pocHttpRequest, int retryCount) throws InterruptedException {
        Exception lastException = null;

        for (int attempt = 0; attempt < retryCount; attempt++) {
            try {
                // 修复文件泄漏：直接使用内存中的响应对象，不创建临时文件
                // 对于正常大小的响应（< 80KB），内存足够，不需要临时文件
                HttpRequestResponse resHttpRequestResponse = api.http().sendRequest(pocHttpRequest);
                Thread.sleep(Math.max(config.getStaticTimeMs(), MIN_SLEEP_TIME_MS));

                if (resHttpRequestResponse.response().body() != null) {
                    return resHttpRequestResponse;
                }

                // 响应体为 null，继续重试
                if (attempt < retryCount - 1) {
                    logger.debug(
                            "Response body is null, retrying... (attempt " + (attempt + 1) + "/" + retryCount + ")");
                    Thread.sleep(
                            ThreadLocalRandom.current().nextInt(config.getStartTimeMs(), config.getEndTimeMs() + 1));
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedException();
            } catch (Exception e) {
                lastException = e;

                // 如果不是最后一次尝试，记录错误并继续
                if (attempt < retryCount - 1) {
                    logger.debug("Request failed, retrying... (attempt " + (attempt + 1) + "/" + retryCount + "): "
                            + e.getMessage());
                    try {
                        Thread.sleep(ThreadLocalRandom.current().nextInt(config.getStartTimeMs(),
                                config.getEndTimeMs() + 1));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new InterruptedException();
                    }
                }
            }
        }

        // 所有重试都已完成，返回默认的空响应
        HttpResponse aHttpResponse = HttpResponse.httpResponse();
        HttpResponse emptyHttpResponse = aHttpResponse.withBody("");
        HttpRequestResponse defaultResponse = HttpRequestResponse.httpRequestResponse(pocHttpRequest,
                emptyHttpResponse);

        if (lastException != null) {
            logger.debug("All retry attempts failed for request after " + retryCount + " attempts: "
                    + lastException.getMessage());
        } else {
            logger.debug("All retry attempts completed with null response body");
        }

        return defaultResponse;
    }

    /**
     * Process manual request from Repeater/Send-to
     * Thread-safe: uses AtomicInteger and no semaphore needed (ThreadPool controls
     * concurrency)
     *
     * @param httpRequestResponse the HTTP request/response to process
     * @throws InterruptedException if thread is interrupted
     */
    /**
     * 执行手动请求的 SQL 注入测试（Repeater 模式）
     * 
     * @param httpRequestResponse HTTP 请求响应
     * @param requestSm3Hash      请求哈希
     * @param logIndex            日志索引
     */
    private void performManualSqlInjectionTest(HttpRequestResponse httpRequestResponse, String requestSm3Hash,
            int logIndex) {
        Thread.currentThread().setName(requestSm3Hash);
        logger.info("Starting manual SQL injection test: " + requestSm3Hash + " (ID: " + logIndex + ")");
        statistics.incrementRequestsProcessed();

        try {
            String vulnType = "";
            if (!Thread.currentThread().isInterrupted()) {
                long startTime = System.currentTimeMillis();
                vulnType = processManualResponse(requestSm3Hash, httpRequestResponse);
                long duration = System.currentTimeMillis() - startTime;
                statistics.recordTestTime(duration);

                if (vulnType != null && !vulnType.isEmpty()) {
                    logger.info("✓ Vulnerability found in manual request: " + vulnType + " in " + requestSm3Hash);
                } else {
                    logger.debug("No vulnerability found in manual request: " + requestSm3Hash + " (took " + duration
                            + "ms)");
                }
            }

            // Update log entry based on detection result
            // Ensure vulnType is never null
            if (vulnType == null) {
                vulnType = "";
            }
            final String finalVulnType = vulnType;
            final int finalLogIndex = logIndex;
            if (vulnType.isBlank()) {
                // memory clean: no vuln found for this request
                try {
                    attackMap.remove(requestSm3Hash);
                } catch (Exception ignore) {
                }
                SwingUtilities.invokeLater(() -> {
                    sourceTableModel.updateVulnState(
                            new SourceLogEntry(
                                    finalLogIndex,
                                    "Send",
                                    requestSm3Hash,
                                    "",
                                    httpRequestResponse.response().bodyToString().length(),
                                    null,
                                    httpRequestResponse.request().httpService().toString(),
                                    httpRequestResponse.request().method(),
                                    httpRequestResponse.request().pathWithoutQuery()),
                            sourceTableModel.indexOf(
                                    new SourceLogEntry(finalLogIndex, null, null, null, 0, null, null, null, null)));
                });
            } else {
                SwingUtilities.invokeLater(() -> {
                    sourceTableModel.updateVulnState(
                            new SourceLogEntry(
                                    finalLogIndex,
                                    "Send",
                                    requestSm3Hash,
                                    finalVulnType,
                                    httpRequestResponse.response().bodyToString().length(),
                                    httpRequestResponse,
                                    httpRequestResponse.request().httpService().toString(),
                                    httpRequestResponse.request().method(),
                                    httpRequestResponse.request().pathWithoutQuery()),
                            sourceTableModel.indexOf(
                                    new SourceLogEntry(finalLogIndex, null, null, null, 0, null, null, null, null)));
                });
            }
        } catch (InterruptedException e) {
            final int finalLogIndex = logIndex;
            SwingUtilities.invokeLater(() -> {
                sourceTableModel.updateVulnState(
                        new SourceLogEntry(
                                finalLogIndex,
                                "Send",
                                requestSm3Hash,
                                "手动停止",
                                httpRequestResponse.response().bodyToString().length(),
                                null,
                                httpRequestResponse.request().httpService().toString(),
                                httpRequestResponse.request().method(),
                                httpRequestResponse.request().pathWithoutQuery()),
                        sourceTableModel.indexOf(
                                new SourceLogEntry(finalLogIndex, null, null, null, 0, null, null, null, null)));
            });
            logger.warn("Manual SQL injection test interrupted: " + requestSm3Hash);
        } catch (Exception e) {
            logger.error("Manual SQL injection test failed: " + requestSm3Hash, e);
            statistics.incrementDetectionErrors();
        }
    }

    /**
     * Submits a manual request (from Context Menu) for processing
     * Unifies logic with Proxy listener: uses SM3 hash for deduplication
     */
    public void submitManualRequest(HttpRequestResponse httpRequestResponse) {
        // Use RECEIVE_EXECUTOR for initial processing to match Proxy flow
        RECEIVE_EXECUTOR.execute(() -> {
            try {
                // 修复: 先检查过滤规则,再检查响应大小
                // 确保域名黑名单等安全边界在所有情况下都生效,不被响应大小检查绕过
                // 应用过滤规则(与 Proxy 模式保持一致)
                if (!MyFilterRequest.filterOneRequest(httpRequestResponse)) {
                    statistics.incrementRequestsFiltered();
                    String url = httpRequestResponse.request().url();
                    String host = httpRequestResponse.request().httpService().host();

                    // 提升日志级别为 INFO,确保用户可见
                    // 诊断:显示过滤原因帮助用户排查问题
                    if (!MyFilterRequest.blackListSet.isEmpty() && MyFilterRequest.matchesBlackList(httpRequestResponse)) {
                        logger.info("Manual request filtered (blacklist): " + host + " - " + url);
                    } else if (!MyFilterRequest.blackPathSet.isEmpty() && MyFilterRequest.matchesBlackPath(httpRequestResponse)) {
                        logger.info("Manual request filtered (blackpath): " + url);
                    } else {
                        logger.info("Manual request filtered: " + url);
                    }
                    return;
                }

                // 检查响应大小 - 在过滤规则之后,避免绕过安全边界
                int bodyLength = httpRequestResponse.response().bodyToString().length();
                if (bodyLength == 0 || bodyLength >= config.getMaxResponseSize()) {
                    logger.debug("Manual request filtered (size): " + httpRequestResponse.request().url());
                    return;
                }

                // 1. Calculate SM3 Hash (Same as Proxy)
                String requestSm3Hash = MyHttpHandler.byteToHex(cryptoUtils
                        .generateDigest(ByteArray.byteArray(MyFilterRequest.getUnique(httpRequestResponse)),
                                DigestAlgorithm.SM3)
                        .getBytes());

                // 2. Deduplication Check (Atomic)
                // Bug 2 修复：使用线程安全的 List，防止并发添加 POC 数据时丢失
                List<PocLogEntry> existing = attackMap.putIfAbsent(requestSm3Hash, Collections.synchronizedList(new ArrayList<>()));
                if (existing != null) {
                    logger.info("Manual request skipped (duplicate): " + httpRequestResponse.request().url());
                    return;
                }

                // 3. Create Log Entry
                int logIndex = countId.getAndIncrement();
                final int finalLogIndex = logIndex;

                SwingUtilities.invokeLater(() -> {
                    sourceTableModel.add(new SourceLogEntry(
                            finalLogIndex,
                            "Send",
                            requestSm3Hash,
                            "run",
                            httpRequestResponse.response().bodyToString().length(),
                            HttpRequestResponse.httpRequestResponse(
                                    httpRequestResponse.request(),
                                    HttpResponse.httpResponse()),
                            httpRequestResponse.request().httpService().toString(),
                            httpRequestResponse.request().method(),
                            httpRequestResponse.request().pathWithoutQuery()));
                });

                logger.info(
                        "Manual request accepted: " + httpRequestResponse.request().url() + " (ID: " + logIndex + ")");

                // 4. Submit to Scan Queue
                Future<?> future = SCAN_EXECUTOR.submit(() -> {
                    try {
                        performManualSqlInjectionTest(httpRequestResponse, requestSm3Hash, logIndex);
                    } catch (Exception e) {
                        logger.error("Manual SQL injection test failed: " + requestSm3Hash, e);
                        statistics.incrementDetectionErrors();
                        // Ensure state is updated on error
                        // Manually update UI since updateLogEntry expects HttpResponseReceived
                        final int errorLogIndex = logIndex;
                        SwingUtilities.invokeLater(() -> {
                            sourceTableModel.updateVulnState(
                                    new SourceLogEntry(
                                            errorLogIndex,
                                            "Send",
                                            requestSm3Hash,
                                            "Error", // Indicate error state
                                            httpRequestResponse.response().bodyToString().length(),
                                            httpRequestResponse,
                                            httpRequestResponse.request().httpService().toString(),
                                            httpRequestResponse.request().method(),
                                            httpRequestResponse.request().pathWithoutQuery()),
                                    sourceTableModel.indexOf(
                                            new SourceLogEntry(finalLogIndex, null, null, null, 0, null, null, null,
                                                    null)));
                        });
                    } finally {
                        runningTasks.remove(requestSm3Hash);
                    }
                });
                runningTasks.put(requestSm3Hash, future);

            } catch (Exception e) {
                logger.error("Manual request submission failed", e);
                statistics.incrementDetectionErrors();
            }
        });
    }

    /**
     * 获取正在运行的任务
     * 用于任务取消（替代 Thread.getAllStackTraces() 反模式）
     * 
     * @param requestHash 请求哈希
     * @return Future 对象，如果任务不存在则返回 null
     */
    public Future<?> getRunningTask(String requestHash) {
        return runningTasks.get(requestHash);
    }

    /**
     * 关闭所有资源，包括线程池
     * 应在扩展卸载时调用，防止僵尸线程和内存泄漏
     */
    public void shutdown() {
        logger.info("开始关闭 DetSql 资源...");

        // 关闭策略管理器
        if (strategyManager != null) {
            strategyManager.shutdown();
        }

        // 关闭接收线程池
        shutdownExecutor(RECEIVE_EXECUTOR, "RECEIVE_EXECUTOR");

        // 关闭扫描线程池
        shutdownExecutor(SCAN_EXECUTOR, "SCAN_EXECUTOR");

        logger.info("DetSql 资源关闭完成");
    }

    /**
     * 优雅地关闭线程池
     * 
     * @param executor 要关闭的线程池
     * @param name     线程池名称（用于日志）
     */
    private void shutdownExecutor(ExecutorService executor, String name) {
        executor.shutdown(); // 禁止新任务提交
        try {
            // 等待现有任务完成（最多 5 秒）
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                logger.warn(name + " 未在 5 秒内完成，强制关闭");
                executor.shutdownNow(); // 强制关闭

                // 等待任务响应中断（最多 5 秒）
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    logger.error(name + " 无法关闭");
                }
            }
        } catch (InterruptedException e) {
            logger.error(name + " 关闭被中断", e);
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.utilities.CryptoUtils;
import burp.api.montoya.utilities.DigestAlgorithm;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.swing.SwingUtilities;
import DetSql.ResponseExtractor;

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
     * - Higher threshold = more strict (responses must be more identical to be considered "similar")
     * - Lower threshold = more lenient (allows more variation)
     *
     * Why 0.9 (90%)?
     * - Balances false positives vs false negatives
     * - Allows for minor variations (timestamps, session IDs, random tokens) that don't affect SQL behavior
     * - Strict enough to detect meaningful changes in SQL query results
     * - Tested empirically to work well across various databases and applications
     *
     * LENGTH_DIFF_THRESHOLD (100 bytes):
     * - If response length difference exceeds 100 bytes, immediately consider responses "different"
     * - Optimization to skip expensive similarity calculations for obviously different responses
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
    public Semaphore semaphore;
    public Semaphore semaphore2;
    public final SourceTableModel sourceTableModel;//两张表
    public final PocTableModel pocTableModel;
    public final ConcurrentHashMap<String, List<PocLogEntry>> attackMap;
    public CryptoUtils cryptoUtils;
    public Lock lk;
    public static volatile String[] errPocs = DefaultConfig.DEFAULT_ERR_POCS.clone();
    public static volatile String[] errPocsj = DefaultConfig.DEFAULT_ERR_POCS_JSON.clone();
    public static Set<String> diyPayloads = ConcurrentHashMap.newKeySet();
    public static Set<String> diyRegexs = ConcurrentHashMap.newKeySet();
    public static volatile int intTime = DefaultConfig.DEFAULT_DELAY_TIME_MS;
    private static final String[] rules = {
            "the\\s+used\\s+select\\s+statements\\s+have\\s+different\\s+number\\s+of\\s+columns",
            "An\\s+illegal\\s+character\\s+has\\s+been\\s+found\\s+in\\s+the\\s+statement",
            "MySQL\\s+server\\s+version\\s+for\\s+the\\s+right\\s+syntax\\s+to\\s+use",
            "supplied\\s+argument\\s+is\\s+not\\s+a\\s+valid\\s+PostgreSQL\\s+result",
            "Unclosed\\s+quotation\\s+mark\\s+before\\s+the\\s+character\\s+string",
            "Unclosed\\s+quotation\\s+mark\\s+after\\s+the\\s+character\\s+string",
            "Column\\s+count\\s+doesn't\\s+match\\s+value\\s+count\\s+at\\s+row",
            "Syntax\\s+error\\s+in\\s+string\\s+in\\s+query\\s+expression",
            "Microsoft\\s+OLE\\s+DB\\s+Provider\\s+for\\s+ODBC\\s+Drivers",
            "Microsoft\\s+OLE\\s+DB\\s+Provider\\s+for\\s+SQL\\s+Server",
            "\\[Microsoft\\]\\[ODBC\\s+Microsoft\\s+Access\\s+Driver\\]",
            "You\\s+have\\s+an\\s+error\\s+in\\s+your\\s+SQL\\s+syntax",
            "supplied\\s+argument\\s+is\\s+not\\s+a\\s+valid\\s+MySQL",
            "Data\\s+type\\s+mismatch\\s+in\\s+criteria\\s+expression",
            "internal\\s+error\\s+\\[IBM\\]\\[CLI\\s+Driver\\]\\[DB2",
            "Unexpected\\s+end\\s+of\\s+command\\s+in\\s+statement",
            "\\[Microsoft\\]\\[ODBC\\s+SQL\\s+Server\\s+Driver\\]",
            "\\[Macromedia\\]\\[SQLServer\\s+JDBC\\s+Driver\\]",
            "has\\s+occurred\\s+in\\s+the\\s+vicinity\\s+of:",
            "A\\s+Parser\\s+Error\\s+\\(syntax\\s+error\\)",
            "Procedure\\s+'[^']+'\\s+requires\\s+parameter",
            "Microsoft\\s+SQL\\s+Native\\s+Client\\s+error",
            "Syntax\\s+error\\s+in\\s+query\\s+expression",
            "System\\.Data\\.SqlClient\\.SqlException",
            "Dynamic\\s+Page\\s+Generation\\s+Error:",
            "System\\.Exception: SQL Execution Error",
            "Microsoft\\s+JET\\s+Database\\s+Engine",
            "System\\.Data\\.OleDb\\.OleDbException",
            "Sintaxis\\s+incorrecta\\s+cerca\\s+de",
            "Table\\s+'[^']+'\\s+doesn't\\s+exist",
            "java\\.sql\\.SQLSyntaxErrorException",
            "Column\\s+count\\s+doesn't\\s+match",
            "your\\s+MySQL\\s+server\\s+version",
            "\\[SQLServer\\s+JDBC\\s+Driver\\]",
            "ADODB\\.Field\\s+\\(0x800A0BCD\\)",
            "com.microsoft\\.sqlserver\\.jdbc",
            "ODBC\\s+SQL\\s+Server\\s+Driver",
            "(PLS|ORA)-[0-9][0-9][0-9][0-9]",
            "PostgreSQL\\s+query\\s+failed:",
            "on\\s+MySQL\\s+result\\s+index",
            "valid\\s+PostgreSQL\\s+result",
            "macromedia\\.jdbc\\.sqlserver",
            "Access\\s+Database\\s+Engine",
            "SQLServer\\s+JDBC\\s+Driver",
            "Incorrect\\s+syntax\\s+near",
            "java\\.sql\\.SQLException",
            "MySQLSyntaxErrorException",
            "<b>Warning</b>:\\s+ibase_",
            "valid\\s+MySQL\\s+result",
            "org\\.postgresql\\.jdbc",
            "com\\.jnetdirect\\.jsql",
            "Dynamic\\s+SQL\\s+Error",
            "\\[DM_QUERY_E_SYNTAX\\]",
            "mysql_fetch_array\\(\\)",
            "pg_query\\(\\)\\s+\\[:",
            "pg_exec\\(\\)\\s+\\[:",
            "com\\.informix\\.jdbc",
            "DB2\\s+SQL\\s+error",
            "Microsoft\\s+Access",
            "\\[CLI\\s+Driver\\]",
            "\\[SQL\\s+Server\\]",
            "com\\.mysql\\.jdbc",
            "Sybase\\s+message:",
            "\\[MySQL\\]\\[ODBC",
            "ADODB\\.Recordset",
            "Unknown\\s+column",
            "mssql_query\\(\\)",
            "Sybase\\s+message",
            "Database\\s+error",
            "PG::SyntaxError:",
            "where\\s+clause",
            "Syntax\\s+error",
            "Oracle\\s+error",
            "SQLite\\s+error",
            "SybSQLException",
            "\\[SqlException",
            "odbc_exec\\(\\)",
            "MySqlException",
            "INSERT\\s+INTO",
            "SQL\\s+syntax",
            "Error\\s+SQL:",
            "SQL\\s+error",
            "PSQLException",
            "SQLSTATE=\\d+",
            "SELECT .{1,30}FROM ",
            "UPDATE .{1,30}SET ",
            "附近有语法错误",
            "MySqlClient",
            "ORA-\\d{5}",
            "引号不完整",
            "数据库出错"
    };

    /**
     * Precompiled error detection patterns for performance optimization
     * Compiled once at class loading, avoiding repeated Pattern.compile() calls
     * Performance improvement: ~50x faster than compiling patterns on every check
     */
    private static final List<Pattern> COMPILED_ERROR_PATTERNS;

    /**
     * Precompiled pattern for newline removal
     * Used in response body cleaning before regex matching
     */
    private static final Pattern NEWLINE_PATTERN;

    static {
        // Precompile all 92 error detection rules at class loading time
        COMPILED_ERROR_PATTERNS = Arrays.stream(rules)
            .map(rule -> Pattern.compile(rule, Pattern.CASE_INSENSITIVE))
            .collect(Collectors.toList());

        // Precompile newline removal pattern
        NEWLINE_PATTERN = Pattern.compile("\\n|\\r|\\r\\n");
    }
    public int countId;
    public static Set<String> blackParamsSet = ConcurrentHashMap.newKeySet();
    public static Set<String> whiteParamsSet = ConcurrentHashMap.newKeySet();
    public static volatile int staticTime = 100;
    public static volatile int startTime = 0;
    public static volatile int endTime = 0;

    public MyHttpHandler(MontoyaApi mapi, SourceTableModel sourceTableModel, PocTableModel pocTableModel,
                        ConcurrentHashMap<String, List<PocLogEntry>> attackMap, DetSqlConfig config,
                        DetSqlLogger logger, Statistics statistics) {
        this.api = mapi;
        this.config = config;
        this.logger = logger;
        this.statistics = statistics;
        this.sourceTableModel = sourceTableModel;
        this.pocTableModel = pocTableModel;
        this.attackMap = attackMap;
        this.semaphore = new Semaphore(config.getThreadPoolSize());
        this.semaphore2 = new Semaphore(config.getThreadPoolSize2());
        this.cryptoUtils = api.utilities().cryptoUtils();
        this.lk = new ReentrantLock();
        this.countId = 1;  // Dashboard ID 从 1 开始
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }

    /**
     * Request processing context - encapsulates the differences between request types
     * Eliminates 4 duplicate code blocks by parameterizing the variations
     */
    private static class RequestContext {
        final boolean isSmallResponse;
        final boolean isFromProxy;
        final Semaphore semaphore;
        final String hash;

        RequestContext(HttpResponseReceived response, CryptoUtils crypto,
                      Semaphore normalSemaphore, Semaphore throttledSemaphore) {
            int bodyLength = response.bodyToString().length();
            this.isSmallResponse = bodyLength < SMALL_RESPONSE_THRESHOLD;
            this.isFromProxy = MyFilterRequest.fromProxySource(response);

            // Choose semaphore based on response size
            this.semaphore = isSmallResponse ? normalSemaphore : throttledSemaphore;

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
        boolean isProxyMode = DetSql.switchCheck.isSelected()
            && MyFilterRequest.fromProxySource(response)
            && MyFilterRequest.filterOneRequest(response);

        boolean isRepeaterMode = DetSql.vulnCheck.isSelected()
            && MyFilterRequest.fromRepeaterSource(response)
            && MyFilterRequest.filterOneRequest(response);

        return isProxyMode || isRepeaterMode;
    }

    /**
     * Creates initial log entry and returns the log index
     */
    private int createLogEntry(HttpResponseReceived response, String hash) {
        lk.lock();
        try {
            int logIndex = countId;
            countId++; // move into lock to ensure uniqueness
            attackMap.putIfAbsent(hash, new ArrayList<>()); // initialize under lock to avoid races

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
                        HttpResponse.httpResponse()
                    ),
                    response.initiatingRequest().httpService().toString(),
                    response.initiatingRequest().method(),
                    response.initiatingRequest().pathWithoutQuery()
                ));
            });
            return logIndex;
        } finally {
            lk.unlock();
        }
    }

    // Package-private helper for concurrency smoke tests without instantiating heavy dependencies
    static int allocateIdAndInitMapForTest(Lock lock,
                                           int[] countIdRef,
                                           java.util.concurrent.ConcurrentHashMap<String, java.util.List<PocLogEntry>> map,
                                           String hash) {
        lock.lock();
        try {
            int id = countIdRef[0];
            countIdRef[0]++;
            map.putIfAbsent(hash, new java.util.ArrayList<>());
            return id;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Updates log entry with vulnerability type or empty/stopped status
     */
    private void updateLogEntry(HttpResponseReceived response, String hash,
                               int logIndex, String vulnType) {
        final int finalLogIndex = logIndex;
        final String finalVulnType = (vulnType == null) ? "" : vulnType;
        // memory clean: if no vuln, drop heavy HTTP data for this request
        if (finalVulnType.isBlank()) {
            attackMap.remove(hash);
        }

        SwingUtilities.invokeLater(() -> {
            SourceLogEntry newEntry = new SourceLogEntry(
                finalLogIndex,
                response.toolSource().toolType().toolName(),
                hash,
                finalVulnType,
                response.bodyToString().length(),
                finalVulnType.isBlank() ? null : HttpRequestResponse.httpRequestResponse(
                    response.initiatingRequest(),
                    HttpResponse.httpResponse(response.toByteArray())
                ),
                response.initiatingRequest().httpService().toString(),
                response.initiatingRequest().method(),
                response.initiatingRequest().pathWithoutQuery()
            );

            int rowIndex = sourceTableModel.log.indexOf(
                new SourceLogEntry(finalLogIndex, null, null, null, 0, null, null, null, null)
            );
            sourceTableModel.updateVulnState(newEntry, rowIndex, rowIndex);
        });
    }

    /**
     * Unified request processing - replaces 4 duplicate code blocks
     */
    private void processRequest(HttpResponseReceived response, RequestContext ctx) {
        Thread.currentThread().setName(ctx.hash);

        // Skip if Proxy source and already processed
        if (ctx.isFromProxy && attackMap.containsKey(ctx.hash)) {
            return;
        }

        int logIndex = createLogEntry(response, ctx.hash);
        logger.info("Processing request: " + ctx.hash + " (ID: " + logIndex + ")");
        statistics.incrementRequestsProcessed();

        try {
            String vulnType = "";
            ctx.semaphore.acquire();
            try {
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
                                    entries
                                );
                            }
                        } catch (Exception ignore) {
                            // do not break flow on statistics aggregation error
                        }
                    } else {
                        logger.debug("No vulnerability found in " + ctx.hash + " (took " + duration + "ms)");
                    }
                }
            } finally {
                ctx.semaphore.release();
                updateLogEntry(response, ctx.hash, logIndex, vulnType);
            }
        } catch (InterruptedException e) {
            updateLogEntry(response, ctx.hash, logIndex, "手动停止");
            logger.warn("Request processing interrupted: " + ctx.hash);
        } catch (Exception e) {
            logger.error("Request processing failed: " + ctx.hash, e);
            statistics.incrementDetectionErrors();
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        new Thread(() -> {
            try {
                int bodyLength = httpResponseReceived.bodyToString().length();

                // Early return: empty or oversized response
                if (bodyLength == 0 || bodyLength >= config.getMaxResponseSize()) {
                    statistics.incrementRequestsFiltered();
                    logger.info("Request filtered: body size " + bodyLength + " bytes");
                    return;
                }

                // Early return: not enabled or filtered out
                if (!DetSql.switchCheck.isSelected() && !DetSql.vulnCheck.isSelected()) {
                    return;
                }

                // Early return: doesn't pass filter check
                if (!shouldProcess(httpResponseReceived)) {
                    statistics.incrementRequestsFiltered();
                    return;
                }

                // Unified processing with context
                RequestContext ctx = new RequestContext(
                    httpResponseReceived,
                    cryptoUtils,
                    semaphore,
                    semaphore2
                );

                processRequest(httpResponseReceived, ctx);

            } catch (Exception e) {
                logger.error("HTTP response handling failed", e);
                statistics.incrementDetectionErrors();
            }
        }).start();

        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }


    public String processAutoResponse(HttpResponseReceived httpResponseReceived, String requestSm3Hash) throws InterruptedException {
        HttpRequest sourceHttpRequest = httpResponseReceived.initiatingRequest().copyToTempFile();
        String sourceBody = httpResponseReceived.body().toString();
        boolean html_flag = httpResponseReceived.mimeType().description().equals("HTML");
        return processRequestInternal(sourceHttpRequest, sourceBody, html_flag, requestSm3Hash);
    }

    private String processRequestInternal(HttpRequest sourceHttpRequest, String sourceBody, boolean html_flag, String requestSm3Hash) throws InterruptedException {
        boolean errFlag = false;
        boolean numFlag = false;
        boolean orderFlag = false;
        boolean stringFlag = false;
        boolean boolFlag = false;

        boolean diyFlag = false;
        List<PocLogEntry> getAttackList = attackMap.get(requestSm3Hash);
        if (!sourceHttpRequest.parameters(HttpParameterType.URL).isEmpty()) {
            //新参数
            List<ParsedHttpParameter> parameters = sourceHttpRequest.parameters(HttpParameterType.URL);
            ArrayList<HttpParameter> newHttpParameters = new ArrayList<>();
            for (ParsedHttpParameter parameter : parameters) {
                newHttpParameters.add(HttpParameter.urlParameter(parameter.name(), parameter.value()));
            }
            //报错 - 使用提取的方法
            errFlag = testErrorInjection(newHttpParameters, sourceHttpRequest,
                (source, name, value, payload) -> {
                    List<HttpParameter> pocParams = new ArrayList<>(newHttpParameters);
                    int index = newHttpParameters.indexOf(HttpParameter.urlParameter(name, value));
                    pocParams.set(index, HttpParameter.urlParameter(name, value + payload));
                    return source.withUpdatedParameters(pocParams);
                }, requestSm3Hash);

            // URL参数 - DIY Payload检测（使用统一方法）
            if (testDiyInjection(
                sourceHttpRequest,
                parameters,
                ParameterModifiers.URL,
                requestSm3Hash
            )) {
                diyFlag = true;
            }


            // URL参数 - 字符串注入检测 (使用统一方法)
            stringFlag = testStringInjection(
                sourceHttpRequest,
                sourceBody,
                html_flag,
                parameters,
                ParameterModifiers.URL,
                requestSm3Hash
            );


            // URL参数 - 数字注入检测 (使用统一方法)
            if (testNumericInjection(
                sourceHttpRequest,
                sourceBody,
                html_flag,
                parameters,
                ParameterModifiers.URL,
                requestSm3Hash
            )) {
                numFlag = true;
            }


            // URL参数 - Order注入检测 (使用统一方法)
            if (testOrderInjection(
                sourceHttpRequest,
                sourceBody,
                html_flag,
                parameters,
                ParameterModifiers.URL,
                requestSm3Hash
            )) {
                orderFlag = true;
            }
            // URL参数 - Boolean注入检测 (使用统一方法)
            if (testBooleanInjection(
                sourceHttpRequest,
                sourceBody,
                html_flag,
                parameters,
                ParameterModifiers.URL,
                requestSm3Hash
            )) {
                boolFlag = true;
            }

        }
        //处理post/PUT
        if (sourceHttpRequest.method().equals(METHOD_POST) || sourceHttpRequest.method().equals(METHOD_PUT)) {
            if (!sourceHttpRequest.parameters(HttpParameterType.BODY).isEmpty()) {
                //新参数
                List<ParsedHttpParameter> parameters = sourceHttpRequest.parameters(HttpParameterType.BODY);
                ArrayList<HttpParameter> newHttpParameters = new ArrayList<>();
                for (ParsedHttpParameter parameter : parameters) {
                    newHttpParameters.add(HttpParameter.bodyParameter(parameter.name(), parameter.value()));
                }
                //err - 使用提取的方法
                errFlag = testErrorInjection(newHttpParameters, sourceHttpRequest,
                    (source, name, value, payload) -> {
                        List<HttpParameter> pocParams = new ArrayList<>(newHttpParameters);
                        int index = newHttpParameters.indexOf(HttpParameter.bodyParameter(name, value));
                        pocParams.set(index, HttpParameter.bodyParameter(name, value + payload));
                        return source.withUpdatedParameters(pocParams);
                    }, requestSm3Hash);

                // BODY参数 - DIY Payload检测（使用统一方法）
                if (testDiyInjection(
                    sourceHttpRequest,
                    parameters,
                    ParameterModifiers.BODY,
                    requestSm3Hash
                )) {
                    diyFlag = true;
                }
                // BODY参数 - 字符串注入检测 (使用统一方法)
                stringFlag = testStringInjection(
                    sourceHttpRequest,
                    sourceBody,
                    html_flag,
                    parameters,
                    ParameterModifiers.BODY,
                    requestSm3Hash
                );


                // BODY参数 - 数字注入检测 (使用统一方法)
                if (testNumericInjection(
                    sourceHttpRequest,
                    sourceBody,
                    html_flag,
                    parameters,
                    ParameterModifiers.BODY,
                    requestSm3Hash
                )) {
                    numFlag = true;
                }

                // BODY参数 - Order注入检测 (使用统一方法)
                if (testOrderInjection(
                    sourceHttpRequest,
                    sourceBody,
                    html_flag,
                    parameters,
                    ParameterModifiers.BODY,
                    requestSm3Hash
                )) {
                    orderFlag = true;
                }
                // BODY参数 - Boolean注入检测 (使用统一方法)
                if (testBooleanInjection(
                    sourceHttpRequest,
                    sourceBody,
                    html_flag,
                    parameters,
                    ParameterModifiers.BODY,
                    requestSm3Hash
                )) {
                    boolFlag = true;
                }
            } else if (!sourceHttpRequest.parameters(HttpParameterType.JSON).isEmpty()) {
                List<ParsedHttpParameter> parameters = sourceHttpRequest.parameters(HttpParameterType.JSON);
                String sourceRequestIndex = sourceHttpRequest.toByteArray().toString();
                int bodyStartIndex = sourceHttpRequest.bodyOffset();
                //err - 使用提取的方法 (JSON需要引号检查,使用errPocsj)
                errFlag = testErrorInjectionStringBased(parameters, sourceHttpRequest,
                    sourceRequestIndex, bodyStartIndex, errPocsj, true, requestSm3Hash);
                //diy
                if (shouldRunDiyInjection()){
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        if (sourceRequestIndex.charAt(valueStart - 1) == '"' && sourceRequestIndex.charAt(valueEnd) == '"') {
                            String paramName = parameter.name();
                            if(shouldSkipParameter(paramName)){
                                continue;
                            }
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            for (String errPoc : diyPayloads) {
                                String pocBody = prefix + errPoc + suffix;
                                HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                                HttpRequestResponse pocHttpRequestResponse = sendHttpRequest(pocHttpRequest, DEFAULT_RETRY_COUNT);
                                String pocResponseBody = extractResponseBody(pocHttpRequestResponse);
                                if(!diyRegexs.isEmpty()){
                                    String resBool = diyRegexCheck(pocResponseBody);
                                    if (resBool != null) {
                                        PocLogEntry logEntry = PocLogEntry.fromResponse(paramName, errPoc, null, VULN_TYPE_DIY + "(" + resBool + ")", pocHttpRequestResponse, requestSm3Hash);
                                        getAttackList.add(logEntry);
                                        diyFlag = true;
                                    }
                                }
                                long responseTime = pocHttpRequestResponse.timingData()
                                    .map(timing -> timing.timeBetweenRequestSentAndEndOfResponse().toMillis())
                                    .orElse(0L);
                                if(!DetSql.timeTextField.getText().isEmpty() && responseTime > intTime){
                                    PocLogEntry logEntry = PocLogEntry.fromResponse(paramName, errPoc, null, VULN_TYPE_DIY + "(time)", pocHttpRequestResponse, requestSm3Hash);
                                    getAttackList.add(logEntry);
                                    diyFlag = true;
                                }
                            }
                        }
                    }
                }

                // JSON参数 - 字符串注入检测 (使用统一方法)
                // 预过滤：只测试被双引号包裹的字符串值
                List<ParsedHttpParameter> jsonStringParams = new ArrayList<>();
                for (ParsedHttpParameter param : parameters) {
                    int valueStart = param.valueOffsets().startIndexInclusive();
                    int valueEnd = param.valueOffsets().endIndexExclusive();
                    if (sourceRequestIndex.charAt(valueStart - 1) == '"' && sourceRequestIndex.charAt(valueEnd) == '"') {
                        jsonStringParams.add(param);
                    }
                }
                stringFlag = testStringInjection(
                    sourceHttpRequest,
                    sourceBody,
                    html_flag,
                    jsonStringParams,
                    ParameterModifiers.JSON,
                    requestSm3Hash
                );

                // JSON参数 - Order注入检测 (使用统一方法)
                // 预过滤：只测试被双引号包裹且非空的字符串值
                List<ParsedHttpParameter> jsonOrderParams = new ArrayList<>();
                for (ParsedHttpParameter param : parameters) {
                    int valueStart = param.valueOffsets().startIndexInclusive();
                    int valueEnd = param.valueOffsets().endIndexExclusive();
                    if (sourceRequestIndex.charAt(valueStart - 1) == '"'
                        && sourceRequestIndex.charAt(valueEnd) == '"'
                        && valueStart != valueEnd) {
                        jsonOrderParams.add(param);
                    }
                }
                if (testOrderInjection(
                    sourceHttpRequest,
                    sourceBody,
                    html_flag,
                    jsonOrderParams,
                    ParameterModifiers.JSON,
                    requestSm3Hash
                )) {
                    orderFlag = true;
                }

                // JSON参数 - Boolean注入检测 (使用统一方法)
                // 预过滤：只测试被双引号包裹的字符串值
                List<ParsedHttpParameter> jsonBoolParams = new ArrayList<>();
                for (ParsedHttpParameter param : parameters) {
                    int valueStart = param.valueOffsets().startIndexInclusive();
                    int valueEnd = param.valueOffsets().endIndexExclusive();
                    if (sourceRequestIndex.charAt(valueStart - 1) == '"'
                        && sourceRequestIndex.charAt(valueEnd) == '"') {
                        jsonBoolParams.add(param);
                    }
                }
                if (testBooleanInjection(
                    sourceHttpRequest,
                    sourceBody,
                    html_flag,
                    jsonBoolParams,
                    ParameterModifiers.JSON,
                    requestSm3Hash
                )) {
                    boolFlag = true;
                }


            } else if (!sourceHttpRequest.parameters(HttpParameterType.XML).isEmpty()) {

                List<ParsedHttpParameter> parameters = sourceHttpRequest.parameters(HttpParameterType.XML);
                String sourceRequestIndex = sourceHttpRequest.toByteArray().toString();
                int bodyStartIndex = sourceHttpRequest.bodyOffset();
                //err - 使用提取的方法 (XML不需要引号检查,使用errPocsj)
                errFlag = testErrorInjectionStringBased(parameters, sourceHttpRequest,
                    sourceRequestIndex, bodyStartIndex, errPocsj, false, requestSm3Hash);
                //diy
                if (shouldRunDiyInjection()){
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        String paramName = parameter.name();
                        if(shouldSkipParameter(paramName)){
                            continue;
                        }
                        String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                        String suffix = sourceRequestIndex.substring(valueEnd);
                        for (String errPoc : diyPayloads) {
                            String pocBody = prefix + errPoc + suffix;
                            HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                            HttpRequestResponse pocHttpRequestResponse = sendHttpRequest(pocHttpRequest, DEFAULT_RETRY_COUNT);
                            String pocResponseBody = extractResponseBody(pocHttpRequestResponse);
                            if(!diyRegexs.isEmpty()){
                                String resBool = diyRegexCheck(pocResponseBody);
                                if (resBool != null) {
                                    PocLogEntry logEntry = PocLogEntry.fromResponse(paramName, errPoc, null, "diypoc(" + resBool + ")", pocHttpRequestResponse, requestSm3Hash);
                                    getAttackList.add(logEntry);
                                    diyFlag = true;
                                }
                            }
                            long responseTime = pocHttpRequestResponse.timingData()
                                .map(timing -> timing.timeBetweenRequestSentAndEndOfResponse().toMillis())
                                .orElse(0L);
                            if(!DetSql.timeTextField.getText().isEmpty() && responseTime > intTime){
                                PocLogEntry logEntry = PocLogEntry.fromResponse(paramName, errPoc, null, "diypoc(time)", pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                diyFlag = true;
                            }
                        }
                    }
                }


                // XML参数 - 数字注入检测 (使用统一方法)
                if (testNumericInjection(
                    sourceHttpRequest,
                    sourceBody,
                    html_flag,
                    parameters,
                    ParameterModifiers.XML,
                    requestSm3Hash
                )) {
                    numFlag = true;
                }
                // XML参数 - 字符串注入检测 (使用统一方法)
                stringFlag = testStringInjection(
                    sourceHttpRequest,
                    sourceBody,
                    html_flag,
                    parameters,
                    ParameterModifiers.XML,
                    requestSm3Hash
                );
                // XML参数 - Order注入检测 (使用统一方法)
                // 预过滤：只测试非空的参数值
                List<ParsedHttpParameter> xmlOrderParams = new ArrayList<>();
                for (ParsedHttpParameter param : parameters) {
                    int valueStart = param.valueOffsets().startIndexInclusive();
                    int valueEnd = param.valueOffsets().endIndexExclusive();
                    if (valueStart != valueEnd) {
                        xmlOrderParams.add(param);
                    }
                }
                if (testOrderInjection(
                    sourceHttpRequest,
                    sourceBody,
                    html_flag,
                    xmlOrderParams,
                    ParameterModifiers.XML,
                    requestSm3Hash
                )) {
                    orderFlag = true;
                }

                // XML参数 - Boolean注入检测 (使用统一方法)
                if (testBooleanInjection(
                    sourceHttpRequest,
                    sourceBody,
                    html_flag,
                    parameters,
                    ParameterModifiers.XML,
                    requestSm3Hash
                )) {
                    boolFlag = true;
                }


            }
        }//POST 处理结束
        //处理cookie
        if (DetSql.cookieCheck.isSelected() && !sourceHttpRequest.parameters(HttpParameterType.COOKIE).isEmpty()) {
            List<ParsedHttpParameter> parameters = sourceHttpRequest.parameters(HttpParameterType.COOKIE);
            ArrayList<HttpParameter> newHttpParameters = new ArrayList<>();
            for (ParsedHttpParameter parameter : parameters) {
                newHttpParameters.add(HttpParameter.cookieParameter(parameter.name(), parameter.value()));
            }
            //err - 使用提取的方法
            errFlag = testErrorInjection(newHttpParameters, sourceHttpRequest,
                (source, name, value, payload) -> {
                    List<HttpParameter> pocParams = new ArrayList<>(newHttpParameters);
                    int index = newHttpParameters.indexOf(HttpParameter.cookieParameter(name, value));
                    pocParams.set(index, HttpParameter.cookieParameter(name, value + payload));
                    return source.withUpdatedParameters(pocParams);
                }, requestSm3Hash);

            // COOKIE参数 - DIY Payload检测（使用统一方法）
            if (testDiyInjection(
                sourceHttpRequest,
                parameters,
                ParameterModifiers.COOKIE,
                requestSm3Hash
            )) {
                diyFlag = true;
            }
            // COOKIE参数 - 字符串注入检测 (使用统一方法)
            stringFlag = testStringInjection(
                sourceHttpRequest,
                sourceBody,
                html_flag,
                parameters,
                ParameterModifiers.COOKIE,
                requestSm3Hash
            );

            // COOKIE参数 - 数字注入检测 (使用统一方法)
            if (testNumericInjection(
                sourceHttpRequest,
                sourceBody,
                html_flag,
                parameters,
                ParameterModifiers.COOKIE,
                requestSm3Hash
            )) {
                numFlag = true;
            }
            // COOKIE参数 - Order注入检测 (使用统一方法)
            if (testOrderInjection(
                sourceHttpRequest,
                sourceBody,
                html_flag,
                parameters,
                ParameterModifiers.COOKIE,
                requestSm3Hash
            )) {
                orderFlag = true;
            }

            // COOKIE参数 - Boolean注入检测 (使用统一方法)
            if (testBooleanInjection(
                sourceHttpRequest,
                sourceBody,
                html_flag,
                parameters,
                ParameterModifiers.COOKIE,
                requestSm3Hash
            )) {
                boolFlag = true;
            }
        }
        return buildResultString(errFlag, stringFlag, numFlag, orderFlag, boolFlag, diyFlag);
    }

    /**
     * Builds result string from injection detection flags
     * @param errFlag true if error-based injection detected
     * @param stringFlag true if string-based injection detected
     * @param numFlag true if numeric injection detected
     * @param orderFlag true if order-by injection detected
     * @param boolFlag true if boolean-based injection detected
     * @param diyFlag true if custom DIY injection detected
     * @return concatenated string of detected injection types
     */
    // Package-private for unit testing; retains original behavior
    static String buildResultStringExposed(boolean errFlag, boolean stringFlag, boolean numFlag,
                                      boolean orderFlag, boolean boolFlag, boolean diyFlag) {
        StringBuilder sb = new StringBuilder();
        if (errFlag) sb.append("-").append(VULN_TYPE_ERROR);
        if (stringFlag) sb.append("-").append(VULN_TYPE_STRING);
        if (numFlag) sb.append("-").append(VULN_TYPE_NUMERIC);
        if (orderFlag) sb.append("-").append(VULN_TYPE_ORDER);
        if (boolFlag) sb.append("-").append(VULN_TYPE_BOOLEAN);
        if (diyFlag) sb.append("-").append(VULN_TYPE_DIY);
        return sb.toString();
    }

    private String buildResultString(boolean errFlag, boolean stringFlag, boolean numFlag,
                                     boolean orderFlag, boolean boolFlag, boolean diyFlag) {
        return buildResultStringExposed(errFlag, stringFlag, numFlag, orderFlag, boolFlag, diyFlag);
    }

    /**
     * Unified string-based SQL injection detection method
     *
     * Detection Logic (4 steps):
     * 1. ' - Single quote, expect ERROR/different response (breaks SQL syntax)
     * 2. '' - Escaped quote, expect different from step 1 (fixes SQL syntax)
     * 3. '+' - Concatenate empty string, expect similar to original (valid SQL)
     * 4. '||' - Alternative concatenation (Oracle/PostgreSQL), similar to original
     *
     * Why this works:
     * - Step 1 breaks SQL → different response
     * - Step 2 fixes SQL but different behavior → different from step 1
     * - Step 3/4 concatenates empty string → same result as original
     * - If responses match this pattern, confirms string-based injection
     *
     * Early exit: If step 3 succeeds, skip step 4 (both test same vulnerability)
     *
     * @param sourceRequest original HTTP request
     * @param sourceBody original response body
     * @param htmlFlag whether response is HTML (affects similarity calculation)
     * @param params list of parameters to test
     * @param modifier parameter modification strategy (URL/BODY/JSON/XML/COOKIE)
     * @param requestHash unique hash identifying this request
     * @return true if string injection detected, false otherwise
     * @throws InterruptedException if thread is interrupted
     */
    private boolean testStringInjection(
            HttpRequest sourceRequest,
            String sourceBody,
            boolean htmlFlag,
            List<ParsedHttpParameter> params,
            ParameterModifier modifier,
            String requestHash) throws InterruptedException {

        // Check if string injection detection is enabled
        if (!DetSql.stringCheck.isSelected()) {
            return false;
        }

        boolean foundVulnerability = false;
        List<PocLogEntry> attackList = attackMap.get(requestHash);

        stringloop:
        for (int i = 0; i < params.size(); i++) {
            // Check for thread interruption
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("Detection interrupted");
            }

            ParsedHttpParameter param = params.get(i);
            String paramName = param.name();

            // Skip blacklisted parameters
            if (shouldSkipParameter(paramName)) {
                continue;
            }

            // Collect all PoC results for this parameter
            List<PocLogEntry> pocEntries = new ArrayList<>();

            // Step 1: Single quote test - expect dissimilar (breaks SQL syntax)
            HttpRequest req1 = modifier.modifyParameter(sourceRequest, param, "'");
            HttpRequestResponse resp1 = sendHttpRequest(req1, DEFAULT_RETRY_COUNT);
            String body1 = extractResponseBody(resp1);

            List<Double> sim1 = MyCompare.averageLevenshtein(sourceBody, body1, "", "", htmlFlag);
            double minSim1 = Collections.min(sim1);

            if (minSim1 > config.getSimilarityThreshold()) {
                // Failed: single quote didn't change response → not an injection point
                continue stringloop;
            }

            pocEntries.add(PocLogEntry.fromResponse(
                paramName, "'", MyCompare.formatPercent(minSim1),
                VULN_TYPE_STRING, resp1, requestHash
            ));

            // Step 2: Double quote test - expect dissimilar from step 1
            HttpRequest req2 = modifier.modifyParameter(sourceRequest, param, "''");
            HttpRequestResponse resp2 = sendHttpRequest(req2, DEFAULT_RETRY_COUNT);
            String body2 = extractResponseBody(resp2);

            List<Double> sim2 = MyCompare.averageLevenshtein(body1, body2, "", "", htmlFlag);
            double minSim2 = Collections.min(sim2);

            if (minSim2 > config.getSimilarityThreshold()) {
                // Failed: double quote same as single quote → not SQL injection
                continue stringloop;
            }

            pocEntries.add(PocLogEntry.fromResponse(
                paramName, "''", MyCompare.formatPercent(minSim2),
                VULN_TYPE_STRING, resp2, requestHash
            ));

            // Step 3: '+' test - expect similar to original response
            String plusPayload = modifier.needsUrlEncoding() ? "'%2B'" : "'+'";
            HttpRequest req3 = modifier.modifyParameter(sourceRequest, param, plusPayload);
            HttpRequestResponse resp3 = sendHttpRequest(req3, DEFAULT_RETRY_COUNT);
            String body3 = extractResponseBody(resp3);

            List<Double> sim3 = MyCompare.averageLevenshtein(sourceBody, body3, "", "'+'", htmlFlag);
            double maxSim3 = Collections.max(sim3);

            if (maxSim3 > config.getSimilarityThreshold()) {
                // Success: '+' concatenation same as original → confirmed SQL injection
                pocEntries.add(PocLogEntry.fromResponse(
                    paramName, "'+'", MyCompare.formatPercent(maxSim3),
                    VULN_TYPE_STRING, resp3, requestHash
                ));
                attackList.addAll(pocEntries);
                foundVulnerability = true;
                continue stringloop; // Skip to next parameter
            }

            // Step 4: '||' test - alternative concatenation (Oracle/PostgreSQL)
            HttpRequest req4 = modifier.modifyParameter(sourceRequest, param, "'||'");
            HttpRequestResponse resp4 = sendHttpRequest(req4, DEFAULT_RETRY_COUNT);
            String body4 = extractResponseBody(resp4);

            List<Double> sim4 = MyCompare.averageLevenshtein(sourceBody, body4, "", "'||'", htmlFlag);
            double maxSim4 = Collections.max(sim4);

            if (maxSim4 > config.getSimilarityThreshold()) {
                // Success: '||' concatenation same as original → confirmed SQL injection
                pocEntries.add(PocLogEntry.fromResponse(
                    paramName, "'||'", MyCompare.formatPercent(maxSim4),
                    VULN_TYPE_STRING, resp4, requestHash
                ));
                attackList.addAll(pocEntries);
                foundVulnerability = true;
            }
        }

        return foundVulnerability;
    }

    /**
     * 统一的数字注入检测方法
     *
     * Detection Logic (2 steps):
     * 1. value-0-0-0 - Expect similar to original response (valid arithmetic)
     * 2. value-abc - Expect dissimilar to both original and step 1 (invalid arithmetic)
     *
     * Why this works:
     * - Step 1: value-0-0-0 = value (arithmetic) → same result as original
     * - Step 2: value-abc causes error → different from both responses
     * - If responses match this pattern, confirms numeric injection
     *
     * @param sourceRequest 原始HTTP请求
     * @param sourceBody 原始响应体
     * @param htmlFlag 是否为HTML响应
     * @param params 要测试的参数列表
     * @param modifier 参数修改策略
     * @param requestHash 请求的SM3哈希值
     * @return 是否发现漏洞
     * @throws InterruptedException 线程中断异常
     */
    private boolean testNumericInjection(
        HttpRequest sourceRequest,
        String sourceBody,
        boolean htmlFlag,
        List<ParsedHttpParameter> params,
        ParameterModifier modifier,
        String requestHash
    ) throws InterruptedException {

        // 检查是否启用数字注入检测
        if (!DetSql.numCheck.isSelected()) {
            return false;
        }

        boolean foundVuln = false;
        List<PocLogEntry> attackList = attackMap.get(requestHash);

        numloop:
        for (int i = 0; i < params.size(); i++) {
            // 检查线程中断
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("检测被中断");
            }

            ParsedHttpParameter param = params.get(i);
            String paramName = param.name();
            String paramValue = param.value();

            // 跳过黑名单参数
            if (shouldSkipParameter(paramName)) {
                continue;
            }

            // 检查是否为纯数字参数
            if (!isNumeric(paramValue)) {
                continue;
            }

            List<PocLogEntry> pocEntries = new ArrayList<>();

            // 测试1: value-0-0-0 - 期望与原始响应相似
            String payload1 = "-0-0-0";
            HttpRequest req1 = modifier.modifyParameter(sourceRequest, param, payload1);
            HttpRequestResponse resp1 = sendHttpRequest(req1, DEFAULT_RETRY_COUNT);
            String body1 = extractResponseBody(resp1);

            List<Double> sim1 = MyCompare.averageLevenshtein(sourceBody, body1, "", payload1, htmlFlag);
            double maxSim1 = Collections.max(sim1);

            if (maxSim1 <= config.getSimilarityThreshold()) {
                continue numloop; // 测试失败，跳过此参数
            }

            pocEntries.add(PocLogEntry.fromResponse(
                paramName, payload1, MyCompare.formatPercent(maxSim1),
                VULN_TYPE_NUMERIC, resp1, requestHash
            ));

            // 测试2: value-abc - 期望与原始响应和测试1响应都不相似
            String payload2 = "-abc";
            HttpRequest req2 = modifier.modifyParameter(sourceRequest, param, payload2);
            HttpRequestResponse resp2 = sendHttpRequest(req2, DEFAULT_RETRY_COUNT);
            String body2 = extractResponseBody(resp2);

            // 检查与原始响应的相似度
            List<Double> sim2Source = MyCompare.averageLevenshtein(sourceBody, body2, "", "", htmlFlag);
            double minSim2Source = Collections.min(sim2Source);

            if (minSim2Source > config.getSimilarityThreshold()) {
                continue numloop; // 测试失败，跳过此参数
            }

            pocEntries.add(PocLogEntry.fromResponse(
                paramName, payload2, MyCompare.formatPercent(minSim2Source),
                VULN_TYPE_NUMERIC, resp2, requestHash
            ));

            // 检查与测试1响应的相似度
            List<Double> sim2First = MyCompare.averageLevenshtein(body1, body2, "", "", htmlFlag);
            double minSim2First = Collections.min(sim2First);

            if (minSim2First <= config.getSimilarityThreshold()) {
                attackList.addAll(pocEntries);
                foundVuln = true;
            }
        }

        return foundVuln;
    }

    /**
     * 检查字符串是否为纯数字
     * 支持Long范围的整数判断
     *
     * @param str 要检查的字符串
     * @return true表示是纯数字, false表示不是
     */
    // Package-private for unit testing; retains original behavior
    static boolean isNumericExposed(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        try {
            Long.parseLong(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private boolean isNumeric(String str) {
        return isNumericExposed(str);
    }

    /**
     * 统一的Order By注入检测方法
     *
     * Detection Logic (4 steps):
     * 1. value,0 - Expect dissimilar to original (invalid column index)
     * 2. value,xxxxxx - Expect dissimilar to original (invalid column name)
     * 3. Verify step 1 and 2 are similar to each other (both invalid inputs)
     * 4. value,1 or value,2 - Expect similar to original (valid column index)
     *
     * Why this works:
     * - Step 1: ORDER BY 0 is invalid → different response
     * - Step 2: ORDER BY xxxxxx is invalid → different response
     * - Step 3: Both invalid → same error → similar to each other
     * - Step 4: ORDER BY 1/2 is valid → same result as original
     * - If responses match this pattern, confirms Order By injection
     *
     * IMPORTANT: Uses Jaccard similarity (not Levenshtein) for Order injection
     *
     * @param sourceRequest 原始HTTP请求
     * @param sourceBody 原始响应体
     * @param htmlFlag 是否为HTML响应
     * @param params 要测试的参数列表
     * @param modifier 参数修改策略
     * @param requestHash 请求的SM3哈希值
     * @return 是否发现漏洞
     * @throws InterruptedException 线程中断异常
     */
    private boolean testOrderInjection(
        HttpRequest sourceRequest,
        String sourceBody,
        boolean htmlFlag,
        List<ParsedHttpParameter> params,
        ParameterModifier modifier,
        String requestHash
    ) throws InterruptedException {

        // 检查是否启用Order注入检测
        if (!DetSql.orderCheck.isSelected()) {
            return false;
        }

        boolean foundVuln = false;
        List<PocLogEntry> attackList = attackMap.get(requestHash);

        orderloop:
        for (int i = 0; i < params.size(); i++) {
            // 检查线程中断
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("检测被中断");
            }

            ParsedHttpParameter param = params.get(i);
            String paramName = param.name();
            String paramValue = param.value();

            // 跳过黑名单参数
            if (shouldSkipParameter(paramName)) {
                continue;
            }

            // 跳过空值参数
            if (paramValue.isBlank()) {
                continue;
            }

            List<PocLogEntry> pocEntries = new ArrayList<>();

            // 测试1: value,0 - 期望与原始响应不相似 (无效列索引)
            HttpRequest req1 = modifier.modifyParameter(sourceRequest, param, ",0");
            HttpRequestResponse resp1 = sendHttpRequest(req1, DEFAULT_RETRY_COUNT);
            String body1 = extractResponseBody(resp1);

            List<Double> sim1 = MyCompare.averageJaccard(sourceBody, body1, "", "", htmlFlag);
            double minSim1 = Collections.min(sim1);

            if (minSim1 > config.getSimilarityThreshold()) {
                continue orderloop; // 测试失败,跳过此参数
            }

            pocEntries.add(PocLogEntry.fromResponse(
                paramName, ",0", MyCompare.formatPercent(minSim1),
                VULN_TYPE_ORDER, resp1, requestHash
            ));

            // 测试2: value,xxxxxx - 期望与原始响应不相似 (无效列名)
            HttpRequest req2 = modifier.modifyParameter(sourceRequest, param, ",XXXXXX");
            HttpRequestResponse resp2 = sendHttpRequest(req2, DEFAULT_RETRY_COUNT);
            String body2 = extractResponseBody(resp2);

            List<Double> sim2 = MyCompare.averageJaccard(sourceBody, body2, "", "", htmlFlag);
            double minSim2 = Collections.min(sim2);

            if (minSim2 > config.getSimilarityThreshold()) {
                continue orderloop; // 测试失败,跳过此参数
            }

            pocEntries.add(PocLogEntry.fromResponse(
                paramName, ",XXXXXX", MyCompare.formatPercent(minSim2),
                VULN_TYPE_ORDER, resp2, requestHash
            ));

            // 测试3: 验证两个无效输入响应相似 (都是错误响应)
            List<Double> sim3 = MyCompare.averageJaccard(body1, body2, "", "", htmlFlag);
            double maxSim3 = Collections.max(sim3);

            if (maxSim3 <= config.getSimilarityThreshold()) {
                continue orderloop; // 测试失败,两个错误响应应该相似
            }

            // 测试4a: value,1 - 期望与原始响应相似 (有效列索引)
            HttpRequest req4a = modifier.modifyParameter(sourceRequest, param, ",1");
            HttpRequestResponse resp4a = sendHttpRequest(req4a, DEFAULT_RETRY_COUNT);
            String body4a = extractResponseBody(resp4a);

            List<Double> sim4a = MyCompare.averageJaccard(sourceBody, body4a, "", "", htmlFlag);
            double maxSim4a = Collections.max(sim4a);

            // 同时检查 ,1 与 ,0 不相似 (避免所有响应都相同的情况)
            List<Double> sim4aVs1 = MyCompare.averageJaccard(body1, body4a, "", "", htmlFlag);
            double minSim4aVs1 = Collections.min(sim4aVs1);

            if (maxSim4a > config.getSimilarityThreshold() && minSim4aVs1 <= config.getSimilarityThreshold()) {
                // 成功: ,1 与原始相似,且与 ,0 不相似
                pocEntries.add(PocLogEntry.fromResponse(
                    paramName, ",1", MyCompare.formatPercent(maxSim4a),
                    VULN_TYPE_ORDER, resp4a, requestHash
                ));
                attackList.addAll(pocEntries);
                foundVuln = true;
                continue orderloop;
            }

            // 测试4b: value,2 - 备选测试 (另一个有效列索引)
            HttpRequest req4b = modifier.modifyParameter(sourceRequest, param, ",2");
            HttpRequestResponse resp4b = sendHttpRequest(req4b, DEFAULT_RETRY_COUNT);
            String body4b = extractResponseBody(resp4b);

            List<Double> sim4b = MyCompare.averageJaccard(sourceBody, body4b, "", "", htmlFlag);
            double maxSim4b = Collections.max(sim4b);

            // 同时检查 ,2 与 ,0 不相似
            List<Double> sim4bVs1 = MyCompare.averageJaccard(body1, body4b, "", "", htmlFlag);
            double minSim4bVs1 = Collections.min(sim4bVs1);

            if (maxSim4b > config.getSimilarityThreshold() && minSim4bVs1 <= config.getSimilarityThreshold()) {
                // 成功: ,2 与原始相似,且与 ,0 不相似
                pocEntries.add(PocLogEntry.fromResponse(
                    paramName, ",2", MyCompare.formatPercent(maxSim4b),
                    VULN_TYPE_ORDER, resp4b, requestHash
                ));
                attackList.addAll(pocEntries);
                foundVuln = true;
            }
        }

        return foundVuln;
    }

    /**
     * 统一的Boolean注入检测方法
     *
     * Detection Logic (4 steps):
     * 1. '||EXP(710)||' - Trigger numeric overflow, expect ERROR/different response
     * 2a. '||EXP(290)||' (Primary) - Normal exponent value, expect different from step 1
     * 2b. '||1/0||' (Fallback) - Division by zero, some DBs handle gracefully
     * 3. '||1/1||' - Normal result (1), expect similar to step 2's successful response
     *
     * Why this works:
     * - Step 1 triggers error → different response
     * - Step 2 returns normal value → different from error
     * - Step 3 returns same value as step 2 → similar response
     * - If responses match this pattern, confirms boolean-based injection
     *
     * IMPORTANT: Uses Levenshtein similarity (not Jaccard) for Boolean injection
     *
     * @param sourceRequest 原始HTTP请求
     * @param sourceBody 原始响应体
     * @param htmlFlag 是否为HTML响应
     * @param params 要测试的参数列表
     * @param modifier 参数修改策略
     * @param requestHash 请求的SM3哈希值
     * @return 是否发现漏洞
     * @throws InterruptedException 线程中断异常
     */
    private boolean testBooleanInjection(
        HttpRequest sourceRequest,
        String sourceBody,
        boolean htmlFlag,
        List<ParsedHttpParameter> params,
        ParameterModifier modifier,
        String requestHash
    ) throws InterruptedException {

        // 检查是否启用Boolean注入检测
        if (!DetSql.boolCheck.isSelected()) {
            return false;
        }

        boolean foundVuln = false;
        List<PocLogEntry> attackList = attackMap.get(requestHash);

        boolloop:
        for (int i = 0; i < params.size(); i++) {
            // 检查线程中断
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("检测被中断");
            }

            ParsedHttpParameter param = params.get(i);
            String paramName = param.name();
            String paramValue = param.value();

            // 跳过黑名单参数
            if (shouldSkipParameter(paramName)) {
                continue;
            }

            List<PocLogEntry> pocEntries = new ArrayList<>();
            String referenceBody;  // 用于最后一步比较的参考响应

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 步骤1: '||EXP(710)||' - 触发溢出
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            HttpRequest req1 = modifier.modifyParameter(
                sourceRequest, param, "'||EXP(710)||'"
            );
            HttpRequestResponse resp1 = sendHttpRequest(req1, DEFAULT_RETRY_COUNT);
            String body1 = extractResponseBody(resp1);

            List<Double> sim1 = MyCompare.averageLevenshtein(
                sourceBody, body1, "", "", htmlFlag
            );
            double minSim1 = Collections.min(sim1);

            if (minSim1 > config.getSimilarityThreshold()) {
                // 失败: EXP(710)没有改变响应 → 不可能是注入点
                continue boolloop;
            }

            pocEntries.add(PocLogEntry.fromResponse(
                paramName, "'||EXP(710)||'", MyCompare.formatPercent(minSim1),
                VULN_TYPE_BOOLEAN, resp1, requestHash
            ));

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 步骤2a: '||EXP(290)||' - 正常值 (主要路径)
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            HttpRequest req2 = modifier.modifyParameter(
                sourceRequest, param, "'||EXP(290)||'"
            );
            HttpRequestResponse resp2 = sendHttpRequest(req2, DEFAULT_RETRY_COUNT);
            String body2 = extractResponseBody(resp2);

            List<Double> sim2 = MyCompare.averageLevenshtein(
                body1, body2, "", "", htmlFlag
            );
            double minSim2 = Collections.min(sim2);

            if (minSim2 <= config.getSimilarityThreshold()) {
                // 成功: EXP(290)与EXP(710)响应不同
                pocEntries.add(PocLogEntry.fromResponse(
                    paramName, "'||EXP(290)||'", MyCompare.formatPercent(minSim2),
                    VULN_TYPE_BOOLEAN, resp2, requestHash
                ));
                referenceBody = body2;
            } else {
                // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                // 步骤2b: '||1/0||' - 备选路径 (Division by zero)
                // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                // URL参数需要URL编码: / → %2F
                String divZeroPayload = modifier.needsUrlEncoding()
                    ? "'||1%2F0||'" : "'||1/0||'";

                HttpRequest req2b = modifier.modifyParameter(
                    sourceRequest, param, divZeroPayload
                );
                HttpRequestResponse resp2b = sendHttpRequest(req2b, DEFAULT_RETRY_COUNT);
                String body2b = extractResponseBody(resp2b);

                List<Double> sim2b = MyCompare.averageLevenshtein(
                    sourceBody, body2b, "", "'||1/0||'", htmlFlag
                );
                double maxSim2b = Collections.max(sim2b);

                if (maxSim2b <= config.getSimilarityThreshold()) {
                    // 失败: 备选路径也失败
                    continue boolloop;
                }

                pocEntries.add(PocLogEntry.fromResponse(
                    paramName, divZeroPayload, MyCompare.formatPercent(maxSim2b),
                    VULN_TYPE_BOOLEAN, resp2b, requestHash
                ));
                referenceBody = body2b;
            }

            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // 步骤3: '||1/1||' - 应该与步骤2相似
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            String divOnePayload = modifier.needsUrlEncoding()
                ? "'||1%2F1||'" : "'||1/1||'";

            HttpRequest req3 = modifier.modifyParameter(
                sourceRequest, param, divOnePayload
            );
            HttpRequestResponse resp3 = sendHttpRequest(req3, DEFAULT_RETRY_COUNT);
            String body3 = extractResponseBody(resp3);

            List<Double> sim3 = MyCompare.averageLevenshtein(
                referenceBody, body3, "EXP\\(290\\)", "1/1", htmlFlag
            );
            double maxSim3 = Collections.max(sim3);

            if (maxSim3 > config.getSimilarityThreshold()) {
                // 成功: 1/1 与参考响应相似 → 确认Boolean注入
                pocEntries.add(PocLogEntry.fromResponse(
                    paramName, divOnePayload, MyCompare.formatPercent(maxSim3),
                    VULN_TYPE_BOOLEAN, resp3, requestHash
                ));
                attackList.addAll(pocEntries);
                foundVuln = true;
            }
        }

        return foundVuln;
    }

    /**
     * 统一的DIY Payload检测方法
     * 支持regex匹配和time延迟两种检测方式
     *
     * @param sourceRequest 原始HTTP请求
     * @param params 要测试的参数列表
     * @param modifier 参数修改策略
     * @param requestHash 请求的SM3哈希值
     * @return 是否发现漏洞
     * @throws InterruptedException 线程中断异常
     */
    private boolean testDiyInjection(
        HttpRequest sourceRequest,
        List<ParsedHttpParameter> params,
        ParameterModifier modifier,
        String requestHash
    ) throws InterruptedException {

        // 检查是否启用DIY检测
        if (!shouldRunDiyInjection()) {
            return false;
        }

        boolean foundVuln = false;
        List<PocLogEntry> attackList = attackMap.get(requestHash);

        for (int i = 0; i < params.size(); i++) {
            // 检查线程中断
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("检测被中断");
            }

            ParsedHttpParameter param = params.get(i);
            String paramName = param.name();
            String paramValue = param.value();

            // 跳过黑名单参数
            if (shouldSkipParameter(paramName)) {
                continue;
            }

            // 测试所有DIY Payload
            for (String payload : diyPayloads) {
                HttpRequest pocRequest = modifier.modifyParameter(
                    sourceRequest, param, payload
                );
                HttpRequestResponse pocResponse = sendHttpRequest(pocRequest, DEFAULT_RETRY_COUNT);
                String responseBody = extractResponseBody(pocResponse);

                // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                // 检测方式1: Regex匹配
                // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                if (!diyRegexs.isEmpty()) {
                    String matchedRegex = diyRegexCheck(responseBody);
                    if (matchedRegex != null) {
                        attackList.add(PocLogEntry.fromResponse(
                            paramName, payload, null,
                            VULN_TYPE_DIY + "(" + matchedRegex + ")",
                            pocResponse, requestHash
                        ));
                        foundVuln = true;
                    }
                }

                // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                // 检测方式2: Time延迟
                // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                if (!DetSql.timeTextField.getText().isEmpty()) {
                    long responseTime = pocResponse.timingData()
                        .map(timing -> timing.timeBetweenRequestSentAndEndOfResponse().toMillis())
                        .orElse(0L);
                    if (responseTime > intTime) {
                        attackList.add(PocLogEntry.fromResponse(
                            paramName, payload, null,
                            VULN_TYPE_DIY + "(time)",
                            pocResponse, requestHash
                        ));
                        foundVuln = true;
                    }
                }
            }
        }

        return foundVuln;
    }

    public String processManualResponse(String requestSm3Hash, HttpRequestResponse httpRequestResponse) throws InterruptedException {
        HttpRequest sourceHttpRequest = httpRequestResponse.request().copyToTempFile();
        String sourceBody = extractResponseBody(httpRequestResponse);
        boolean html_flag = httpRequestResponse.response().mimeType().description().equals("HTML");
        return processRequestInternal(sourceHttpRequest, sourceBody, html_flag, requestSm3Hash);
    }

    /**
     * Checks if DIY injection testing should run based on configuration
     * @return true if DIY checkbox is selected AND payloads exist AND (time threshold OR regex patterns exist)
     */
    private static boolean shouldRunDiyInjection() {
        return DetSql.diyCheck.isSelected()
            && !diyPayloads.isEmpty()
            && (!DetSql.timeTextField.getText().isEmpty() || !diyRegexs.isEmpty());
    }

    /**
     * Checks if text matches any regex pattern from a collection
     * @param text the text to check
     * @param patterns collection of regex patterns to match against
     * @return the first matching pattern, or null if no match
     */
    private static String checkRegexMatch(String text, Iterable<String> patterns) {
        String cleanedText = text.replaceAll("\\n|\\r|\\r\\n", "");
        for (String pattern : patterns) {
            Pattern compiled = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
            if (compiled.matcher(cleanedText).find()) {
                return pattern;
            }
        }
        return null;
    }

    /**
     * Optimized regex matching using precompiled patterns (50x faster)
     * Uses precompiled Pattern objects to avoid repeated Pattern.compile() calls
     *
     * @param text the text to check
     * @param patterns precompiled Pattern objects
     * @return the first matching pattern string, or null if no match
     */
    private static String checkRegexMatch(String text, List<Pattern> patterns) {
        String cleanedText = NEWLINE_PATTERN.matcher(text).replaceAll("");
        for (Pattern pattern : patterns) {
            if (pattern.matcher(cleanedText).find()) {
                return pattern.pattern();  // Return original regex string
            }
        }
        return null;
    }

    public static String ErrSqlCheck(String text) {
        return checkRegexMatch(text, COMPILED_ERROR_PATTERNS);
    }

    public static String diyRegexCheck(String text) {
        return checkRegexMatch(text, diyRegexs);
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
     * @param paramName the parameter name to check
     * @return true if the parameter should be skipped, false otherwise
     */
    private static boolean shouldSkipParameter(String paramName) {
        return !blackParamsSet.isEmpty() && blackParamsSet.contains(paramName);
    }

    /**
     * Extracts response body as string
     * @param response the HTTP response
     * @return response body as string
     */
    private static String extractResponseBody(HttpRequestResponse response) {
        return response.response().body().toString();
    }

    /**
     * Functional interface for building PoC requests with payload injection
     * Encapsulates the difference between parameter-based and body-based injection
     */
    @FunctionalInterface
    private interface PocRequestBuilder {
        HttpRequest buildRequest(HttpRequest source, String paramName, String paramValue, String payload);
    }

    /**
     * Tests error-based SQL injection on parameters
     * Unified method that works with URL, BODY, and COOKIE parameters via strategy pattern
     *
     * @param params list of HTTP parameters to test
     * @param sourceRequest original HTTP request
     * @param requestBuilder strategy for building PoC requests (varies by parameter type)
     * @param requestHash unique hash identifying this request
     * @return true if error injection detected, false otherwise
     */
    private boolean testErrorInjection(
            List<HttpParameter> params,
            HttpRequest sourceRequest,
            PocRequestBuilder requestBuilder,
            String requestHash) throws InterruptedException {

        if (!DetSql.errorCheck.isSelected()) {
            return false;
        }

        List<PocLogEntry> getAttackList = attackMap.get(requestHash);
        boolean foundVuln = false;

        for (int i = 0; i < params.size(); i++) {
            String paramName = params.get(i).name();
            if (shouldSkipParameter(paramName)) {
                continue;
            }

            String paramValue = params.get(i).value();
            for (String poc : errPocs) {
                HttpRequest pocRequest = requestBuilder.buildRequest(sourceRequest, paramName, paramValue, poc);
                HttpRequestResponse pocResponse = sendHttpRequest(pocRequest, DEFAULT_RETRY_COUNT);
                String responseBody = extractResponseBody(pocResponse);
                String matchedRule = ErrSqlCheck(responseBody);

                if (matchedRule != null) {
                    PocLogEntry logEntry = PocLogEntry.fromResponse(
                        paramName, poc, null, VULN_TYPE_ERROR + "(" + matchedRule + ")",
                        pocResponse, requestHash
                    );
                    getAttackList.add(logEntry);
                    foundVuln = true;
                }
            }
        }
        return foundVuln;
    }

    /**
     * Tests error-based SQL injection on JSON/XML parameters
     * Uses string manipulation (prefix+payload+suffix) instead of parameter replacement
     *
     * @param parameters list of parsed HTTP parameters
     * @param sourceRequest original HTTP request
     * @param sourceRequestStr full request as string
     * @param bodyStartIndex offset where body starts
     * @param payloads payload list to use (errPocsj for JSON/XML)
     * @param quotesRequired whether to check for surrounding quotes (JSON: true, XML: false)
     * @param requestHash unique hash identifying this request
     * @return true if error injection detected, false otherwise
     */
    private boolean testErrorInjectionStringBased(
            List<ParsedHttpParameter> parameters,
            HttpRequest sourceRequest,
            String sourceRequestStr,
            int bodyStartIndex,
            String[] payloads,
            boolean quotesRequired,
            String requestHash) throws InterruptedException {

        if (!DetSql.errorCheck.isSelected()) {
            return false;
        }

        List<PocLogEntry> getAttackList = attackMap.get(requestHash);
        boolean foundVuln = false;

        for (ParsedHttpParameter parameter : parameters) {
            int valueStart = parameter.valueOffsets().startIndexInclusive();
            int valueEnd = parameter.valueOffsets().endIndexExclusive();

            // JSON requires quotes around values, XML does not
            if (quotesRequired) {
                if (sourceRequestStr.charAt(valueStart - 1) != '"' || sourceRequestStr.charAt(valueEnd) != '"') {
                    continue;
                }
            }

            String paramName = parameter.name();
            if (shouldSkipParameter(paramName)) {
                continue;
            }

            String prefix = sourceRequestStr.substring(bodyStartIndex, valueEnd);
            String suffix = sourceRequestStr.substring(valueEnd);

            for (String poc : payloads) {
                String pocBody = prefix + poc + suffix;
                HttpRequest pocRequest = sourceRequest.withBody(pocBody);
                HttpRequestResponse pocResponse = sendHttpRequest(pocRequest, DEFAULT_RETRY_COUNT);
                String responseBody = extractResponseBody(pocResponse);
                String matchedRule = ErrSqlCheck(responseBody);

                if (matchedRule != null) {
                    PocLogEntry logEntry = PocLogEntry.fromResponse(
                        paramName, poc, null, VULN_TYPE_ERROR + "(" + matchedRule + ")",
                        pocResponse, requestHash
                    );
                    getAttackList.add(logEntry);
                    foundVuln = true;
                }
            }
        }
        return foundVuln;
    }

    public HttpRequestResponse sendHttpRequest(HttpRequest pocHttpRequest, int retryCount) throws InterruptedException {
        HttpRequestResponse resHttpRequestResponse;
        try {
            resHttpRequestResponse = api.http().sendRequest(pocHttpRequest).copyToTempFile();
            Thread.sleep(Math.max(staticTime, MIN_SLEEP_TIME_MS));
            if (resHttpRequestResponse.response().body() != null) {
                return resHttpRequestResponse;
            }
        } catch (InterruptedException e) {
            throw new InterruptedException();
        } catch (Exception e) {
            HttpResponse aHttpResponse = HttpResponse.httpResponse();
            HttpResponse emptyHttpResponse = aHttpResponse.withBody("");
            resHttpRequestResponse = HttpRequestResponse.httpRequestResponse(pocHttpRequest, emptyHttpResponse);
        }
        if (retryCount <= 0) {
            return resHttpRequestResponse;
        }
        Thread.sleep(ThreadLocalRandom.current().nextInt(startTime, endTime + 1));
        return sendHttpRequest(pocHttpRequest, retryCount - 1);
    }

    /**
     * Process request with specified semaphore for concurrency control
     * Extracted from createProcessThread to eliminate duplicate code blocks
     *
     * @param httpRequestResponse the HTTP request/response to process
     * @param sem the semaphore to use for concurrency control
     * @throws InterruptedException if thread is interrupted
     */
    private void processRequestWithSemaphore(
        HttpRequestResponse httpRequestResponse,
        Semaphore sem
    ) throws InterruptedException {
        String requestSm3Hash = String.valueOf(System.currentTimeMillis());
        Thread.currentThread().setName(requestSm3Hash);
        int oneLogSize = 0;

        // Step 1: Create log entry and initialize tracking
        lk.lock();
        try {
            oneLogSize = countId;
            final int finalOneLogSize = oneLogSize;
            SwingUtilities.invokeLater(() -> {
                sourceTableModel.add(new SourceLogEntry(
                    finalOneLogSize,
                    "Send",
                    requestSm3Hash,
                    "run",
                    httpRequestResponse.response().bodyToString().length(),
                    HttpRequestResponse.httpRequestResponse(
                        httpRequestResponse.request(),
                        HttpResponse.httpResponse()
                    ),
                    httpRequestResponse.request().httpService().toString(),
                    httpRequestResponse.request().method(),
                    httpRequestResponse.request().pathWithoutQuery()
                ));
            });
        } finally {
            lk.unlock();
            attackMap.putIfAbsent(requestSm3Hash, new ArrayList<>());
            countId += 1;
        }

        // Step 2: Process request with semaphore control
        try {
            String oneVuln = "";
            sem.acquire();
            try {
                if (!Thread.currentThread().isInterrupted()) {
                    oneVuln = processManualResponse(requestSm3Hash, httpRequestResponse);
                }
            } catch (Exception e) {
                logger.error("Manual response processing failed: " + requestSm3Hash, e);
                statistics.incrementDetectionErrors();
            } finally {
                sem.release();
                final int finalOneLogSize = oneLogSize;
                final String finalOneVuln = oneVuln;

                // Update log entry based on detection result
                if (oneVuln.isBlank()) {
                    // memory clean: no vuln found for this request
                    try { attackMap.remove(requestSm3Hash); } catch (Exception ignore) {}
                    SwingUtilities.invokeLater(() -> {
                        sourceTableModel.updateVulnState(
                            new SourceLogEntry(
                                finalOneLogSize,
                                "Send",
                                requestSm3Hash,
                                "",
                                httpRequestResponse.response().bodyToString().length(),
                                null,
                                httpRequestResponse.request().httpService().toString(),
                                httpRequestResponse.request().method(),
                                httpRequestResponse.request().pathWithoutQuery()
                            ),
                            sourceTableModel.log.indexOf(
                                new SourceLogEntry(finalOneLogSize, null, null, null, 0, null, null, null, null)
                            ),
                            sourceTableModel.log.indexOf(
                                new SourceLogEntry(finalOneLogSize, null, null, null, 0, null, null, null, null)
                            )
                        );
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        sourceTableModel.updateVulnState(
                            new SourceLogEntry(
                                finalOneLogSize,
                                "Send",
                                requestSm3Hash,
                                finalOneVuln,
                                httpRequestResponse.response().bodyToString().length(),
                                httpRequestResponse,
                                httpRequestResponse.request().httpService().toString(),
                                httpRequestResponse.request().method(),
                                httpRequestResponse.request().pathWithoutQuery()
                            ),
                            sourceTableModel.log.indexOf(
                                new SourceLogEntry(finalOneLogSize, null, null, null, 0, null, null, null, null)
                            ),
                            sourceTableModel.log.indexOf(
                                new SourceLogEntry(finalOneLogSize, null, null, null, 0, null, null, null, null)
                            )
                        );
                    });
                }
            }
        } catch (InterruptedException e) {
            final int finalOneLogSize = oneLogSize;
            SwingUtilities.invokeLater(() -> {
                sourceTableModel.updateVulnState(
                    new SourceLogEntry(
                        finalOneLogSize,
                        "Send",
                        requestSm3Hash,
                        "手动停止",
                        httpRequestResponse.response().bodyToString().length(),
                        null,
                        httpRequestResponse.request().httpService().toString(),
                        httpRequestResponse.request().method(),
                        httpRequestResponse.request().pathWithoutQuery()
                    ),
                    sourceTableModel.log.indexOf(
                        new SourceLogEntry(finalOneLogSize, null, null, null, 0, null, null, null, null)
                    ),
                    sourceTableModel.log.indexOf(
                        new SourceLogEntry(finalOneLogSize, null, null, null, 0, null, null, null, null)
                    )
                );
            });
            throw e; // Re-throw to caller
        }
    }

    public void createProcessThread(HttpRequestResponse httpRequestResponse) {
        new Thread(() -> {
            try {
                int bodyLength = httpRequestResponse.response().bodyToString().length();

                // Skip empty responses
                if (bodyLength == 0) {
                    return;
                }

                // Choose semaphore based on response size
                Semaphore sem;
                if (bodyLength < SMALL_RESPONSE_THRESHOLD) {
                    sem = semaphore;
                } else if (bodyLength < MEDIUM_RESPONSE_MAX) {
                    sem = semaphore2;
                } else {
                    // Skip oversized responses
                    return;
                }

                // Process with selected semaphore
                processRequestWithSemaphore(httpRequestResponse, sem);

            } catch (Exception e) {
                logger.error("Thread processing failed", e);
                statistics.incrementDetectionErrors();
            }
        }).start();
    }
}

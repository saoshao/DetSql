/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import DetSql.config.DetSqlConfig;
import DetSql.logging.DetSqlLogger;
import DetSql.model.PocLogEntry;
import DetSql.util.Statistics;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * 注入策略抽象基类
 * 提供通用的请求发送、响应提取等功能
 */
public abstract class AbstractInjectionStrategy implements InjectionStrategy {
    
    // P0-2 修复：全局共享的超时控制线程池 (所有 Strategy 实例共用)
    // 避免每次重试都创建新线程池,防止线程爆炸问题
    private static final ScheduledExecutorService SHARED_TIMEOUT_EXECUTOR = 
        Executors.newScheduledThreadPool(
            Runtime.getRuntime().availableProcessors(),
            r -> {
                Thread t = new Thread(r, "DetSql-Timeout-Thread");
                t.setDaemon(true);
                return t;
            }
        );
    
    protected final MontoyaApi api;
    protected final DetSqlConfig config;
    protected final DetSqlLogger logger;
    protected final Statistics statistics;
    protected final Map<String, List<PocLogEntry>> attackMap;
    
    private static final int DEFAULT_RETRY_COUNT = 2;
    private static final int MIN_SLEEP_TIME_MS = 100;
    
    public AbstractInjectionStrategy(
        MontoyaApi api,
        DetSqlConfig config,
        DetSqlLogger logger,
        Statistics statistics,
        Map<String, List<PocLogEntry>> attackMap
    ) {
        this.api = api;
        this.config = config;
        this.logger = logger;
        this.statistics = statistics;
        this.attackMap = attackMap;
    }
    
    /**
     * 发送 HTTP 请求（带重试机制和超时控制）
     * P0-2 修复：使用共享线程池 + CompletableFuture,避免线程爆炸问题
     */
    protected HttpRequestResponse sendHttpRequest(HttpRequest pocHttpRequest, int retryCount) throws InterruptedException {
        Exception lastException = null;
        // 超时阈值设为 20 秒
        final int REQUEST_TIMEOUT_SECONDS = 20;

        for (int attempt = 0; attempt < retryCount; attempt++) {
            try {
                // P0-2: 使用共享线程池 + supplyAsync + orTimeout
                // 替代原来每次重试都创建新线程池的方式
                CompletableFuture<HttpRequestResponse> future = 
                    CompletableFuture.supplyAsync(
                        () -> api.http().sendRequest(pocHttpRequest),
                        SHARED_TIMEOUT_EXECUTOR
                    ).orTimeout(REQUEST_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                
                // 等待响应
                HttpRequestResponse resHttpRequestResponse = future.get();
                Thread.sleep(Math.max(config.getStaticTimeMs(), MIN_SLEEP_TIME_MS));

                if (resHttpRequestResponse.response().body() != null) {
                    return resHttpRequestResponse;
                }

                if (attempt < retryCount - 1) {
                    logger.debug("响应体为空,重试中... (尝试 " + (attempt + 1) + "/" + retryCount + ")");
                    Thread.sleep(ThreadLocalRandom.current().nextInt(config.getStartTimeMs(), config.getEndTimeMs() + 1));
                }

            } catch (ExecutionException e) {
                // ExecutionException 包装了实际异常
                Throwable cause = e.getCause();
                
                // 检查是否为超时异常
                if (cause instanceof TimeoutException) {
                    lastException = (TimeoutException) cause;
                    logger.debug("请求超时(" + REQUEST_TIMEOUT_SECONDS + "秒),重试中... (尝试 " + (attempt + 1) + "/" + retryCount + ")");
                } else {
                    // 其他执行异常
                    lastException = cause != null ? (Exception) cause : e;
                    logger.debug("请求失败,重试中... (尝试 " + (attempt + 1) + "/" + retryCount + "): " + lastException.getMessage());
                }
                
                if (attempt < retryCount - 1) {
                    Thread.sleep(ThreadLocalRandom.current().nextInt(config.getStartTimeMs(), config.getEndTimeMs() + 1));
                }
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedException();
            }
        }

        // 所有重试都失败,返回空响应
        HttpResponse emptyHttpResponse = HttpResponse.httpResponse().withBody("");
        HttpRequestResponse defaultResponse = HttpRequestResponse.httpRequestResponse(pocHttpRequest, emptyHttpResponse);

        if (lastException != null) {
            logger.debug("所有重试尝试失败,共 " + retryCount + " 次: " + lastException.getMessage());
        }

        return defaultResponse;
    }
    
    /**
     * 提取响应体
     */
    protected String extractResponseBody(HttpRequestResponse response) {
        return response.response().body().toString();
    }
    
    /**
     * 检查参数是否应该被跳过（黑名单检查）
     */
    @Override
    public boolean shouldSkipParameter(String paramName) {
        return !config.getBlackListParams().isEmpty() && config.getBlackListParams().contains(paramName);
    }
    
    /**
     * 获取攻击列表
     */
    protected List<PocLogEntry> getAttackList(String requestHash) {
        return attackMap.get(requestHash);
    }
    
    /**
     * 添加 PoC 日志条目
     */
    protected void addPocEntry(String requestHash, PocLogEntry entry) {
        List<PocLogEntry> attackList = getAttackList(requestHash);
        if (attackList != null) {
            attackList.add(entry);
        }
    }
    
    /**
     * 检查线程是否被中断
     */
    protected void checkInterrupted() throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("检测被中断");
        }
    }
}

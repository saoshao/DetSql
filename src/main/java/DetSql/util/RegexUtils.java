package DetSql.util;

import java.util.concurrent.*;
import java.util.regex.*;

/**
 * 安全的正则表达式工具类，防止ReDoS攻击
 * 使用Future超时机制限制正则匹配时间
 *
 * @author DetSql Security Team
 * @since v3.3.1
 */
public class RegexUtils {
    private static final int THREAD_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    private static volatile ExecutorService REGEX_EXECUTOR = createExecutor();

    // 默认超时1000ms，降低在CI负载下的不必要超时，同时仍提供ReDoS防护
    private static final long DEFAULT_TIMEOUT_MS = 1000;

    /**
     * 创建正则匹配线程池
     */
    private static ExecutorService createExecutor() {
        return Executors.newCachedThreadPool(new ThreadFactory() {
            private int counter = 0;
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "DetSql-Regex-" + counter++);
                t.setDaemon(true);
                return t;
            }
        });
    }

    /**
     * 获取或重建线程池（如果已终止）
     */
    private static ExecutorService getOrCreateExecutor() {
        ExecutorService executor = REGEX_EXECUTOR;
        if (executor.isShutdown() || executor.isTerminated()) {
            synchronized (RegexUtils.class) {
                executor = REGEX_EXECUTOR;
                if (executor.isShutdown() || executor.isTerminated()) {
                    REGEX_EXECUTOR = createExecutor();
                    executor = REGEX_EXECUTOR;
                }
            }
        }
        return executor;
    }

    /**
     * 安全的正则匹配，带超时保护
     * @param pattern 正则表达式模式
     * @param text 待匹配的文本
     * @param timeoutMs 超时时间（毫秒）
     * @return 是否匹配成功
     */
    public static boolean safeMatch(String pattern, String text, long timeoutMs) {
        if (pattern == null || text == null) {
            return false;
        }

        Future<Boolean> future = getOrCreateExecutor().submit(() -> {
            try {
                Pattern p = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
                return p.matcher(text).find();
            } catch (PatternSyntaxException e) {
                return false;
            }
        });

        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            // 记录超时的正则，可能是ReDoS
            logRegexTimeout(pattern, text.length());
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 使用默认超时的安全匹配
     * @param pattern 正则表达式模式
     * @param text 待匹配的文本
     * @return 是否匹配成功
     */
    public static boolean safeMatch(String pattern, String text) {
        return safeMatch(pattern, text, DEFAULT_TIMEOUT_MS);
    }

    /**
     * 预编译的Pattern安全匹配
     * @param pattern 预编译的Pattern对象
     * @param text 待匹配的文本
     * @param timeoutMs 超时时间（毫秒）
     * @return 是否匹配成功
     */
    public static boolean safeMatchPrecompiled(Pattern pattern, String text, long timeoutMs) {
        if (pattern == null || text == null) {
            return false;
        }

        Future<Boolean> future = getOrCreateExecutor().submit(() ->
            pattern.matcher(text).find()
        );

        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            logRegexTimeout(pattern.pattern(), text.length());
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 使用默认超时的预编译Pattern匹配
     * @param pattern 预编译的Pattern对象
     * @param text 待匹配的文本
     * @return 是否匹配成功
     */
    public static boolean safeMatchPrecompiled(Pattern pattern, String text) {
        return safeMatchPrecompiled(pattern, text, DEFAULT_TIMEOUT_MS);
    }

    /**
     * 记录正则超时日志
     * @param pattern 超时的正则表达式
     * @param textLength 文本长度
     */
    private static void logRegexTimeout(String pattern, int textLength) {
        // 记录可能的ReDoS模式
        System.err.println("[RegexUtils] Regex timeout detected (possible ReDoS) - Pattern: " +
            (pattern.length() > 50 ? pattern.substring(0, 50) + "..." : pattern) +
            ", Text length: " + textLength);
    }

    /**
     * 关闭线程池
     */
    public static void shutdown() {
        REGEX_EXECUTOR.shutdown();
        try {
            if (!REGEX_EXECUTOR.awaitTermination(5, TimeUnit.SECONDS)) {
                REGEX_EXECUTOR.shutdownNow();
            }
        } catch (InterruptedException e) {
            REGEX_EXECUTOR.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
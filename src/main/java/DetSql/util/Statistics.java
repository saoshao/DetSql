/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.util;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import DetSql.model.PocLogEntry;


/**
 * Thread-safe statistics tracker for DetSql
 * Tracks detection progress and resource usage

 * Usage:
 *   Statistics stats = new Statistics();
 *   stats.incrementRequestsProcessed();
 *   stats.incrementVulnerabilitiesFound();
 *   String summary = stats.getSummary();
 */
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class Statistics {
    /**
     * 漏洞参数的唯一标识
     * 使用 Record 避免字符串拼接，提高性能和类型安全
     */
    public record VulnerabilityKey(
        String method,
        String host,
        int port,
        String path,
        String paramName
    ) {
        /**
         * 紧凑构造函数：验证参数
         */
        public VulnerabilityKey {
            if (method == null || method.isBlank()) {
                method = "GET"; // 默认方法
            } else {
                method = method.toUpperCase();
            }
            if (host == null || host.isBlank()) {
                throw new IllegalArgumentException("Host 不能为空");
            }
            if (path == null) {
                path = "/";
            }
            if (paramName == null || paramName.isBlank()) {
                throw new IllegalArgumentException("参数名不能为空");
            }
        }
        
        @Override
        public String toString() {
            return method + "|" + host + ":" + port + path + "|" + paramName;
        }
    }
    // Request counters (thread-safe)
    private final AtomicInteger requestsProcessed = new AtomicInteger(0);
    private final AtomicInteger requestsFiltered = new AtomicInteger(0);
    private final AtomicInteger detectionErrors = new AtomicInteger(0);
    private final AtomicInteger strategyTimeouts = new AtomicInteger(0);

    // Unique vulnerable combinations: VulnerabilityKey
    private final Set<VulnerabilityKey> vulnerableParams = ConcurrentHashMap.newKeySet();

    // Timing
    private final long startTime = System.currentTimeMillis();
    private final AtomicLong totalTestTime = new AtomicLong(0);

    /**
     * Increments the count of processed requests
     */
    public void incrementRequestsProcessed() {
        requestsProcessed.incrementAndGet();
    }

    /**
     * 记录漏洞参数
     * @param method HTTP 方法
     * @param host 主机名
     * @param port 端口
     * @param path 路径
     * @param paramName 参数名
     */
    public void recordVulnerableParam(String method, String host, int port, String path, String paramName) {
        try {
            VulnerabilityKey key = new VulnerabilityKey(method, host, port, path, paramName);
            vulnerableParams.add(key);
        } catch (IllegalArgumentException e) {
            // 忽略无效参数，不中断流程
        }
    }

    /**
     * Increments the count of filtered requests (not tested)
     */
    public void incrementRequestsFiltered() {
        requestsFiltered.incrementAndGet();
    }

    /**
     * Increments the count of detection errors
     */
    public void incrementDetectionErrors() {
        detectionErrors.incrementAndGet();
    }

    /**
     * Increments the count of strategy timeouts
     */
    public void incrementStrategyTimeouts() {
        strategyTimeouts.incrementAndGet();
    }

    /**
     * Records the time taken for a test
     * @param milliseconds time in milliseconds
     */
    public void recordTestTime(long milliseconds) {
        totalTestTime.addAndGet(milliseconds);
    }

    /**
     * Gets the count of processed requests
     * @return number of requests processed
     */
    public int getRequestsProcessed() {
        return requestsProcessed.get();
    }

    /**
     * 获取漏洞参数数量
     * @return 唯一漏洞参数的数量
     */
    public int getVulnerabilitiesFound() {
        return vulnerableParams.size();
    }
    
    /**
     * 获取所有漏洞参数（用于导出）
     * @return 漏洞参数集合的副本
     */
    public Set<VulnerabilityKey> getVulnerableParams() {
        return new java.util.HashSet<>(vulnerableParams);
    }

    /**
     * 从 URL 和 POC 条目中聚合并记录唯一的漏洞参数组合
     * 将 URL 解析和去重集中到统计层
     * @param url 请求 URL
     * @param method HTTP 方法
     * @param entries POC 日志条目列表
     */
    public void recordFromEntries(String url, String method, java.util.List<PocLogEntry> entries) {
        if (url == null || entries == null || entries.isEmpty()) {
            return;
        }
        
        String host = "";
        int port = -1;
        String path = "";
        
        try {
            java.net.URI u = java.net.URI.create(url);
            host = u.getHost();
            if (host == null) host = "";
            port = u.getPort();
            String scheme = u.getScheme();
            if (port == -1) {
                if ("http".equalsIgnoreCase(scheme)) port = 80;
                else if ("https".equalsIgnoreCase(scheme)) port = 443;
            }
            path = u.getPath();
            if (path == null) path = "/";
        } catch (Exception ignore) {
            // URL 解析失败，使用默认值
            if (host.isEmpty()) host = "unknown";
            if (port == -1) port = 80;
            if (path.isEmpty()) path = url;
        }
        
        // 提取唯一的参数名
        java.util.Set<String> uniqueParams = new java.util.HashSet<>();
        for (PocLogEntry e : entries) {
            if (e == null) continue;
            String pname = e.getName();
            if (pname != null && !pname.isEmpty()) {
                uniqueParams.add(pname);
            }
        }
        
        // 记录每个参数
        String finalMethod = (method == null || method.isEmpty()) ? "GET" : method;
        for (String pname : uniqueParams) {
            recordVulnerableParam(finalMethod, host, port, path, pname);
        }
    }

    /**
     * Gets the count of filtered requests
     * @return number of requests filtered
     */
    public int getRequestsFiltered() {
        return requestsFiltered.get();
    }

    /**
     * Gets the count of detection errors
     * @return number of detection errors
     */
    public int getDetectionErrors() {
        return detectionErrors.get();
    }

    /**
     * Gets the count of strategy timeouts
     * @return number of strategy timeouts
     */
    public int getStrategyTimeouts() {
        return strategyTimeouts.get();
    }

    /**
     * Gets the uptime in milliseconds
     * @return milliseconds since statistics started
     */
    public long getUptimeMillis() {
        return System.currentTimeMillis() - startTime;
    }

    /**
     * Gets the average test time per request
     * @return average milliseconds per test, or 0 if no tests
     */
    public long getAverageTestTime() {
        int processed = requestsProcessed.get();
        if (processed == 0) {
            return 0;
        }
        return totalTestTime.get() / processed;
    }

    /**
     * Gets current memory usage in MB
     * @return memory used in megabytes
     */
    public long getMemoryUsedMB() {
        Runtime runtime = Runtime.getRuntime();
        long usedMemory = runtime.totalMemory() - runtime.freeMemory();
        return usedMemory / (1024 * 1024);
    }

    /**
     * Gets maximum available memory in MB
     * @return maximum memory in megabytes
     */
    public long getMaxMemoryMB() {
        return Runtime.getRuntime().maxMemory() / (1024 * 1024);
    }

    /**
     * Gets a formatted summary of all statistics
     * @return multi-line summary string
     */
    public String getSummary() {
        long uptimeSeconds = getUptimeMillis() / 1000;
        long hours = uptimeSeconds / 3600;
        long minutes = (uptimeSeconds % 3600) / 60;
        long seconds = uptimeSeconds % 60;

        return String.format(
            "═══════════════════════════════════════════════════\n" +
            "DetSql Statistics\n" +
            "═══════════════════════════════════════════════════\n" +
            "Requests Processed:    %d\n" +
            "Vulnerabilities Found: %d\n" +
            "Requests Filtered:     %d\n" +
            "Detection Errors:      %d\n" +
            "Strategy Timeouts:     %d\n" +
            "Average Test Time:     %d ms\n" +
            "Memory Used:           %d MB / %d MB\n" +
            "Uptime:                %02d:%02d:%02d\n" +
            "═══════════════════════════════════════════════════",
            getRequestsProcessed(),
            getVulnerabilitiesFound(),
            getRequestsFiltered(),
            getDetectionErrors(),
            getStrategyTimeouts(),
            getAverageTestTime(),
            getMemoryUsedMB(),
            getMaxMemoryMB(),
            hours, minutes, seconds
        );
    }

    /**
     * Gets a compact one-line summary
     * @return compact summary string
     */
    public String getCompactSummary() {
        return String.format(
            "Tested: %d | Vulns: %d | Filtered: %d | Errors: %d | Mem: %dMB",
            getRequestsProcessed(),
            getVulnerabilitiesFound(),
            getRequestsFiltered(),
            getDetectionErrors(),
            getMemoryUsedMB()
        );
    }

    /**
     * 重置所有统计信息
     * 用于开始新的测试会话
     */
    public void reset() {
        requestsProcessed.set(0);
        requestsFiltered.set(0);
        detectionErrors.set(0);
        strategyTimeouts.set(0);
        totalTestTime.set(0);
        vulnerableParams.clear();
    }
}

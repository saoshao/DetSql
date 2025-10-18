/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe statistics tracker for DetSql
 * Tracks detection progress and resource usage
 *
 * Usage:
 *   Statistics stats = new Statistics();
 *   stats.incrementRequestsProcessed();
 *   stats.incrementVulnerabilitiesFound();
 *   String summary = stats.getSummary();
 */
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class Statistics {
    // Request counters (thread-safe)
    private final AtomicInteger requestsProcessed = new AtomicInteger(0);
    private final AtomicInteger requestsFiltered = new AtomicInteger(0);
    private final AtomicInteger detectionErrors = new AtomicInteger(0);

    // Unique vulnerable combinations: path|paramName
    private final Set<String> uniqueVulnCombos = ConcurrentHashMap.newKeySet();

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
     * Records a vulnerable finding for a specific URL path and parameter name.
     * Counting is based on unique (path + parameter) combinations across the session.
     * @param urlPath request URL path (e.g., /api/items)
     * @param paramName vulnerable parameter name
     */
    public void recordVulnerableParam(String urlPath, String paramName) {
        if (urlPath == null) urlPath = "";
        if (paramName == null) paramName = "";
        uniqueVulnCombos.add(urlPath + "|" + paramName);
    }

    /**
     * Records a vulnerable finding for a specific host/port/path and parameter name.
     * Key format: host:port + path + | + paramName
     */
    public void recordVulnerableParam(String host, int port, String path, String paramName) {
        if (host == null) host = "";
        if (path == null) path = "";
        if (paramName == null) paramName = "";
        String key = host.toLowerCase() + ":" + port + path + "|" + paramName;
        uniqueVulnCombos.add(key);
    }

    /**
     * Records a vulnerable finding for a specific method/host/port/path and parameter name.
     * Key format: METHOD|host:port + path + | + paramName
     */
    public void recordVulnerableParam(String method, String host, int port, String path, String paramName) {
        if (method == null) method = "";
        if (host == null) host = "";
        if (path == null) path = "";
        if (paramName == null) paramName = "";
        String key = method.toUpperCase() + "|" + host.toLowerCase() + ":" + port + path + "|" + paramName;
        uniqueVulnCombos.add(key);
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
     * Gets the count of unique (URL path + parameter) vulnerabilities found
     * @return number of unique vulnerable param combos
     */
    public int getVulnerabilitiesFound() {
        return uniqueVulnCombos.size();
    }

    /**
     * Aggregate and record unique vulnerable param combos from a URL and Poc entries.
     * This centralizes URL parsing and de-duplication to the statistics layer.
     *
     * Uniqueness key format: METHOD|host:port + path + | + paramName
     */
    public void recordFromEntries(String url, String method, java.util.List<PocLogEntry> entries) {
        if (url == null || method == null || entries == null || entries.isEmpty()) return;
        String host = "";
        int port = -1;
        String path = "";
        try {
            java.net.URI u = java.net.URI.create(url);
            host = u.getHost();
            port = u.getPort();
            String scheme = u.getScheme();
            if (port == -1) {
                if ("http".equalsIgnoreCase(scheme)) port = 80;
                else if ("https".equalsIgnoreCase(scheme)) port = 443;
            }
            path = u.getPath();
        } catch (Exception ignore) {
            path = url; // fallback to full URL as path if parsing fails
        }
        java.util.Set<String> uniqueParams = new java.util.HashSet<>();
        for (PocLogEntry e : entries) {
            if (e == null) continue;
            String pname = e.getName();
            if (pname != null && !pname.isEmpty()) uniqueParams.add(pname);
        }
        for (String pname : uniqueParams) {
            recordVulnerableParam(method, host, port, path, pname);
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
            "Average Test Time:     %d ms\n" +
            "Memory Used:           %d MB / %d MB\n" +
            "Uptime:                %02d:%02d:%02d\n" +
            "═══════════════════════════════════════════════════",
            getRequestsProcessed(),
            getVulnerabilitiesFound(),
            getRequestsFiltered(),
            getDetectionErrors(),
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
     * Resets all statistics to zero
     * Useful for starting a new testing session
     */
    public void reset() {
        requestsProcessed.set(0);
        requestsFiltered.set(0);
        detectionErrors.set(0);
        totalTestTime.set(0);
        uniqueVulnCombos.clear();
    }
}

/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe wrapper for attack detection results
 * Replaces HashMap with ConcurrentHashMap to prevent race conditions
 */
public class ThreadSafeAttackMap {
    private final ConcurrentHashMap<String, List<PocLogEntry>> attackMap;

    public ThreadSafeAttackMap() {
        this.attackMap = new ConcurrentHashMap<>();
    }

    /**
     * Initialize a new entry for a request
     * @param requestHash unique request identifier
     */
    public void initializeRequest(String requestHash) {
        attackMap.putIfAbsent(requestHash, new ArrayList<>());
    }

    /**
     * Get attack list for a request (thread-safe)
     * @param requestHash unique request identifier
     * @return list of detected attacks
     */
    public List<PocLogEntry> get(String requestHash) {
        return attackMap.computeIfAbsent(requestHash, k -> new ArrayList<>());
    }

    /**
     * Add a single attack entry
     * @param requestHash unique request identifier
     * @param entry attack log entry
     */
    public void addEntry(String requestHash, PocLogEntry entry) {
        get(requestHash).add(entry);
    }

    /**
     * Add multiple attack entries
     * @param requestHash unique request identifier
     * @param entries list of attack log entries
     */
    public void addEntries(String requestHash, List<PocLogEntry> entries) {
        get(requestHash).addAll(entries);
    }

    /**
     * Check if request has any detected attacks
     * @param requestHash unique request identifier
     * @return true if attacks detected
     */
    public boolean hasAttacks(String requestHash) {
        List<PocLogEntry> entries = attackMap.get(requestHash);
        return entries != null && !entries.isEmpty();
    }

    /**
     * Get number of attacks for a request
     * @param requestHash unique request identifier
     * @return number of detected attacks
     */
    public int getAttackCount(String requestHash) {
        List<PocLogEntry> entries = attackMap.get(requestHash);
        return entries != null ? entries.size() : 0;
    }

    /**
     * Remove all entries for a request
     * @param requestHash unique request identifier
     */
    public void remove(String requestHash) {
        attackMap.remove(requestHash);
    }

    /**
     * Clear all entries
     */
    public void clear() {
        attackMap.clear();
    }

    /**
     * Get total number of requests tracked
     * @return number of requests
     */
    public int size() {
        return attackMap.size();
    }
}

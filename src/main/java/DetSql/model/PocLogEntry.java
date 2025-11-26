/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import DetSql.util.ResponseExtractor;
import java.lang.ref.WeakReference;

public class PocLogEntry {
    // Convenience constructor for tests/backward compatibility
    public PocLogEntry(String name, String poc, String similarity) {
        this(name, poc, similarity, "UNKNOWN", "0", "200", "0", "", "", "", System.currentTimeMillis(), "");
    }
    
    private String name;
    private String poc;
    private String similarity;
    private String vulnState;
    private String bodyLength;
    private String statusCode;
    private String time;
    
    // 内存优化：使用 WeakReference 允许 GC 在内存不足时回收完整响应
    // 同时保留元数据用于降级显示
    private WeakReference<HttpRequestResponse> responseRef;

    // 强引用：发现漏洞时升级，锁定证据防止 GC 回收
    private HttpRequestResponse strongResponseRef;

    // 轻量级元数据（永久保留,用于降级显示）
    private String url;
    private String method;
    private String responsePreview; // 只保留前 500 字符
    private long timestamp;

    private String myHash;

    /**
     * 主构造函数（保持向后兼容）
     * @deprecated 使用 fromResponse() 工厂方法代替
     */
    @Deprecated
    public PocLogEntry(String name, String poc, String similarity, String vulnState, String bodyLength, 
                      String statusCode, String time, HttpRequestResponse httpRequestResponse, String myHash) {
        this.name = name;
        this.poc = poc;
        this.similarity = similarity;
        this.vulnState = vulnState;
        this.bodyLength = bodyLength;
        this.statusCode = statusCode;
        this.time = time;
        this.myHash = myHash;
        
        // 从 HttpRequestResponse 提取元数据（如果提供）
        if (httpRequestResponse != null) {
            this.responseRef = new WeakReference<>(httpRequestResponse);
            this.url = httpRequestResponse.request().url();
            this.method = httpRequestResponse.request().method();
            String body = httpRequestResponse.response().bodyToString();
            this.responsePreview = body.length() > 500 ? body.substring(0, 500) + "..." : body;
            this.timestamp = System.currentTimeMillis();
        } else {
            this.responseRef = null;
            this.url = "";
            this.method = "";
            this.responsePreview = "";
            this.timestamp = System.currentTimeMillis();
        }
    }
    
    /**
     * 轻量级构造函数（只存储元数据）
     */
    public PocLogEntry(String name, String poc, String similarity, String vulnState, String bodyLength,
                      String statusCode, String time, String url, String method, String responsePreview,
                      long timestamp, String myHash) {
        this.name = name;
        this.poc = poc;
        this.similarity = similarity;
        this.vulnState = vulnState;
        this.bodyLength = bodyLength;
        this.statusCode = statusCode;
        this.time = time;
        this.url = url;
        this.method = method;
        this.responsePreview = responsePreview;
        this.timestamp = timestamp;
        this.myHash = myHash;
        this.responseRef = null; // 轻量级构造函数不存储完整响应
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPoc() {
        return poc;
    }

    public void setPoc(String poc) {
        this.poc = poc;
    }

    public String getSimilarity() {
        return similarity;
    }

    public void setSimilarity(String similarity) {
        this.similarity = similarity;
    }

    public String getVulnState() {
        return vulnState;
    }

    public void setVulnState(String vulnState) {
        this.vulnState = vulnState;
    }

    public String getBodyLength() {
        return bodyLength;
    }

    public void setBodyLength(String bodyLength) {
        this.bodyLength = bodyLength;
    }

    public String getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(String statusCode) {
        this.statusCode = statusCode;
    }

    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }

    /**
     * 获取完整的 HttpRequestResponse 对象（智能回退）
     * 1. 优先返回强引用（漏洞证据）
     * 2. 尝试从 WeakReference 获取
     * 3. 如果已被 GC 回收，返回 null（UI 需要优雅处理）
     *
     * @return HttpRequestResponse 对象，如果已被 GC 回收则返回 null
     */
    public HttpRequestResponse getHttpRequestResponse() {
        // 1. 优先返回强引用
        if (strongResponseRef != null) {
            return strongResponseRef;
        }
        // 2. 尝试从 WeakReference 获取
        if (responseRef != null) {
            HttpRequestResponse cached = responseRef.get();
            if (cached != null) {
                return cached; // ✅ WeakReference 命中
            }
        }
        // 3. GC 已回收或从未存储，返回 null
        return null;
    }

    /**
     * 内存优化：将 WeakReference 升级为强引用
     * 用于发现漏洞时锁定证据，防止 GC 回收
     */
    public void keepResponse() {
        if (strongResponseRef == null && responseRef != null) {
            HttpRequestResponse response = responseRef.get();
            if (response != null) {
                strongResponseRef = response; // 升级为强引用
                responseRef = null; // 清空 WeakReference，避免重复引用
            }
        }
    }

    /**
     * 检查响应是否已被强引用保护
     */
    public boolean isResponseKept() {
        return strongResponseRef != null;
    }

    /**
     * @deprecated 不再直接使用此方法设置响应对象
     * 推荐使用 fromResponse() 工厂方法创建新实例
     */
    @Deprecated
    public void setHttpRequestResponse(HttpRequestResponse httpRequestResponse) {
        // 更新 WeakReference 和元数据
        if (httpRequestResponse != null) {
            this.responseRef = new WeakReference<>(httpRequestResponse);
            this.url = httpRequestResponse.request().url();
            this.method = httpRequestResponse.request().method();
            String body = httpRequestResponse.response().bodyToString();
            this.responsePreview = body.length() > 500 ? body.substring(0, 500) + "..." : body;
            this.timestamp = System.currentTimeMillis();
        }
    }
    
    // 新增 getter 方法用于访问元数据
    public String getUrl() {
        return url;
    }
    
    public String getMethod() {
        return method;
    }
    
    public String getResponsePreview() {
        return responsePreview;
    }
    
    public long getTimestamp() {
        return timestamp;
    }

    public String getMyHash() {
        return myHash;
    }
    public void setMyHash(String myHash) {
        this.myHash = myHash;
    }

    /**
     * Factory method to create PocLogEntry from response
     *
     * **重要：漏洞证据使用强引用保护**
     * - 此方法仅在发现漏洞时调用，因此直接使用强引用保存完整响应
     * - 不使用 WeakReference，避免 GC 回收导致证据丢失
     * - 同时提取元数据用于 UI 显示
     *
     * @param paramName 参数名
     * @param payload 注入 Payload
     * @param similarity 相似度
     * @param injectionType 注入类型
     * @param response 完整的 HTTP 响应对象
     * @param requestHash 请求哈希值
     * @return PocLogEntry 实例
     */
    public static PocLogEntry fromResponse(
        String paramName,
        String payload,
        String similarity,
        String injectionType,
        HttpRequestResponse response,
        String requestHash) {

        // 创建实例
        PocLogEntry entry = new PocLogEntry(
            paramName,
            payload,
            similarity,
            injectionType,
            ResponseExtractor.getBodyLengthString(response),
            ResponseExtractor.getStatusCodeString(response),
            ResponseExtractor.getResponseTimeSeconds(response),
            response.request().url(),
            response.request().method(),
            extractResponsePreview(response),
            System.currentTimeMillis(),
            requestHash
        );

        // ✅ 修复 Bug 2: 直接使用强引用保存漏洞证据
        // 此方法仅在发现漏洞时调用，必须保留完整响应用于证据展示
        // 不使用 WeakReference，避免 GC 导致数据丢失
        entry.strongResponseRef = response;

        return entry;
    }

    /**
     * 提取响应预览（前 500 字符）
     */
    private static String extractResponsePreview(HttpRequestResponse response) {
        String body = response.response().bodyToString();
        return body.length() > 500 ? body.substring(0, 500) + "..." : body;
    }
}
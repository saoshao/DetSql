/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

public class SourceLogEntry {
    private int id;
    private String tool;
    private String myHash;
    private String vulnState;
    private int bodyLength;
    private HttpRequestResponse httpRequestResponse;
    // 内存优化：无漏洞时保留 Request 用于复现，丢弃 Response 释放内存
    private HttpRequest requestOnly;
    private boolean responseDiscarded = false;

    private String httpService;
    private String method;
    private String path;


    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getTool() {
        return tool;
    }

    public void setTool(String tool) {
        this.tool = tool;
    }

    public String getMyHash() {
        return myHash;
    }

    public void setMyHash(String myHash) {
        this.myHash = myHash;
    }

    public String getVulnState() {
        return vulnState;
    }

    public void setVulnState(String vulnState) {
        this.vulnState = vulnState;
    }

    public int getBodyLength() {
        return bodyLength;
    }

    public void setBodyLength(int bodyLength) {
        this.bodyLength = bodyLength;
    }

    public HttpRequestResponse getHttpRequestResponse() {
        if (responseDiscarded && requestOnly != null) {
            // Response 已丢弃，返回 null（UI 需要优雅处理）
            return null;
        }
        return httpRequestResponse;
    }

    public void setHttpRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.httpRequestResponse = httpRequestResponse;
        this.responseDiscarded = false;
        this.requestOnly = null;
    }

    /**
     * 内存优化：释放 Response，仅保留 Request
     * 用于无漏洞的请求，节省内存同时保留复现能力
     */
    public void discardResponse() {
        if (httpRequestResponse != null && !responseDiscarded) {
            requestOnly = httpRequestResponse.request();
            httpRequestResponse = null; // 释放完整响应，允许 GC 回收
            responseDiscarded = true;
        }
    }

    /**
     * 获取 Request（即使 Response 已丢弃也可用）
     */
    public HttpRequest getRequest() {
        if (responseDiscarded && requestOnly != null) {
            return requestOnly;
        }
        return httpRequestResponse != null ? httpRequestResponse.request() : null;
    }

    /**
     * 检查 Response 是否已被丢弃
     */
    public boolean isResponseDiscarded() {
        return responseDiscarded;
    }
    public String getHttpService() {
        return httpService;
    }

    public void setHttpService(String httpService) {
        this.httpService = httpService;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public SourceLogEntry(int id, String tool, String myHash, String vulnState, int bodyLength, HttpRequestResponse httpRequestResponse, String httpService, String method, String path) {
        this.id = id;
        this.tool = tool;
        this.myHash = myHash;
        this.vulnState = vulnState;
        this.bodyLength = bodyLength;
        this.httpRequestResponse = httpRequestResponse;
        this.httpService = httpService;
        this.method = method;
        this.path = path;
    }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SourceLogEntry comSource = (SourceLogEntry) o;
        return id == comSource.id;
    }

    @Override
    public int hashCode() {
        return Integer.hashCode(id);
    }
}
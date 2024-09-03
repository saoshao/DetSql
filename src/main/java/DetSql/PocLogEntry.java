package DetSql;

import burp.api.montoya.http.message.HttpRequestResponse;

public class PocLogEntry {
    private String name;
    private String poc;
    private String similarity;
    private String vulnState;
    private String bodyLength;
    private String statusCode;
    private String time;
    private HttpRequestResponse httpRequestResponse;
    private String myHash;

    public PocLogEntry(String name, String poc, String similarity, String vulnState, String bodyLength, String statusCode, String time, HttpRequestResponse httpRequestResponse, String myHash) {
        this.name = name;
        this.poc = poc;
        this.similarity = similarity;
        this.vulnState = vulnState;
        this.bodyLength = bodyLength;
        this.statusCode = statusCode;
        this.time = time;
        this.httpRequestResponse = httpRequestResponse;
        this.myHash = myHash;
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

    public HttpRequestResponse getHttpRequestResponse() {
        return httpRequestResponse;
    }

    public void setHttpRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.httpRequestResponse = httpRequestResponse;
    }

    public String getMyHash() {
        return myHash;
    }

    public void setMyHash(String myHash) {
        this.myHash = myHash;
    }
}

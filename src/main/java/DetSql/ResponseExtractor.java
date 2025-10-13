/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Utility class for extracting data from HTTP responses
 * Eliminates repeated response data access patterns throughout the codebase
 */
public class ResponseExtractor {

    /**
     * Extracts response body as string
     * @param httpRequestResponse the HTTP request/response pair
     * @return response body string
     */
    public static String getBodyString(HttpRequestResponse httpRequestResponse) {
        return httpRequestResponse.response() != null ? httpRequestResponse.response().bodyToString() : "";
    }

    /**
     * Extracts response body length
     * @param httpRequestResponse the HTTP request/response pair
     * @return response body length in bytes
     */
    public static int getBodyLength(HttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse.response() == null || httpRequestResponse.response().body() == null) {
            return 0;
        }
        return httpRequestResponse.response().body().length();
    }

    /**
     * Extracts HTTP status code
     * @param httpRequestResponse the HTTP request/response pair
     * @return HTTP status code (e.g., 200, 404, 500), or 0 if response is null
     */
    public static int getStatusCode(HttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse.response() == null) {
            return 0;
        }
        return httpRequestResponse.response().statusCode();
    }

    /**
     * Extracts response time in milliseconds
     * @param httpRequestResponse the HTTP request/response pair
     * @return response time in milliseconds
     */
    public static long getResponseTimeMillis(HttpRequestResponse httpRequestResponse) {
        var tdOpt = httpRequestResponse.timingData();
        if (tdOpt == null || tdOpt.isEmpty()) {
            return 0L;
        }
        return tdOpt.get().timeBetweenRequestSentAndEndOfResponse().toMillis();
    }

    /**
     * Extracts response time in seconds (formatted as string with 3 decimal places)
     * @param httpRequestResponse the HTTP request/response pair
     * @return response time in seconds (e.g., "1.234")
     */
    public static String getResponseTimeSeconds(HttpRequestResponse httpRequestResponse) {
        return String.format("%.3f", getResponseTimeMillis(httpRequestResponse) / 1000.0);
    }

    /**
     * Extracts response body length as string
     * @param httpRequestResponse the HTTP request/response pair
     * @return response body length as string
     */
    public static String getBodyLengthString(HttpRequestResponse httpRequestResponse) {
        return String.valueOf(getBodyLength(httpRequestResponse));
    }

    /**
     * Extracts status code as string
     * @param httpRequestResponse the HTTP request/response pair
     * @return status code as string
     */
    public static String getStatusCodeString(HttpRequestResponse httpRequestResponse) {
        return String.valueOf(getStatusCode(httpRequestResponse));
    }
}

/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class MyFilterRequest {
    // HTTP Method Constants
    private static final String METHOD_GET = "GET";
    private static final String METHOD_POST = "POST";
    private static final String METHOD_PUT = "PUT";

    public static Set<String> whiteListSet = new HashSet<>();

    public static Set<String> blackListSet = new HashSet<>();
    public static Set<String> blackPathSet=new HashSet<>();

    public static Set<String> unLegalExtensionSet = new HashSet<>(DefaultConfig.DEFAULT_SUFFIX_SET);

    // 参数黑名单 - 从 MyHttpHandler 迁移到这里
    // 因为过滤逻辑在这个类中
    public static Set<String> blackParamsSet = new HashSet<>();


    //过滤一，来源为Proxy,Repeater
    public static boolean fromProxySource(HttpResponseReceived httpResponseReceived) {

        return httpResponseReceived.toolSource().isFromTool(ToolType.PROXY);
    }

    public static boolean fromRepeaterSource(HttpResponseReceived httpResponseReceived) {

        return httpResponseReceived.toolSource().isFromTool(ToolType.REPEATER);
    }

    /**
     * 正确的域名匹配逻辑：精确匹配或子域名匹配
     * @param host 要检查的主机名
     * @param pattern 匹配模式（域名）
     * @return true 如果匹配，false 否则
     */
    private static boolean domainMatches(String host, String pattern) {
        // 都转换为小写进行比较
        String hostLower = host.toLowerCase();
        String patternLower = pattern.toLowerCase();

        // 精确匹配或者子域名匹配（注意前面必须有点号）
        return hostLower.equals(patternLower)
            || hostLower.endsWith("." + patternLower);
    }

    //过滤二，保留白名单域名
    public static boolean matchesWhiteList(HttpResponseReceived httpResponseReceived) {
        if (whiteListSet.isEmpty()) {
            return true;
        }
        String host = httpResponseReceived.initiatingRequest().httpService().host();
        for (String pattern : whiteListSet) {
            if (domainMatches(host, pattern)) {
                return true;
            }
        }
        return false;
    }


    //过滤三，删除黑名单域名
    public static boolean matchesBlackList(HttpResponseReceived httpResponseReceived) {
        if (blackListSet.isEmpty()) {
            return false;
        }
        String host = httpResponseReceived.initiatingRequest().httpService().host();
        for (String pattern : blackListSet) {
            if (domainMatches(host, pattern)) {
                return true;
            }
        }
        return false;
    }

    //过滤四，保留GET,POST请求+PUT请求
    public static boolean isGetOrPostRequest(HttpResponseReceived httpResponseReceived) {
        return httpResponseReceived.initiatingRequest().method().equals(METHOD_GET) || httpResponseReceived.initiatingRequest().method().equals(METHOD_POST)||httpResponseReceived.initiatingRequest().method().equals(METHOD_PUT);
    }


    //过滤五，去除非法后缀
    public static boolean hasAllowedExtension(HttpResponseReceived httpResponseReceived) {
        if (unLegalExtensionSet.isEmpty()) {
            return true;
        }
        String fileExtension = httpResponseReceived.initiatingRequest().fileExtension().toLowerCase();
        return !unLegalExtensionSet.contains(fileExtension);
    }

    //过滤六，GET或POST参数不能为空+PUT（并且不能全部被黑名单过滤）

    private static boolean hasEffectiveParams(java.util.List<ParsedHttpParameter> params){
        if (params == null || params.isEmpty()) return false;
        // 如果全部参数名都在黑名单内，则视为无效（直接跳过测试）
        for (ParsedHttpParameter p : params) {
            if (!MyFilterRequest.blackParamsSet.contains(p.name())) {
                return true; // 至少存在一个未被黑名单过滤的参数
            }
        }
        return false;
    }

    public static boolean hasParameters(HttpResponseReceived httpResponseReceived) {
        var request = httpResponseReceived.initiatingRequest();
        String method = request.method();

        if (method.equals(METHOD_GET)) {
            return hasEffectiveParams(request.parameters(HttpParameterType.URL));
        }
        if (method.equals(METHOD_POST) || method.equals(METHOD_PUT)) {
            return hasEffectiveParams(request.parameters(HttpParameterType.BODY))
                || hasEffectiveParams(request.parameters(HttpParameterType.JSON))
                || hasEffectiveParams(request.parameters(HttpParameterType.XML));
        }
        return false;
    }
    //过滤七，路径黑名单
    public static boolean matchesBlackPath(HttpResponseReceived httpResponseReceived) {
        if(blackPathSet.isEmpty()){return false;}
        String path = httpResponseReceived.initiatingRequest().pathWithoutQuery();

        String cleanedText = path.replaceAll("\\n|\\r|\\r\\n", "");

        for (String rule : blackPathSet) {
            // 使用 RegexUtils 防止 ReDoS 攻击
            if (RegexUtils.safeMatch(rule, cleanedText)) {
                return true;

            }
        }
        return false;
    }

    //包含5个过滤方法的方法
    public static boolean filterOneRequest(HttpResponseReceived httpResponseReceived) {
        return matchesWhiteList(httpResponseReceived)
                && !matchesBlackList(httpResponseReceived)
                && isGetOrPostRequest(httpResponseReceived)
                && hasAllowedExtension(httpResponseReceived)
                && hasParameters(httpResponseReceived)
                && !matchesBlackPath(httpResponseReceived);
    }


    /**
     * Collects parameter names from a list and concatenates them into a single string
     * @param params list of HTTP parameters
     * @return concatenated parameter names
     */
    private static String collectParamNames(List<ParsedHttpParameter> params) {
        return params.stream()
                .map(ParsedHttpParameter::name)
                .collect(java.util.stream.Collectors.joining());
    }

    private static String getUniqueInternal(
            String method,
            String httpServices,
            String littlePath,
            List<ParsedHttpParameter> urlParams,
            List<ParsedHttpParameter> bodyParams,
            List<ParsedHttpParameter> jsonParams,
            List<ParsedHttpParameter> xmlParams
    ) {
        String paramNames;
        if (method.equals(METHOD_GET)) {
            paramNames = collectParamNames(urlParams);
        } else if (method.equals(METHOD_POST) || method.equals(METHOD_PUT)) {
            if (!bodyParams.isEmpty()) {
                paramNames = collectParamNames(bodyParams);
            } else if (!jsonParams.isEmpty()) {
                paramNames = collectParamNames(jsonParams);
            } else if (!xmlParams.isEmpty()) {
                paramNames = collectParamNames(xmlParams);
            } else {
                paramNames = "";
            }
        } else {
            paramNames = "";
        }
        return method + httpServices + littlePath + paramNames;
    }

    public static String getUnique(HttpResponseReceived httpResponseReceived) {
        return getUniqueInternal(
                httpResponseReceived.initiatingRequest().method(),
                httpResponseReceived.initiatingRequest().httpService().toString(),
                httpResponseReceived.initiatingRequest().pathWithoutQuery(),
                httpResponseReceived.initiatingRequest().parameters(HttpParameterType.URL),
                httpResponseReceived.initiatingRequest().parameters(HttpParameterType.BODY),
                httpResponseReceived.initiatingRequest().parameters(HttpParameterType.JSON),
                httpResponseReceived.initiatingRequest().parameters(HttpParameterType.XML)
        );
    }

    public static String getUnique(HttpRequestResponse selectHttpRequestRespons) {
        return getUniqueInternal(
                selectHttpRequestRespons.request().method(),
                selectHttpRequestRespons.request().httpService().toString(),
                selectHttpRequestRespons.request().pathWithoutQuery(),
                selectHttpRequestRespons.request().parameters(HttpParameterType.URL),
                selectHttpRequestRespons.request().parameters(HttpParameterType.BODY),
                selectHttpRequestRespons.request().parameters(HttpParameterType.JSON),
                selectHttpRequestRespons.request().parameters(HttpParameterType.XML)
        );
    }

}
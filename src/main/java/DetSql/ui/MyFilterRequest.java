/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.ui;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import DetSql.config.DefaultConfig;
import DetSql.util.StructuralSignature;

public class MyFilterRequest {
    // HTTP Method Constants
    private static final String METHOD_GET = "GET";
    private static final String METHOD_POST = "POST";
    private static final String METHOD_PUT = "PUT";

    // 调试开关 - 控制详细诊断日志输出
    // 设置为 true 可以看到每个请求的黑名单匹配过程
    private static final boolean DEBUG_BLACKLIST = true;

    // volatile 确保多线程环境下配置更新的可见性
    // 原因: UI线程更新配置时,HTTP工作线程池需要立即看到最新值
    public static volatile Set<String> whiteListSet = new HashSet<>();

    public static volatile Set<String> blackListSet = new HashSet<>();
    public static volatile Set<String> blackPathSet = new HashSet<>();

    public static volatile Set<String> unLegalExtensionSet = new HashSet<>(DefaultConfig.DEFAULT_SUFFIX_SET);

    // 参数黑名单 - 从 MyHttpHandler 迁移到这里
    // 因为过滤逻辑在这个类中
    public static volatile Set<String> blackParamsSet = new HashSet<>();

    // 已过滤域名的跟踪集合 - 避免重复输出相同域名的过滤日志
    // 使用ConcurrentHashMap实现线程安全的Set
    private static final java.util.Set<String> filteredHostsLogged = java.util.concurrent.ConcurrentHashMap.newKeySet();

    // 已过滤路径的跟踪集合 - 避免重复输出相同路径的过滤日志
    private static final java.util.Set<String> filteredPathsLogged = java.util.concurrent.ConcurrentHashMap.newKeySet();

    // 过滤一，来源为Proxy,Repeater
    public static boolean fromProxySource(HttpResponseReceived httpResponseReceived) {

        return httpResponseReceived.toolSource().isFromTool(ToolType.PROXY);
    }

    public static boolean fromRepeaterSource(HttpResponseReceived httpResponseReceived) {

        return httpResponseReceived.toolSource().isFromTool(ToolType.REPEATER);
    }

    /**
     * 正确的域名匹配逻辑：精确匹配或子域名匹配
     * 
     * @param host    要检查的主机名
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

    // 过滤二，保留白名单域名
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

    // 过滤三,删除黑名单域名
    public static boolean matchesBlackList(HttpResponseReceived httpResponseReceived) {
        if (blackListSet.isEmpty()) {
            // 调试日志: 黑名单为空时输出警告
            if (DEBUG_BLACKLIST) {
                System.out.println("[DetSQL DEBUG] 黑名单检查(被动): blackListSet 为空,未配置任何黑名单");
            }
            return false;
        }
        String host = httpResponseReceived.initiatingRequest().httpService().host();

        // 调试日志: 输出当前检查的主机和黑名单规则
        if (DEBUG_BLACKLIST) {
            System.out.println("[DetSQL DEBUG] 黑名单检查(被动): host=" + host + ", blackListSet=" + blackListSet);
        }

        for (String pattern : blackListSet) {
            if (domainMatches(host, pattern)) {
                // 每个域名只输出一次过滤日志，避免日志泛滥
                String logKey = host + ":" + pattern;
                if (filteredHostsLogged.add(logKey)) {
                    System.out.println("[DetSQL 过滤] 域名已被黑名单拦截: " + host + " (匹配规则: " + pattern + ")");
                }
                return true;
            }
        }

        // 调试日志: 未匹配黑名单
        if (DEBUG_BLACKLIST) {
            System.out.println("[DetSQL DEBUG] 黑名单检查(被动): host=" + host + " 未匹配任何黑名单规则");
        }
        return false;
    }

    // 过滤四，保留GET,POST请求+PUT请求
    public static boolean isGetOrPostRequest(HttpResponseReceived httpResponseReceived) {
        return httpResponseReceived.initiatingRequest().method().equals(METHOD_GET)
                || httpResponseReceived.initiatingRequest().method().equals(METHOD_POST)
                || httpResponseReceived.initiatingRequest().method().equals(METHOD_PUT);
    }

    // 过滤五，去除非法后缀
    public static boolean hasAllowedExtension(HttpResponseReceived httpResponseReceived) {
        if (unLegalExtensionSet.isEmpty()) {
            return true;
        }
        String fileExtension = httpResponseReceived.initiatingRequest().fileExtension().toLowerCase();
        return !unLegalExtensionSet.contains(fileExtension);
    }

    // 过滤六，GET或POST参数不能为空+PUT（并且不能全部被黑名单过滤）

    private static boolean hasEffectiveParams(java.util.List<ParsedHttpParameter> params) {
        if (params == null || params.isEmpty())
            return false;
        // 如果全部参数名都在黑名单内，则视为无效（直接跳过测试）
        for (ParsedHttpParameter p : params) {
            if (!MyFilterRequest.blackParamsSet.contains(p.name())) {
                return true; // 至少存在一个未被黑名单过滤的参数
            }
        }
        return false;
    }

    /**
     * 检查请求是否为"无效请求"（只有一个参数且参数名等于参数值）
     * 例如: GET /?xxx=xxx 会被过滤
     * 但是: GET /?a=a&b=b 不会被过滤（多参数情况）
     *
     * @param params 参数列表
     * @return true 如果是无效请求，false 否则
     */
    private static boolean isUselessRequest(java.util.List<ParsedHttpParameter> params) {
        if (params == null || params.size() != 1) {
            return false; // 不是单参数请求，不处理
        }
        ParsedHttpParameter param = params.get(0);
        return param.name().equals(param.value());
    }

    /**
     * 检查参数是否为时间戳参数（用于缓存破坏）
     * 过滤以下情况：
     * 1. 单个参数且参数名或参数值为纯数字时间戳（>= 10 位）
     * 2. 例如: GET /?1764049379072 或 GET /?t=1764049379072
     *
     * @param params 参数列表
     * @return true 如果是时间戳参数，false 否则
     */
    private static boolean isTimestampParameter(java.util.List<ParsedHttpParameter> params) {
        if (params == null || params.isEmpty()) {
            return false;
        }

        // 只处理单参数情况（多参数可能包含有效业务参数）
        if (params.size() == 1) {
            ParsedHttpParameter param = params.get(0);
            String name = param.name();
            String value = param.value();

            // 参数名为纯数字且 >= 10 位（时间戳长度）
            if (name != null && name.matches("^\\d{10,}$")) {
                return true;
            }

            // 参数值为纯数字且 >= 10 位
            if (value != null && value.matches("^\\d{10,}$")) {
                return true;
            }
        }

        return false;
    }

    public static boolean hasParameters(HttpResponseReceived httpResponseReceived) {
        var request = httpResponseReceived.initiatingRequest();
        String method = request.method();

        if (method.equals(METHOD_GET)) {
            java.util.List<ParsedHttpParameter> urlParams = request.parameters(HttpParameterType.URL);
            // 过滤无效请求（单参数且 name==value）
            if (isUselessRequest(urlParams)) {
                return false;
            }
            // 过滤时间戳参数（单参数且为纯数字时间戳）
            if (isTimestampParameter(urlParams)) {
                return false;
            }
            return hasEffectiveParams(urlParams);
        }
        if (method.equals(METHOD_POST) || method.equals(METHOD_PUT)) {
            // 增强: 彻底移除所有空白字符后检查空 JSON/Array
            String body = request.bodyToString().replaceAll("\\s+", "");
            if (body.equals("[]") || body.equals("{}")) {
                return false;
            }

            return hasEffectiveParams(request.parameters(HttpParameterType.BODY))
                    || hasEffectiveParams(request.parameters(HttpParameterType.JSON))
                    || hasEffectiveParams(request.parameters(HttpParameterType.XML));
        }
        return false;
    }

    // 过滤七，路径黑名单
    public static boolean matchesBlackPath(HttpResponseReceived httpResponseReceived) {
        if (blackPathSet.isEmpty()) {
            return false;
        }
        String path = httpResponseReceived.initiatingRequest().pathWithoutQuery();
        String cleanedText = path.replaceAll("\\n|\\r|\\r\\n", "").trim();

        // 调试日志: 输出当前检查的路径和黑名单规则
        if (DEBUG_BLACKLIST) {
            System.out.println("[DetSQL DEBUG] 路径黑名单检查: path=" + cleanedText + ", blackPathSet=" + blackPathSet);
        }

        // 精确匹配：O(1) HashSet 查找，替代 O(N) 正则遍历
        if (blackPathSet.contains(cleanedText)) {
            // 每个路径只输出一次过滤日志，避免日志泛滥
            if (filteredPathsLogged.add(cleanedText)) {
                System.out.println("[DetSQL 过滤] 路径已被黑名单拦截: " + cleanedText);
            }
            return true;
        }

        // 调试日志: 未匹配黑名单
        if (DEBUG_BLACKLIST) {
            System.out.println("[DetSQL DEBUG] 路径黑名单检查: path=" + cleanedText + " 未匹配任何黑名单规则");
        }
        return false;
    }

    // 包含5个过滤方法的方法
    public static boolean filterOneRequest(HttpResponseReceived httpResponseReceived) {
        return matchesWhiteList(httpResponseReceived)
                && !matchesBlackList(httpResponseReceived)
                && isGetOrPostRequest(httpResponseReceived)
                && hasAllowedExtension(httpResponseReceived)
                && !matchesBlackPath(httpResponseReceived)
                && hasParameters(httpResponseReceived);
    }

    /**
     * Collects parameter names from a list and concatenates them into a single
     * string
     * Parameters are sorted to ensure consistent hash regardless of parameter order
     * Uses pipe separator to prevent parameter name collision (e.g., "id|name" vs
     * "idn|ame")
     * 
     * @param params list of HTTP parameters
     * @return concatenated parameter names with separator
     */
    private static String collectParamNames(List<ParsedHttpParameter> params) {
        return params.stream()
                .map(ParsedHttpParameter::name)
                .sorted()
                .collect(java.util.stream.Collectors.joining("|"));
    }

    private static String getUniqueInternal(
            String method,
            String httpServices,
            String littlePath,
            List<ParsedHttpParameter> urlParams,
            List<ParsedHttpParameter> bodyParams,
            List<ParsedHttpParameter> jsonParams,
            List<ParsedHttpParameter> xmlParams) {
        // 提取主机名
        String host = StructuralSignature.extractHost(httpServices);

        // 收集参数名
        List<String> paramNames = new ArrayList<>();
        if (method.equals(METHOD_GET)) {
            paramNames = urlParams.stream()
                    .map(ParsedHttpParameter::name)
                    .collect(java.util.stream.Collectors.toList());
        } else if (method.equals(METHOD_POST) || method.equals(METHOD_PUT)) {
            if (!bodyParams.isEmpty()) {
                paramNames = bodyParams.stream()
                        .map(ParsedHttpParameter::name)
                        .collect(java.util.stream.Collectors.toList());
            } else if (!jsonParams.isEmpty()) {
                paramNames = jsonParams.stream()
                        .map(ParsedHttpParameter::name)
                        .collect(java.util.stream.Collectors.toList());
            } else if (!xmlParams.isEmpty()) {
                paramNames = xmlParams.stream()
                        .map(ParsedHttpParameter::name)
                        .collect(java.util.stream.Collectors.toList());
            }
        }

        // 使用结构化签名
        return StructuralSignature.generate(method, host, littlePath, paramNames);
    }

    public static String getUnique(HttpResponseReceived httpResponseReceived) {
        return getUniqueInternal(
                httpResponseReceived.initiatingRequest().method(),
                httpResponseReceived.initiatingRequest().httpService().toString(),
                httpResponseReceived.initiatingRequest().pathWithoutQuery(),
                httpResponseReceived.initiatingRequest().parameters(HttpParameterType.URL),
                httpResponseReceived.initiatingRequest().parameters(HttpParameterType.BODY),
                httpResponseReceived.initiatingRequest().parameters(HttpParameterType.JSON),
                httpResponseReceived.initiatingRequest().parameters(HttpParameterType.XML));
    }

    public static String getUnique(HttpRequestResponse selectHttpRequestRespons) {
        return getUniqueInternal(
                selectHttpRequestRespons.request().method(),
                selectHttpRequestRespons.request().httpService().toString(),
                selectHttpRequestRespons.request().pathWithoutQuery(),
                selectHttpRequestRespons.request().parameters(HttpParameterType.URL),
                selectHttpRequestRespons.request().parameters(HttpParameterType.BODY),
                selectHttpRequestRespons.request().parameters(HttpParameterType.JSON),
                selectHttpRequestRespons.request().parameters(HttpParameterType.XML));
    }

    // **************************
    // 适配 HttpRequestResponse 的过滤方法
    // 用于右键菜单"发送到 DetSql"功能
    // **************************

    /**
     * 检查 HttpRequestResponse 是否匹配白名单域名
     */
    public static boolean matchesWhiteList(HttpRequestResponse request) {
        if (whiteListSet.isEmpty()) {
            return true;
        }
        String host = request.request().httpService().host();
        for (String pattern : whiteListSet) {
            if (domainMatches(host, pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检查 HttpRequestResponse 是否在黑名单域名中
     */
    public static boolean matchesBlackList(HttpRequestResponse request) {
        if (blackListSet.isEmpty()) {
            // 调试日志: 黑名单为空时输出警告
            if (DEBUG_BLACKLIST) {
                System.out.println("[DetSQL DEBUG] 黑名单检查(主动): blackListSet 为空,未配置任何黑名单");
            }
            return false;
        }
        String host = request.request().httpService().host();

        // 调试日志: 输出当前检查的主机和黑名单规则
        if (DEBUG_BLACKLIST) {
            System.out.println("[DetSQL DEBUG] 黑名单检查(主动): host=" + host + ", blackListSet=" + blackListSet);
        }

        for (String pattern : blackListSet) {
            if (domainMatches(host, pattern)) {
                // 每个域名只输出一次过滤日志，避免日志泛滥
                String logKey = host + ":" + pattern;
                if (filteredHostsLogged.add(logKey)) {
                    System.out.println("[DetSQL 过滤] 域名已被黑名单拦截: " + host + " (匹配规则: " + pattern + ")");
                }
                return true;
            }
        }

        // 调试日志: 未匹配黑名单
        if (DEBUG_BLACKLIST) {
            System.out.println("[DetSQL DEBUG] 黑名单检查(主动): host=" + host + " 未匹配任何黑名单规则");
        }
        return false;
    }

    /**
     * 检查 HttpRequestResponse 是否为 GET/POST/PUT 请求
     */
    public static boolean isGetOrPostRequest(HttpRequestResponse request) {
        String method = request.request().method();
        return method.equals(METHOD_GET) || method.equals(METHOD_POST) || method.equals(METHOD_PUT);
    }

    /**
     * 检查 HttpRequestResponse 是否有允许的扩展名
     */
    public static boolean hasAllowedExtension(HttpRequestResponse request) {
        if (unLegalExtensionSet.isEmpty()) {
            return true;
        }
        String fileExtension = request.request().fileExtension().toLowerCase();
        return !unLegalExtensionSet.contains(fileExtension);
    }

    /**
     * 检查 HttpRequestResponse 是否有有效参数
     */
    public static boolean hasParameters(HttpRequestResponse request) {
        String method = request.request().method();

        if (method.equals(METHOD_GET)) {
            java.util.List<ParsedHttpParameter> urlParams = request.request().parameters(HttpParameterType.URL);
            // 过滤无效请求（单参数且 name==value）
            if (isUselessRequest(urlParams)) {
                return false;
            }
            // 过滤时间戳参数（单参数且为纯数字时间戳）
            if (isTimestampParameter(urlParams)) {
                return false;
            }
            return hasEffectiveParams(urlParams);
        }
        if (method.equals(METHOD_POST) || method.equals(METHOD_PUT)) {
            // 增强: 彻底移除所有空白字符后检查空 JSON/Array
            String body = request.request().bodyToString().replaceAll("\\s+", "");
            if (body.equals("[]") || body.equals("{}")) {
                return false;
            }

            return hasEffectiveParams(request.request().parameters(HttpParameterType.BODY))
                    || hasEffectiveParams(request.request().parameters(HttpParameterType.JSON))
                    || hasEffectiveParams(request.request().parameters(HttpParameterType.XML));
        }
        return false;
    }

    /**
     * 检查 HttpRequestResponse 是否匹配路径黑名单
     */
    public static boolean matchesBlackPath(HttpRequestResponse request) {
        if (blackPathSet.isEmpty()) {
            return false;
        }
        String path = request.request().pathWithoutQuery();
        String cleanedText = path.replaceAll("\\n|\\r|\\r\\n", "").trim();

        // 调试日志: 输出当前检查的路径和黑名单规则
        if (DEBUG_BLACKLIST) {
            System.out.println("[DetSQL DEBUG] 路径黑名单检查(主动): path=" + cleanedText + ", blackPathSet=" + blackPathSet);
        }

        // 精确匹配：O(1) HashSet 查找，替代 O(N) 正则遍历
        if (blackPathSet.contains(cleanedText)) {
            // 每个路径只输出一次过滤日志，避免日志泛滥
            if (filteredPathsLogged.add(cleanedText)) {
                System.out.println("[DetSQL 过滤] 路径已被黑名单拦截(主动): " + cleanedText);
            }
            return true;
        }

        // 调试日志: 未匹配黑名单
        if (DEBUG_BLACKLIST) {
            System.out.println("[DetSQL DEBUG] 路径黑名单检查(主动): path=" + cleanedText + " 未匹配任何黑名单规则");
        }
        return false;
    }

    /**
     * 检查 HttpRequestResponse 请求大小是否在限制范围内
     * 防止发送过大的请求导致内存问题
     */
    public static boolean hasValidRequestSize(HttpRequestResponse request) {
        try {
            int requestSize = request.request().toByteArray().length();
            return requestSize <= DefaultConfig.MAX_REQUEST_SIZE_BYTES;
        } catch (Exception e) {
            // 如果无法获取请求大小,默认允许
            return true;
        }
    }

    /**
     * 重置诊断标志 - 用于配置更新后重新输出诊断日志
     * 应在配置更新时调用此方法
     */
    public static void resetDiagnosticFlags() {
        // 清空已记录的过滤域名和路径集合，使配置更新后能重新输出过滤日志
        filteredHostsLogged.clear();
        filteredPathsLogged.clear();
        System.out.println("[DetSQL 配置] 域名黑名单已更新: " + blackListSet);
        System.out.println("[DetSQL 配置] 路径黑名单已更新: " + blackPathSet);
    }

    /**
     * 统一的过滤逻辑 - 支持 HttpRequestResponse
     * 用于右键菜单"发送到 DetSql"功能
     */
    public static boolean filterOneRequest(HttpRequestResponse request) {
        return matchesWhiteList(request)
                && !matchesBlackList(request)
                && isGetOrPostRequest(request)
                && hasAllowedExtension(request)
                && !matchesBlackPath(request)
                && hasParameters(request)
                && hasValidRequestSize(request);
    }

}
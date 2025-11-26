/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.util;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 结构化签名生成器
 * 用于智能去重 REST API 请求，避免对相似路径的重复扫描
 * 
 * 功能：
 * 1. 路径规范化：将动态部分替换为占位符
 *    - 数字：/user/123 → /user/{int}
 *    - UUID：/api/550e8400-e29b-41d4-a716-446655440000 → /api/{uuid}
 *    - 十六进制：/session/a1b2c3d4e5f6 → /session/{hex}
 * 2. 参数过滤：忽略噪声参数（时间戳、随机数等）
 * 3. 签名生成：组合关键信息生成唯一签名
 */
public class StructuralSignature {
    
    // UUID 正则：8-4-4-4-12 格式
    private static final Pattern UUID_PATTERN = Pattern.compile(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );
    
    // 纯数字路径段
    private static final Pattern NUMERIC_PATTERN = Pattern.compile("^\\d+$");
    
    // 十六进制路径段（至少 8 位）
    private static final Pattern HEX_PATTERN = Pattern.compile("^[0-9a-fA-F]{8,}$");
    
    // 噪声参数名称（时间戳、随机数、回调函数等）
    private static final Set<String> NOISE_PARAMS = new HashSet<>(Arrays.asList(
        "timestamp", "_t", "_ts", "time",
        "random", "nonce", "_r", "rand",
        "callback", "jsonp", "_"
    ));
    
    /**
     * 规范化路径：替换动态部分为占位符
     * 
     * @param path 原始路径
     * @return 规范化后的路径
     */
    public static String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return path;
        }
        
        // 按 / 分割路径
        String[] segments = path.split("/");
        StringBuilder normalized = new StringBuilder();
        
        boolean first = true;
        for (String segment : segments) {
            if (segment.isEmpty()) {
                continue;  // 跳过空段（由连续的 / 或开头的 / 产生）
            }
            
            // 添加分隔符
            if (!first) {
                normalized.append("/");
            }
            first = false;
            
            // 检查是否为 UUID
            if (UUID_PATTERN.matcher(segment).matches()) {
                normalized.append("{uuid}");
            }
            // 检查是否为纯数字
            else if (NUMERIC_PATTERN.matcher(segment).matches()) {
                normalized.append("{int}");
            }
            // 检查是否为十六进制（至少 8 位）
            else if (HEX_PATTERN.matcher(segment).matches()) {
                normalized.append("{hex}");
            }
            // 保持原样
            else {
                normalized.append(segment);
            }
        }
        
        // 如果原路径以 / 开头，结果也应该以 / 开头
        String result = normalized.toString();
        if (path.startsWith("/") && !result.startsWith("/")) {
            result = "/" + result;
        }
        
        return result;
    }
    
    /**
     * 过滤噪声参数
     * 
     * @param paramNames 参数名列表
     * @return 过滤后的参数名列表
     */
    public static List<String> filterNoiseParams(List<String> paramNames) {
        if (paramNames == null || paramNames.isEmpty()) {
            return paramNames;
        }
        
        return paramNames.stream()
            .filter(name -> !NOISE_PARAMS.contains(name.toLowerCase()))
            .collect(Collectors.toList());
    }
    
    /**
     * 生成结构化签名
     * 
     * @param method HTTP 方法
     * @param host 主机名
     * @param path 路径
     * @param paramNames 参数名列表
     * @return 签名字符串
     */
    public static String generate(String method, String host, String path, List<String> paramNames) {
        // 1. 规范化路径
        String normalizedPath = normalizePath(path);
        
        // 2. 过滤噪声参数
        List<String> filteredParams = filterNoiseParams(paramNames);
        
        // 3. 排序参数名（确保一致性）
        List<String> sortedParams = new ArrayList<>(filteredParams);
        Collections.sort(sortedParams);
        
        // 4. 组合签名：Method + Host + NormalizedPath + SortedParamKeys
        StringBuilder signature = new StringBuilder();
        signature.append(method != null ? method : "");
        signature.append("|");
        signature.append(host != null ? host : "");
        signature.append("|");
        signature.append(normalizedPath != null ? normalizedPath : "");
        signature.append("|");
        signature.append(String.join("|", sortedParams));
        
        return signature.toString();
    }
    
    /**
     * 从 httpServices 字符串中提取主机名
     * 
     * @param httpServices 格式如 "https://example.com:443"
     * @return 主机名，如 "example.com"
     */
    public static String extractHost(String httpServices) {
        if (httpServices == null || httpServices.isEmpty()) {
            return "";
        }
        
        // 移除协议部分
        String withoutProtocol = httpServices.replaceFirst("^https?://", "");
        
        // 移除端口部分
        int colonIndex = withoutProtocol.indexOf(':');
        if (colonIndex > 0) {
            return withoutProtocol.substring(0, colonIndex);
        }
        
        return withoutProtocol;
    }
}

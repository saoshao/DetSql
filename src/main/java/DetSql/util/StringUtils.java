package DetSql.util;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 字符串工具类
 * 从 DetSqlUI 中提取的工具方法
 */
public class StringUtils {

    /**
     * Base64 编码
     * 
     * @param input 输入字符串
     * @return Base64 编码后的字符串
     */
    public static String base64Encode(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Base64 解码
     * 
     * @param input Base64 编码的字符串
     * @return 解码后的字符串
     */
    public static String base64Decode(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(input);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return "解码失败: " + e.getMessage();
        }
    }

    /**
     * URL 编码
     * 
     * @param input 输入字符串
     * @return URL 编码后的字符串
     */
    public static String urlEncode(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        return URLEncoder.encode(input, StandardCharsets.UTF_8);
    }

    /**
     * URL 解码
     * 
     * @param input URL 编码的字符串
     * @return 解码后的字符串
     */
    public static String urlDecode(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        return URLDecoder.decode(input, StandardCharsets.UTF_8);
    }

    /**
     * Unicode 解码
     * 
     * @param unicodeStr Unicode 编码的字符串 (如 \u0041)
     * @return 解码后的字符串,如果格式错误则返回错误提示
     */
    public static String unicodeDecode(String unicodeStr) {
        if (unicodeStr == null || unicodeStr.isEmpty()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        Matcher matcher = Pattern.compile("\\\\u([0-9a-fA-F]{4})").matcher(unicodeStr);

        // 记录是否有匹配和解码失败
        boolean hasMatch = false;
        boolean hasError = false;

        while (matcher.find()) {
            hasMatch = true;
            try {
                String ch = String.valueOf((char) Integer.parseInt(matcher.group(1), 16));
                sb.append(ch);
            } catch (NumberFormatException e) {
                // 保留原始序列,但标记错误
                sb.append(matcher.group(0));
                hasError = true;
            }
        }

        // 如果没有匹配到任何 Unicode 序列,返回提示
        if (!hasMatch && !unicodeStr.isEmpty()) {
            return "解码失败: 未检测到有效的 Unicode 序列 (格式: \\uXXXX)";
        }

        // 如果有解码失败,在结果末尾添加提示
        if (hasError) {
            return sb.toString() + "\n[警告: 部分序列解码失败]";
        }

        return sb.toString();
    }

    /**
     * Unicode 编码
     * 
     * @param string 输入字符串
     * @return Unicode 编码后的字符串
     */
    public static String unicodeEncode(String string) {
        char[] utfBytes = string.toCharArray();
        StringBuilder unicodeBytes = new StringBuilder();
        for (char utfByte : utfBytes) {
            String hexB = Integer.toHexString(utfByte);
            if (hexB.length() <= 2) {
                hexB = "00" + hexB;
            }
            unicodeBytes.append("\\u").append(hexB);
        }
        return unicodeBytes.toString();
    }

    /**
     * 截断字符串到指定长度
     * 
     * @param input     输入字符串
     * @param maxLength 最大长度
     * @return 截断后的字符串
     */
    public static String truncate(String input, int maxLength) {
        if (input == null) {
            return "";
        }
        if (input.length() <= maxLength) {
            return input;
        }
        return input.substring(0, maxLength) + "...";
    }

    /**
     * 解析分隔字符串为 Set（使用 | 分隔符）
     * 安全性：此方法确保没有前导/尾随空格，以防止过滤器绕过漏洞
     * 
     * @param input 输入字符串，使用 | 分隔（例如 "jpg | png | gif"）
     * @return 修剪后的非空标记集合
     */
    public static java.util.Set<String> parseDelimitedString(String input) {
        if (input == null || input.isBlank()) {
            return new java.util.HashSet<>();
        }
        // Support pipe, comma, semicolon, and newline as delimiters
        return java.util.Arrays.stream(input.split("[|,\n;]"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(java.util.stream.Collectors.toSet());
    }
}

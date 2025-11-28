package DetSql.util;

/**
 * 安全的字符串操作工具类，防止索引越界
 * 所有操作都包含边界检查
 *
 * @author DetSql Security Team
 * @since v3.3.1
 */
public class SafeString {

    /**
     * 安全的charAt，带边界检查
     * @param s 字符串
     * @param index 索引位置
     * @param defaultValue 越界时的默认值
     * @return 指定位置的字符或默认值
     */
    public static char charAt(String s, int index, char defaultValue) {
        if (s == null || index < 0 || index >= s.length()) {
            return defaultValue;
        }
        return s.charAt(index);
    }

    /**
     * 安全的charAt，越界返回空字符
     * @param s 字符串
     * @param index 索引位置
     * @return 指定位置的字符或空字符
     */
    public static char charAt(String s, int index) {
        return charAt(s, index, '\0');
    }

    /**
     * 检查索引是否有效
     * @param s 字符串
     * @param index 索引位置
     * @return 索引是否在有效范围内
     */
    public static boolean isValidIndex(String s, int index) {
        return s != null && index >= 0 && index < s.length();
    }

    /**
     * 安全的substring，自动修正越界
     * @param s 字符串
     * @param start 起始位置
     * @param end 结束位置
     * @return 子字符串
     */
    public static String substring(String s, int start, int end) {
        if (s == null) return "";

        int len = s.length();
        // 修正起始位置
        start = Math.max(0, Math.min(start, len));
        // 修正结束位置
        end = Math.max(start, Math.min(end, len));

        return s.substring(start, end);
    }

    /**
     * 安全的substring，从start到末尾
     * @param s 字符串
     * @param start 起始位置
     * @return 子字符串
     */
    public static String substring(String s, int start) {
        if (s == null) return "";

        int len = s.length();
        start = Math.max(0, Math.min(start, len));
        return s.substring(start);
    }

    /**
     * 安全地检查字符串指定位置是否为特定字符
     * @param s 字符串
     * @param index 索引位置
     * @param c 要比较的字符
     * @return 是否匹配
     */
    public static boolean isCharAt(String s, int index, char c) {
        return isValidIndex(s, index) && s.charAt(index) == c;
    }

    /**
     * 安全地获取子字符串，如果越界返回默认值
     * @param s 字符串
     * @param start 起始位置
     * @param end 结束位置
     * @param defaultValue 越界时的默认值
     * @return 子字符串或默认值
     */
    public static String substringOrDefault(String s, int start, int end, String defaultValue) {
        if (s == null || start < 0 || start >= s.length() || end <= start) {
            return defaultValue;
        }
        return substring(s, start, end);
    }

    /**
     * 安全地在指定位置前后检查字符
     * 用于JSON字符串的引号检查等场景
     * @param s 字符串
     * @param startIndex 起始位置
     * @param endIndex 结束位置
     * @param startChar 起始位置前一个字符
     * @param endChar 结束位置的字符
     * @return 是否匹配
     */
    public static boolean isSurroundedBy(String s, int startIndex, int endIndex, char startChar, char endChar) {
        return isCharAt(s, startIndex - 1, startChar) && isCharAt(s, endIndex, endChar);
    }
}
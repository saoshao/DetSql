/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql.util;
import org.apache.commons.text.similarity.JaccardSimilarity;
import org.apache.commons.text.similarity.LevenshteinDistance;
import java.text.NumberFormat;
import java.util.*;
import java.util.function.BiFunction;

public class MyCompare {
    public static String formatNumber(double number) {
        return String.format("%.3f", number);
    }

    public static String formatPercent(double number) {
        NumberFormat percentFormat = NumberFormat.getPercentInstance();
        percentFormat.setMinimumFractionDigits(1); // 设置小数点后最少的数字位数
        return percentFormat.format(number);
    }

    /**
     * 计算两个字符串的 Levenshtein 相似度（带快速失败机制）
     * @param str1 字符串1
     * @param str2 字符串2
     * @return 相似度值 (0.0-1.0)
     */
    public static double levenshtein(String str1, String str2) {
        return levenshteinWithThreshold(str1, str2, 0.0);
    }
    
    /**
     * 计算两个字符串的 Levenshtein 相似度（带阈值快速失败）
     * @param str1 字符串1
     * @param str2 字符串2
     * @param threshold 相似度阈值（0.0-1.0），低于此值可提前返回
     * @return 相似度值 (0.0-1.0)
     */
    public static double levenshteinWithThreshold(String str1, String str2, double threshold) {
        if (str1 == null || str2 == null) {
            return 0.0;
        }
        
        // 快速检查1：完全相同
        if (str1.equals(str2)) {
            return 1.0;
        }
        
        // 快速检查2：长度差异过大，直接返回
        int lenDiff = Math.abs(str1.length() - str2.length());
        int maxLen = Math.max(str1.length(), str2.length());
        if (maxLen > 0 && lenDiff > maxLen * (1 - threshold)) {
            return 0.0; // 不可能达到阈值
        }
        
        // 快速检查3：前 100 字符差异过大
        if (str1.length() > 100 && str2.length() > 100) {
            String prefix1 = str1.substring(0, 100);
            String prefix2 = str2.substring(0, 100);
            if (!prefix1.equals(prefix2)) {
                int prefixDist = LevenshteinDistance.getDefaultInstance().apply(prefix1, prefix2);
                if (prefixDist > 50) {
                    return 0.0; // 前缀差异太大
                }
            }
        }
        
        // 执行完整计算
        int distance = LevenshteinDistance.getDefaultInstance().apply(str1, str2);
        return 1 - (double) distance / maxLen;
    }
    /**
     * 计算两个字符串的 Jaccard 相似度
     * @param str1 字符串1
     * @param str2 字符串2
     * @return 相似度值 (0.0-1.0)
     */
    public static double jaccard(String str1, String str2) {
        if (str1 == null || str2 == null) {
            return 0.0;
        }
        if (str1.equals(str2)) {
            return 1.0;
        }
        return new JaccardSimilarity().apply(str1, str2);
    }

    // 提取相似度计算公共逻辑
    private static List<Double> calculateSimilarity(
            String s1, String s2,
            String poc1, String poc2,
            boolean html_flag,
            BiFunction<String, String, Double> similarityFunc) {
        List<Double> list = new ArrayList<>();
        int lengthDiff = Math.abs(s1.length() - s2.length());

        if (lengthDiff <= 1) {
            return List.of(1.0);
        }

        if (s1.isEmpty() || s2.isEmpty()) {
            return List.of(0.0);
        }

        if (lengthDiff >= 100) {
            return List.of(0.0);
        }

        if (s1.length() < s2.length() && (s2.startsWith(s1) || s2.endsWith(s1))) {
            return List.of(0.0);
        }

        if (s2.length() < s1.length() && (s1.startsWith(s2) || s1.endsWith(s2))) {
            return List.of(0.0);
        }



        if (html_flag) {
            String[] newStrList;
            if (s1.length() < s2.length()) {
                newStrList = upgradeStr(s1, s2);
                if ((newStrList[0].replaceAll(poc1, "").isEmpty() && !newStrList[1].replaceAll(poc2, "").isEmpty()) ||
                    (!newStrList[0].replaceAll(poc1, "").isEmpty() && newStrList[1].replaceAll(poc2, "").isEmpty())) {
                    list.add(0.0);
                } else if (newStrList[0].replaceAll(poc1, "").isEmpty() && newStrList[1].replaceAll(poc2, "").isEmpty()) {
                    list.add(1.0);
                } else {
                    double similarity = similarityFunc.apply(newStrList[0], newStrList[1]);
                    list.add(similarity);
                }
            } else {
                newStrList = upgradeStr(s2, s1);
                if ((newStrList[0].replaceAll(poc2, "").isEmpty() && !newStrList[1].replaceAll(poc1, "").isEmpty()) ||
                    (!newStrList[0].replaceAll(poc2, "").isEmpty() && newStrList[1].replaceAll(poc1, "").isEmpty())) {
                    list.add(0.0);
                } else if (newStrList[0].replaceAll(poc2, "").isEmpty() && newStrList[1].replaceAll(poc1, "").isEmpty()) {
                    list.add(1.0);
                } else {
                    double similarity = similarityFunc.apply(newStrList[0], newStrList[1]);
                    list.add(similarity);
                }
            }
        } else {
            double similarity = similarityFunc.apply(s1, s2);
            list.add(similarity);
        }

        return list;
    }

    /**
     * 智能相似度计算（针对 HTTP 响应优化）
     * 对于超大响应体，只比较关键部分以提高性能
     * @param response1 响应1
     * @param response2 响应2
     * @param threshold 阈值
     * @return 相似度
     */
    public static double responseSimilarity(String response1, String response2, double threshold) {
        if (response1 == null || response2 == null) {
            return 0.0;
        }
        
        // 如果响应体过大（>50KB），只比较前 10KB 和后 5KB
        final int MAX_SIZE = 50 * 1024;
        final int HEAD_SIZE = 10 * 1024;
        final int TAIL_SIZE = 5 * 1024;
        
        if (response1.length() > MAX_SIZE || response2.length() > MAX_SIZE) {
            String r1Head = response1.substring(0, Math.min(HEAD_SIZE, response1.length()));
            String r1Tail = response1.length() > HEAD_SIZE ? 
                response1.substring(Math.max(0, response1.length() - TAIL_SIZE)) : "";
            
            String r2Head = response2.substring(0, Math.min(HEAD_SIZE, response2.length()));
            String r2Tail = response2.length() > HEAD_SIZE ? 
                response2.substring(Math.max(0, response2.length() - TAIL_SIZE)) : "";
            
            // 分别计算头部和尾部相似度，取平均值
            double headSim = levenshteinWithThreshold(r1Head, r2Head, threshold);
            double tailSim = levenshteinWithThreshold(r1Tail, r2Tail, threshold);
            return (headSim + tailSim) / 2.0;
        }
        
        return levenshteinWithThreshold(response1, response2, threshold);
    }
    
    //SqlNum,SqlString使用
    public static List<Double> averageLevenshtein(String s1, String s2,String poc1,String poc2,boolean html_flag) {
        return calculateSimilarity(s1, s2, poc1, poc2, html_flag, MyCompare::levenshtein);
    }

    //SqlOrder使用
    public static List<Double> averageJaccard(String s1, String s2,String poc1,String poc2,boolean html_flag) {
        return calculateSimilarity(s1, s2, poc1, poc2, html_flag, MyCompare::jaccard);
    }

    /**
     * 移除两个字符串的公共前缀和后缀，只保留不同的部分。
     * 此方法用于在相似度计算前进行字符串预处理，减少无关部分的干扰。
     *
     * @param shorter 较短的字符串（前提条件: shorter.length() <= longer.length()）
     * @param longer 较长的字符串
     * @return 包含两个字符串差异部分的数组 [shorter的差异部分, longer的差异部分]
     *
     * <p>示例：
     * <pre>
     * upgradeStr("abcXdef", "abcYdef") -> ["X", "Y"]
     * upgradeStr("hello", "hello world") -> ["", " world"]
     * upgradeStr("test", "test") -> ["", ""]
     * </pre>
     */
    public static String[] upgradeStr(String shorter, String longer) {
        int shorterLength = shorter.length();
        int longerLength = longer.length();

        // 初始化：假设整个字符串都是差异部分
        int commonPrefixLength = 0;
        int shorterEndIndex = shorterLength;
        int longerEndIndex = longerLength;

        // 第一步：从头开始查找公共前缀
        for (int i = 1; i <= shorterLength; i++) {
            if (shorter.charAt(i - 1) != longer.charAt(i - 1)) {
                commonPrefixLength = i - 1;
                break;
            }
            // 如果循环结束都没有 break，说明 shorter 是 longer 的完整前缀
            commonPrefixLength = shorterLength;
        }

        // 第二步：从尾部开始查找公共后缀（仅在去除公共前缀后的部分中查找）
        for (int j = 1; j <= shorterLength - commonPrefixLength; j++) {
            if (shorter.charAt(shorterLength - j) != longer.charAt(longerLength - j)) {
                shorterEndIndex = shorterLength - j + 1;
                longerEndIndex = longerLength - j + 1;
                break;
            }
            // 如果循环结束都没有 break，说明去除前缀后的 shorter 部分完全匹配 longer 的相应后缀
            shorterEndIndex = commonPrefixLength;
            longerEndIndex = longerLength - shorterLength + commonPrefixLength;
        }

        // 返回两个字符串去除公共前后缀后的差异部分
        return new String[]{
            shorter.substring(commonPrefixLength, shorterEndIndex),
            longer.substring(commonPrefixLength, longerEndIndex)
        };
    }
}
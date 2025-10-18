/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql;

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

    public static double levenshtein(String str1, String str2) {
        int distance = LevenshteinDistance.getDefaultInstance().apply(str1, str2);
        return 1 - (double) distance / Math.max(str1.length(), str2.length());
    }
    public static double jaccard(String str1, String str2) {

        return new JaccardSimilarity().apply(str1, str2);
    }

    // 提取相似度计算公共逻辑
    private static List<Double> calculateSimilarity(
            String s1, String s2,
            String poc1, String poc2,
            boolean html_flag,
            BiFunction<String, String, Double> similarityFunc) {

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

        List<Double> list = new ArrayList<>();

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
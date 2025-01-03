/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql;

import burp.api.montoya.MontoyaApi;
import org.apache.commons.text.similarity.JaccardSimilarity;
import org.apache.commons.text.similarity.LevenshteinDistance;

import java.text.NumberFormat;
import java.util.*;

public class MyCompare {
    public static double calculateCosineSimilarity(String s1, String s2) {
        Map<Character, Integer> v1 = generateVector(s1);
        Map<Character, Integer> v2 = generateVector(s2);

        double dotProduct = 0.0;
        double norm1 = 0.0;
        double norm2 = 0.0;

        for (Character key : v1.keySet()) {
            if (v2.containsKey(key)) {
                dotProduct += v1.get(key) * v2.get(key);
            }
            norm1 += Math.pow(v1.get(key), 2);
        }

        for (Character key : v2.keySet()) {
            norm2 += Math.pow(v2.get(key), 2);
        }

        return dotProduct / (Math.sqrt(norm1) * Math.sqrt(norm2));
    }

    public static Map<Character, Integer> generateVector(String s) {
        Map<Character, Integer> vector = new HashMap<>();

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (vector.containsKey(c)) {
                vector.put(c, vector.get(c) + 1);
            } else {
                vector.put(c, 1);
            }
        }

        return vector;
    }

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


    public static double levenshteinx(String a, String b) {
        if (a == null && b == null) {
            return 1f;
        }
        if (a == null || b == null) {
            return 0F;
        }
        int editDistance = editDis(a, b);
        return 1 - ((double) editDistance / Math.max(a.length(), b.length()));
    }

    private static int editDis(String a, String b) {

        int aLen = a.length();
        int bLen = b.length();

        if (aLen == 0) return aLen;
        if (bLen == 0) return bLen;

        int[][] v = new int[aLen + 1][bLen + 1];
        for (int i = 0; i <= aLen; ++i) {
            for (int j = 0; j <= bLen; ++j) {
                if (i == 0) {
                    v[i][j] = j;
                } else if (j == 0) {
                    v[i][j] = i;
                } else if (a.charAt(i - 1) == b.charAt(j - 1)) {
                    v[i][j] = v[i - 1][j - 1];
                } else {
                    v[i][j] = 1 + Math.min(v[i - 1][j - 1], Math.min(v[i][j - 1], v[i - 1][j]));
                }
            }
        }
        return v[aLen][bLen];
    }

    public static double jaccardx(String str1, String str2) {
        Set<Character> s1 = new HashSet<>();//set元素不可重复
        Set<Character> s2 = new HashSet<>();

        for (int i = 0; i < str1.length(); i++) {
            s1.add(str1.charAt(i));//将string里面的元素一个一个按索引放进set集合
        }
        for (int j = 0; j < str2.length(); j++) {
            s2.add(str2.charAt(j));
        }

        float mergeNum = 0;//并集元素个数
        float commonNum = 0;//相同元素个数（交集）

        for (Character ch1 : s1) {
            for (Character ch2 : s2) {
                if (ch1.equals(ch2)) {
                    commonNum++;
                }
            }
        }

        mergeNum = s1.size() + s2.size() - commonNum;

        return commonNum / mergeNum;
    }

    public static double jaccard(String str1, String str2) {

        return new JaccardSimilarity().apply(str1, str2);
    }

    //SqlNum,SqlString使用
    public static List<Double> averageLevenshtein(String s1, String s2,String poc1,String poc2) {
        List<Double> list = new ArrayList<>();
        if (s1.length() == s2.length()) {
            list.add(1.0);
        } else if (s1.isEmpty() || s2.isEmpty()) {
            list.add(0.0);
        } else if (Math.abs(s1.length() - s2.length()) >= 100) {
            list.add(0.9);
//            double levenshtein = levenshtein(s1, s2);
//            list.add(levenshtein);
        } else if (s1.length()<s2.length()&&(s2.startsWith(s1)||s2.endsWith(s1))) {
            list.add(0.0);
        } else if (s2.length()<s1.length()&&(s1.startsWith(s2)||s1.endsWith(s2))) {
            list.add(0.0);
        } else {
            String[] newStrList;
            if(s1.length()<s2.length()){
                newStrList=upgradeStr(s1,s2);
                if ((newStrList[0].replaceAll(poc1,"").isEmpty()&&!newStrList[1].replaceAll(poc2,"").isEmpty())||(!newStrList[0].replaceAll(poc1,"").isEmpty()&&newStrList[1].replaceAll(poc2,"").isEmpty())){
                    list.add(0.0);
                } else if (newStrList[0].replaceAll(poc1,"").isEmpty()&&newStrList[1].replaceAll(poc2,"").isEmpty()) {
                    list.add(1.0);
                } else{
                    double levenshtein = levenshtein(newStrList[0], newStrList[1]);
                    list.add(levenshtein);
                }
            }else{
                newStrList=upgradeStr(s2,s1);
                if ((newStrList[0].replaceAll(poc2,"").isEmpty()&&!newStrList[1].replaceAll(poc1,"").isEmpty())||(!newStrList[0].replaceAll(poc2,"").isEmpty()&&newStrList[1].replaceAll(poc1,"").isEmpty())){
                    list.add(0.0);
                } else if (newStrList[0].replaceAll(poc2,"").isEmpty()&&newStrList[1].replaceAll(poc1,"").isEmpty()) {
                    list.add(1.0);
                } else{
                    double levenshtein = levenshtein(newStrList[0], newStrList[1]);
                    list.add(levenshtein);
                }
            }


        }
        return list;
    }

    //SqlOrder使用
    public static List<Double> averageJaccard(String s1, String s2,String poc1,String poc2) {
        List<Double> list = new ArrayList<>();
        if (s1.length() == s2.length()) {
            list.add(1.0);
        } else if (s1.isEmpty() || s2.isEmpty()) {
            list.add(0.0);
        } else if (Math.abs(s1.length() - s2.length()) >= 100) {
            list.add(0.9);
        } else if (s1.length()<s2.length()&&(s2.startsWith(s1)||s2.endsWith(s1))) {
            list.add(0.0);
        } else if (s2.length()<s1.length()&&(s1.startsWith(s2)||s1.endsWith(s2))) {
            list.add(0.0);
        } else {
            String[] newStrList;
            if(s1.length()<s2.length()){
                newStrList=upgradeStr(s1,s2);

                if ((newStrList[0].replaceAll(poc1,"").isEmpty()&&!newStrList[1].replaceAll(poc2,"").isEmpty())||(!newStrList[0].replaceAll(poc1,"").isEmpty()&&newStrList[1].replaceAll(poc2,"").isEmpty())){
                    list.add(0.0);
                } else if (newStrList[0].replaceAll(poc1,"").isEmpty()&&newStrList[1].replaceAll(poc2,"").isEmpty()) {
                    list.add(1.0);
                } else{
                    double jaccard = jaccard(newStrList[0], newStrList[1]);
                    list.add(jaccard);
                }
            }else{
                newStrList=upgradeStr(s2,s1);
                if ((newStrList[0].replaceAll(poc2,"").isEmpty()&&!newStrList[1].replaceAll(poc1,"").isEmpty())||(!newStrList[0].replaceAll(poc2,"").isEmpty()&&newStrList[1].replaceAll(poc1,"").isEmpty())){
                    list.add(0.0);
                } else if (newStrList[0].replaceAll(poc2,"").isEmpty()&&newStrList[1].replaceAll(poc1,"").isEmpty()) {
                    list.add(1.0);
                } else{
                    double jaccard = jaccard(newStrList[0], newStrList[1]);
                    list.add(jaccard);
                }
            }


        }
        return list;
    }

    public static List<Double> averageCosine(String s1, String s2) {
        List<Double> list = new ArrayList<>();
        double cosine = calculateCosineSimilarity(s1, s2);
        if (s1.length() == s2.length()) {
            list.add(1.0);
        } else if (s1.length() == 0 || s2.length() == 0) {
            list.add(0.0);
        } else {
            list.add(cosine);
        }
        list.add(1.0);
        return list;
    }
    public static String[] upgradeStr(String s1, String s2) {//s1比s2短
        int len1 = s1.length();
        int len2 = s2.length();
        int startIndex=0;
        int endIndex1=len1;
        int endIndex2=len2;
        for(int i=1;i<=len1;i++){
            if(s1.charAt(i-1)!=s2.charAt(i-1)){
                startIndex=i-1;
                break;
            }
            startIndex=len1;
        }
        for (int j = 1; j <=len1-startIndex ; j++) {
            if(s1.charAt(len1-j)!=s2.charAt(len2-j)){
                endIndex1=len1-j+1;
                endIndex2=len2-j+1;
                break;
            }
            endIndex1=startIndex;
            endIndex2=len2-len1+startIndex;
        }
        return new String[]{s1.substring(startIndex,endIndex1),s2.substring(startIndex,endIndex2)};
    }
}
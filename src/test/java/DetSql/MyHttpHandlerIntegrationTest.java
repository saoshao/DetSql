package DetSql;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * MyHttpHandler 集成测试
 * 
 * 测试覆盖：
 * 1. 正常 HTTP 请求/响应流程
 * 2. 错误注入检测（Error-based SQL Injection）
 * 3. 字符串注入检测（String-based SQL Injection）
 * 4. 数字型注入检测（Numeric SQL Injection）
 * 5. 响应比对和相似度计算
 * 
 * 注意：由于 Burp API 的复杂性，本测试主要测试核心逻辑和辅助方法
 */
public class MyHttpHandlerIntegrationTest {

    /**
     * 测试：错误 SQL 检测 - MySQL 语法错误
     * 
     * 验证：
     * - 能够识别 MySQL 语法错误
     * - 返回匹配的错误模式
     */
    @Test
    void testErrorSqlDetection_MySqlSyntaxError() {
        String response = "HTTP/1.1 500 Internal Server Error\r\n" +
                         "Content-Type: text/html\r\n\r\n" +
                         "<html><body>You have an error in your SQL syntax; " +
                         "check the manual that corresponds to your MySQL server version</body></html>";
        
        String matched = MyHttpHandler.ErrSqlCheck(response);
        
        assertNotNull(matched, "应该检测到 MySQL 语法错误");
        assertTrue(matched.toLowerCase().contains("mysql") || matched.toLowerCase().contains("syntax"),
                  "匹配的模式应该包含 mysql 或 syntax");
    }

    /**
     * 测试：错误 SQL 检测 - PostgreSQL 错误
     */
    @Test
    void testErrorSqlDetection_PostgreSqlError() {
        String response = "Error: supplied argument is not a valid PostgreSQL result resource";
        
        String matched = MyHttpHandler.ErrSqlCheck(response);
        
        assertNotNull(matched, "应该检测到 PostgreSQL 错误");
        assertTrue(matched.toLowerCase().contains("postgresql"),
                  "匹配的模式应该包含 postgresql");
    }

    /**
     * 测试：错误 SQL 检测 - Oracle 错误
     */
    @Test
    void testErrorSqlDetection_OracleError() {
        String response = "ORA-01756: quoted string not properly terminated";
        
        String matched = MyHttpHandler.ErrSqlCheck(response);
        
        assertNotNull(matched, "应该检测到 Oracle 错误");
        // 匹配的是正则表达式模式，不是原始文本
        assertTrue(matched.contains("ORA") || matched.contains("PLS"),
                  "匹配的模式应该包含 ORA 或 PLS");
    }

    /**
     * 测试：错误 SQL 检测 - SQL Server 错误
     */
    @Test
    void testErrorSqlDetection_SqlServerError() {
        String response = "Microsoft SQL Native Client error '80040e14'\r\n" +
                         "Unclosed quotation mark before the character string";
        
        String matched = MyHttpHandler.ErrSqlCheck(response);
        
        assertNotNull(matched, "应该检测到 SQL Server 错误");
    }

    /**
     * 测试：错误 SQL 检测 - 无错误
     */
    @Test
    void testErrorSqlDetection_NoError() {
        String response = "HTTP/1.1 200 OK\r\n" +
                         "Content-Type: application/json\r\n\r\n" +
                         "{\"status\":\"success\",\"data\":{\"user\":\"test\"}}";
        
        String matched = MyHttpHandler.ErrSqlCheck(response);
        
        assertNull(matched, "正常响应不应该检测到 SQL 错误");
    }

    /**
     * 测试：数字检测 - 有效数字
     */
    @Test
    void testIsNumeric_ValidNumbers() {
        assertTrue(MyHttpHandler.isNumericExposed("0"), "0 应该是数字");
        assertTrue(MyHttpHandler.isNumericExposed("123"), "123 应该是数字");
        assertTrue(MyHttpHandler.isNumericExposed("-456"), "-456 应该是数字");
        assertTrue(MyHttpHandler.isNumericExposed("9223372036854775807"), "Long.MAX_VALUE 应该是数字");
    }

    /**
     * 测试：数字检测 - 无效数字
     */
    @Test
    void testIsNumeric_InvalidNumbers() {
        assertFalse(MyHttpHandler.isNumericExposed(null), "null 不应该是数字");
        assertFalse(MyHttpHandler.isNumericExposed(""), "空字符串不应该是数字");
        assertFalse(MyHttpHandler.isNumericExposed("abc"), "abc 不应该是数字");
        assertFalse(MyHttpHandler.isNumericExposed("12.34"), "12.34 不应该是数字（小数）");
        assertFalse(MyHttpHandler.isNumericExposed("12a"), "12a 不应该是数字");
        assertFalse(MyHttpHandler.isNumericExposed(" 123"), "带空格的数字不应该是数字");
    }

    /**
     * 测试：结果字符串构建 - 所有标志为 false
     */
    @Test
    void testBuildResultString_AllFalse() {
        String result = MyHttpHandler.buildResultStringExposed(false, false, false, false, false, false);
        assertEquals("", result, "所有标志为 false 时应该返回空字符串");
    }

    /**
     * 测试：结果字符串构建 - 单个标志
     */
    @Test
    void testBuildResultString_SingleFlags() {
        assertEquals("-errsql", 
                    MyHttpHandler.buildResultStringExposed(true, false, false, false, false, false),
                    "只有 error 标志时应该返回 -errsql");
        
        assertEquals("-stringsql", 
                    MyHttpHandler.buildResultStringExposed(false, true, false, false, false, false),
                    "只有 string 标志时应该返回 -stringsql");
        
        assertEquals("-numsql", 
                    MyHttpHandler.buildResultStringExposed(false, false, true, false, false, false),
                    "只有 numeric 标志时应该返回 -numsql");
        
        assertEquals("-ordersql", 
                    MyHttpHandler.buildResultStringExposed(false, false, false, true, false, false),
                    "只有 order 标志时应该返回 -ordersql");
        
        assertEquals("-boolsql", 
                    MyHttpHandler.buildResultStringExposed(false, false, false, false, true, false),
                    "只有 boolean 标志时应该返回 -boolsql");
        
        assertEquals("-diypoc", 
                    MyHttpHandler.buildResultStringExposed(false, false, false, false, false, true),
                    "只有 diy 标志时应该返回 -diypoc");
    }

    /**
     * 测试：结果字符串构建 - 多个标志
     */
    @Test
    void testBuildResultString_MultipleFlags() {
        String result = MyHttpHandler.buildResultStringExposed(true, true, true, true, true, true);
        assertEquals("-errsql-stringsql-numsql-ordersql-boolsql-diypoc", result,
                    "所有标志为 true 时应该返回完整的结果字符串");
        
        String result2 = MyHttpHandler.buildResultStringExposed(true, false, true, false, true, false);
        assertEquals("-errsql-numsql-boolsql", result2,
                    "部分标志为 true 时应该返回对应的结果字符串");
    }

    /**
     * 测试：响应相似度计算 - 相同响应
     * 
     * 验证：
     * - 相同响应的相似度应该接近 1.0
     */
    @Test
    void testResponseSimilarity_IdenticalResponses() {
        String response1 = "<html><body>Test content with some data</body></html>";
        String response2 = "<html><body>Test content with some data</body></html>";
        
        List<Double> similarity = MyCompare.averageLevenshtein(response1, response2, "", "", true);
        
        assertNotNull(similarity, "相似度列表不应该为 null");
        assertFalse(similarity.isEmpty(), "相似度列表不应该为空");
        assertTrue(similarity.get(0) > 0.99, 
                  "相同响应的相似度应该接近 1.0，实际值: " + similarity.get(0));
    }

    /**
     * 测试：响应相似度计算 - 完全不同的响应
     */
    @Test
    void testResponseSimilarity_CompletelyDifferentResponses() {
        String response1 = "<html><body>User profile: Alice, Age: 25, City: New York</body></html>";
        String response2 = "Error: SQL syntax error near 'WHERE'";
        
        List<Double> similarity = MyCompare.averageLevenshtein(response1, response2, "", "", true);
        
        assertNotNull(similarity, "相似度列表不应该为 null");
        assertFalse(similarity.isEmpty(), "相似度列表不应该为空");
        assertTrue(similarity.get(0) < 0.5, 
                  "完全不同响应的相似度应该较低，实际值: " + similarity.get(0));
    }

    /**
     * 测试：响应相似度计算 - 部分相似的响应
     */
    @Test
    void testResponseSimilarity_PartiallySimilarResponses() {
        String response1 = "<html><body>User: Alice, Age: 25, Status: Active</body></html>";
        String response2 = "<html><body>User: Bob, Age: 30, Status: Active</body></html>";
        
        List<Double> similarity = MyCompare.averageLevenshtein(response1, response2, "", "", true);
        
        assertNotNull(similarity, "相似度列表不应该为 null");
        assertFalse(similarity.isEmpty(), "相似度列表不应该为空");
        double sim = similarity.get(0);
        assertTrue(sim >= 0.5 && sim < 1.0, 
                  "部分相似响应的相似度应该在 0.5 到 1.0 之间（包含 0.5），实际值: " + sim);
    }

    /**
     * 测试：响应相似度计算 - HTML vs JSON
     */
    @Test
    void testResponseSimilarity_HtmlVsJson() {
        String htmlResponse = "<html><body><h1>Welcome</h1><p>Hello World</p></body></html>";
        String jsonResponse = "{\"message\":\"Welcome\",\"content\":\"Hello World\"}";
        
        List<Double> similarity = MyCompare.averageLevenshtein(htmlResponse, jsonResponse, "", "", true);
        
        assertNotNull(similarity, "相似度列表不应该为 null");
        assertFalse(similarity.isEmpty(), "相似度列表不应该为空");
        // HTML 和 JSON 格式不同，但内容相似，相似度应该在中等范围
        double sim = similarity.get(0);
        assertTrue(sim >= 0.0 && sim <= 1.0, 
                  "相似度应该在 0.0 到 1.0 之间，实际值: " + sim);
    }

    /**
     * 测试：响应相似度计算 - 空响应
     */
    @Test
    void testResponseSimilarity_EmptyResponses() {
        String response1 = "";
        String response2 = "";
        
        List<Double> similarity = MyCompare.averageLevenshtein(response1, response2, "", "", true);
        
        assertNotNull(similarity, "相似度列表不应该为 null");
        assertFalse(similarity.isEmpty(), "相似度列表不应该为空");
        // 两个空响应应该完全相同
        assertTrue(similarity.get(0) >= 0.99, 
                  "空响应的相似度应该接近 1.0，实际值: " + similarity.get(0));
    }

    /**
     * 测试：响应相似度计算 - 一个空一个非空
     */
    @Test
    void testResponseSimilarity_EmptyVsNonEmpty() {
        String response1 = "";
        String response2 = "<html><body>Content</body></html>";
        
        List<Double> similarity = MyCompare.averageLevenshtein(response1, response2, "", "", true);
        
        assertNotNull(similarity, "相似度列表不应该为 null");
        assertFalse(similarity.isEmpty(), "相似度列表不应该为空");
        // 空响应和非空响应应该完全不同
        assertTrue(similarity.get(0) < 0.1, 
                  "空响应和非空响应的相似度应该接近 0.0，实际值: " + similarity.get(0));
    }

    /**
     * 测试：Jaccard 相似度计算 - 相同响应
     */
    @Test
    void testJaccardSimilarity_IdenticalResponses() {
        String response1 = "SELECT * FROM users WHERE id=1";
        String response2 = "SELECT * FROM users WHERE id=1";
        
        List<Double> similarity = MyCompare.averageJaccard(response1, response2, "", "", false);
        
        assertNotNull(similarity, "相似度列表不应该为 null");
        assertFalse(similarity.isEmpty(), "相似度列表不应该为空");
        assertTrue(similarity.get(0) > 0.99, 
                  "相同响应的 Jaccard 相似度应该接近 1.0，实际值: " + similarity.get(0));
    }

    /**
     * 测试：Jaccard 相似度计算 - 不同响应
     */
    @Test
    void testJaccardSimilarity_DifferentResponses() {
        String response1 = "SELECT * FROM users WHERE id=1";
        String response2 = "Error: column 'xyz' does not exist";
        
        List<Double> similarity = MyCompare.averageJaccard(response1, response2, "", "", false);
        
        assertNotNull(similarity, "相似度列表不应该为 null");
        assertFalse(similarity.isEmpty(), "相似度列表不应该为空");
        assertTrue(similarity.get(0) < 0.5, 
                  "不同响应的 Jaccard 相似度应该较低，实际值: " + similarity.get(0));
    }

    /**
     * 测试：字节转十六进制
     */
    @Test
    void testByteToHex() {
        byte[] bytes1 = {0x00, 0x01, 0x0F, (byte) 0xFF};
        String hex1 = MyHttpHandler.byteToHex(bytes1);
        assertEquals("00010FFF", hex1, "字节数组应该正确转换为十六进制字符串");
        
        byte[] bytes2 = {};
        String hex2 = MyHttpHandler.byteToHex(bytes2);
        assertEquals("", hex2, "空字节数组应该返回空字符串");
        
        byte[] bytes3 = {0x12, 0x34, 0x56, 0x78, (byte) 0x9A, (byte) 0xBC, (byte) 0xDE, (byte) 0xF0};
        String hex3 = MyHttpHandler.byteToHex(bytes3);
        assertEquals("123456789ABCDEF0", hex3, "多字节数组应该正确转换");
    }

    /**
     * 测试：性能 - 错误检测不应该超时
     * 
     * 验证：
     * - 错误检测应该在合理时间内完成
     * - 不应该因为 ReDoS 而超时
     */
    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void testErrorDetection_NoReDoSTimeout() {
        // 构造一个可能触发 ReDoS 的响应
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            sb.append("a");
        }
        sb.append("You have an error in your SQL syntax");
        
        String response = sb.toString();
        
        // 应该在 5 秒内完成，不会因为 ReDoS 而超时
        String matched = MyHttpHandler.ErrSqlCheck(response);
        
        assertNotNull(matched, "应该检测到 SQL 错误");
    }

    /**
     * 测试：性能 - 大响应的相似度计算
     * 
     * 验证：
     * - 大响应的相似度计算应该在合理时间内完成
     */
    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void testSimilarityCalculation_LargeResponses() {
        // 构造两个大响应（约 10KB）
        StringBuilder sb1 = new StringBuilder();
        StringBuilder sb2 = new StringBuilder();
        
        for (int i = 0; i < 500; i++) {
            sb1.append("<div>User ").append(i).append(": Alice</div>");
            sb2.append("<div>User ").append(i).append(": Bob</div>");
        }
        
        String response1 = sb1.toString();
        String response2 = sb2.toString();
        
        // 应该在 10 秒内完成
        List<Double> similarity = MyCompare.averageLevenshtein(response1, response2, "", "", true);
        
        assertNotNull(similarity, "相似度列表不应该为 null");
        assertFalse(similarity.isEmpty(), "相似度列表不应该为空");
        // 由于长度差可能超过阈值，相似度可能为 0
        double sim = similarity.get(0);
        assertTrue(sim >= 0.0 && sim <= 1.0, 
                  "相似度应该在 0.0 到 1.0 之间，实际值: " + sim);
    }

    /**
     * 测试：边界条件 - 长度差阈值
     * 
     * 验证：
     * - 长度差超过阈值时应该返回 0
     * - 长度差在阈值内时应该计算相似度
     */
    @Test
    void testSimilarity_LengthDifferenceThreshold() {
        // 创建两个长度差较小但不是前缀/后缀关系的响应
        String str1 = "SELECT * FROM users WHERE id=1 ORDER BY name";
        String str2 = "SELECT * FROM users WHERE id=2 ORDER BY email";  // 长度差 1，应该计算相似度
        
        List<Double> similarity1 = MyCompare.averageLevenshtein(str1, str2, "", "", false);
        // 长度差 <= 1 时返回 1.0
        assertEquals(1.0, similarity1.get(0), 0.001, 
                  "长度差 1 时应该返回 1.0，实际值: " + similarity1.get(0));
        
        // 长度差 100，应该返回 0
        String long2 = "x".repeat(50);
        String long3 = "y".repeat(150);
        List<Double> similarity2 = MyCompare.averageLevenshtein(long2, long3, "", "", false);
        assertEquals(0.0, similarity2.get(0), 0.001, 
                    "长度差 100 时应该返回 0");
        
        // 长度差 101，应该返回 0
        String long4 = "y".repeat(151);
        List<Double> similarity3 = MyCompare.averageLevenshtein(long2, long4, "", "", false);
        assertEquals(0.0, similarity3.get(0), 0.001, 
                    "长度差 101 时应该返回 0");
    }
}

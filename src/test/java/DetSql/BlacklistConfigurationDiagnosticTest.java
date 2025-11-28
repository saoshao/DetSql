/*
 * Diagnostic Test - 诊断用户配置问题
 *
 * 这个测试专门用于排查用户报告的域名黑名单不生效问题
 * 可能的原因:
 * 1. 输入格式问题 (空格、特殊字符等)
 * 2. 配置加载顺序问题
 * 3. 配置持久化问题
 *
 * @author DetSql Team
 */
package DetSql;

import org.junit.jupiter.api.*;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import DetSql.util.StringUtils;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class BlacklistConfigurationDiagnosticTest {

    @Test
    @Order(1)
    @DisplayName("诊断1 - parseDelimitedString 处理用户输入格式")
    public void testParseDelimitedStringWithVariousFormats() {
        // 测试用户可能输入的各种格式

        // 格式1: 纯逗号分隔
        String input1 = "datasink.baidu.com,s.union.360.cn,weixin.qq.com,www.google.com";
        Set<String> result1 = StringUtils.parseDelimitedString(input1);
        System.out.println("[诊断] 逗号分隔格式: " + input1);
        System.out.println("[诊断] 解析结果: " + result1);
        assertEquals(4, result1.size(), "应该解析出4个域名");
        assertTrue(result1.contains("datasink.baidu.com"));
        assertTrue(result1.contains("s.union.360.cn"));
        assertTrue(result1.contains("weixin.qq.com"));
        assertTrue(result1.contains("www.google.com"));

        // 格式2: 管道符分隔
        String input2 = "datasink.baidu.com|s.union.360.cn|weixin.qq.com|www.google.com";
        Set<String> result2 = StringUtils.parseDelimitedString(input2);
        System.out.println("[诊断] 管道符分隔格式: " + input2);
        System.out.println("[诊断] 解析结果: " + result2);
        assertEquals(4, result2.size());

        // 格式3: 带空格的逗号分隔
        String input3 = "datasink.baidu.com, s.union.360.cn, weixin.qq.com, www.google.com";
        Set<String> result3 = StringUtils.parseDelimitedString(input3);
        System.out.println("[诊断] 带空格逗号分隔格式: " + input3);
        System.out.println("[诊断] 解析结果: " + result3);
        assertEquals(4, result3.size(), "应该正确trim空格");
        assertTrue(result3.contains("datasink.baidu.com"), "应该不包含前导/尾随空格");

        // 格式4: 换行符分隔
        String input4 = "datasink.baidu.com\ns.union.360.cn\nweixin.qq.com\nwww.google.com";
        Set<String> result4 = StringUtils.parseDelimitedString(input4);
        System.out.println("[诊断] 换行符分隔格式: " + input4.replace("\n", "\\n"));
        System.out.println("[诊断] 解析结果: " + result4);
        assertEquals(4, result4.size());

        // 格式5: 混合分隔符
        String input5 = "datasink.baidu.com,s.union.360.cn|weixin.qq.com;www.google.com";
        Set<String> result5 = StringUtils.parseDelimitedString(input5);
        System.out.println("[诊断] 混合分隔符格式: " + input5);
        System.out.println("[诊断] 解析结果: " + result5);
        assertEquals(4, result5.size());
    }

    @Test
    @Order(2)
    @DisplayName("诊断2 - 检测常见的输入错误")
    public void testCommonInputMistakes() {
        // 错误1: 域名前后有多余空格
        String input1 = " datasink.baidu.com , s.union.360.cn ";
        Set<String> result1 = StringUtils.parseDelimitedString(input1);
        System.out.println("[诊断] 多余空格输入: '" + input1 + "'");
        System.out.println("[诊断] 解析结果: " + result1);
        assertEquals(2, result1.size());
        assertTrue(result1.contains("datasink.baidu.com"), "应该正确trim域名前后的空格");
        assertFalse(result1.contains(" datasink.baidu.com"), "不应该包含带空格的域名");

        // 错误2: 空行
        String input2 = "datasink.baidu.com\n\ns.union.360.cn";
        Set<String> result2 = StringUtils.parseDelimitedString(input2);
        System.out.println("[诊断] 包含空行: " + input2.replace("\n", "\\n"));
        System.out.println("[诊断] 解析结果: " + result2);
        assertEquals(2, result2.size(), "应该过滤掉空行");

        // 错误3: 末尾有分隔符
        String input3 = "datasink.baidu.com,s.union.360.cn,";
        Set<String> result3 = StringUtils.parseDelimitedString(input3);
        System.out.println("[诊断] 末尾分隔符: " + input3);
        System.out.println("[诊断] 解析结果: " + result3);
        assertEquals(2, result3.size(), "应该忽略末尾的空项");

        // 错误4: 重复域名
        String input4 = "datasink.baidu.com,datasink.baidu.com,s.union.360.cn";
        Set<String> result4 = StringUtils.parseDelimitedString(input4);
        System.out.println("[诊断] 重复域名: " + input4);
        System.out.println("[诊断] 解析结果: " + result4);
        assertEquals(2, result4.size(), "Set 应该自动去重");
    }

    @Test
    @Order(3)
    @DisplayName("诊断3 - 验证大小写处理")
    public void testCaseHandling() {
        // 输入时可能是大写
        String input = "datasink.baidu.com,S.UNION.360.CN";
        Set<String> result = StringUtils.parseDelimitedString(input);
        System.out.println("[诊断] 大写输入: " + input);
        System.out.println("[诊断] 解析结果: " + result);

        // 注意: parseDelimitedString 不做大小写转换，保留原样
        // 大小写匹配在 domainMatches() 中处理
        assertTrue(result.contains("datasink.baidu.com"), "应该保留原始大小写");
        assertEquals(2, result.size());
    }

    @Test
    @Order(4)
    @DisplayName("诊断4 - 边界情况测试")
    public void testEdgeCases() {
        // 空字符串
        Set<String> result1 = StringUtils.parseDelimitedString("");
        System.out.println("[诊断] 空字符串解析结果: " + result1);
        assertTrue(result1.isEmpty(), "空字符串应返回空集合");

        // null
        Set<String> result2 = StringUtils.parseDelimitedString(null);
        System.out.println("[诊断] null 解析结果: " + result2);
        assertTrue(result2.isEmpty(), "null 应返回空集合");

        // 只有空格
        Set<String> result3 = StringUtils.parseDelimitedString("   ");
        System.out.println("[诊断] 只有空格解析结果: " + result3);
        assertTrue(result3.isEmpty(), "只有空格应返回空集合");

        // 只有分隔符
        Set<String> result4 = StringUtils.parseDelimitedString(",,,");
        System.out.println("[诊断] 只有分隔符解析结果: " + result4);
        assertTrue(result4.isEmpty(), "只有分隔符应返回空集合");
    }

    @Test
    @Order(5)
    @DisplayName("诊断5 - 验证用户报告的实际配置")
    public void testActualUserConfiguration() {
        // 这是用户可能实际粘贴的配置
        String[] possibleUserInputs = {
            // 可能性1: 直接复制粘贴
            "datasink.baidu.com,s.union.360.cn,weixin.qq.com,www.google.com",

            // 可能性2: 从某处复制带空格
            "datasink.baidu.com, s.union.360.cn, weixin.qq.com, www.google.com",

            // 可能性3: 每行一个域名
            "datasink.baidu.com\ns.union.360.cn\nweixin.qq.com\nwww.google.com",

            // 可能性4: 使用管道符
            "datasink.baidu.com|s.union.360.cn|weixin.qq.com|www.google.com"
        };

        for (int i = 0; i < possibleUserInputs.length; i++) {
            String input = possibleUserInputs[i];
            Set<String> result = StringUtils.parseDelimitedString(input);

            System.out.println("\n[诊断] 用户输入可能性 " + (i + 1) + ":");
            System.out.println("  原始输入: " + input.replace("\n", "\\n"));
            System.out.println("  解析结果: " + result);
            System.out.println("  域名数量: " + result.size());

            // 验证4个域名都正确解析
            assertEquals(4, result.size(),
                "输入格式 " + (i + 1) + " 应该解析出4个域名");

            assertTrue(result.contains("datasink.baidu.com"),
                "应该包含 datasink.baidu.com");
            assertTrue(result.contains("s.union.360.cn"),
                "应该包含 s.union.360.cn");
            assertTrue(result.contains("weixin.qq.com"),
                "应该包含 weixin.qq.com");
            assertTrue(result.contains("www.google.com"),
                "应该包含 www.google.com");
        }
    }

    @Test
    @Order(6)
    @DisplayName("诊断6 - 检测不可见字符")
    public void testInvisibleCharacters() {
        // 可能从某些编辑器复制时带入不可见字符

        // 零宽空格 (U+200B)
        String input1 = "datasink.baidu.com\u200B,s.union.360.cn";
        Set<String> result1 = StringUtils.parseDelimitedString(input1);
        System.out.println("[诊断] 带零宽空格的输入");
        System.out.println("  解析结果: " + result1);
        System.out.println("  是否包含纯净域名: " + result1.contains("datasink.baidu.com"));

        // 如果包含零宽空格，域名会是 "datasink.baidu.com\u200B"
        // 这可能导致域名匹配失败
        if (!result1.contains("datasink.baidu.com")) {
            System.out.println("  [警告] 检测到零宽空格，可能导致匹配失败!");
            System.out.println("  实际域名: " + result1);
        }
    }

    @Test
    @Order(7)
    @DisplayName("诊断7 - 测试配置持久化场景")
    public void testConfigurationPersistence() {
        // 模拟配置保存和加载过程
        String originalInput = "datasink.baidu.com,s.union.360.cn,weixin.qq.com,www.google.com";

        // 第1步: 解析配置
        Set<String> blacklistSet = StringUtils.parseDelimitedString(originalInput);
        System.out.println("[诊断] 第1步 - 解析配置");
        System.out.println("  原始输入: " + originalInput);
        System.out.println("  解析结果: " + blacklistSet);
        assertEquals(4, blacklistSet.size());

        // 第2步: 模拟序列化（转为字符串存储）
        String serialized = String.join(",", blacklistSet);
        System.out.println("\n[诊断] 第2步 - 序列化");
        System.out.println("  序列化结果: " + serialized);

        // 第3步: 模拟反序列化（重新加载）
        Set<String> reloadedSet = StringUtils.parseDelimitedString(serialized);
        System.out.println("\n[诊断] 第3步 - 反序列化");
        System.out.println("  重新加载结果: " + reloadedSet);
        assertEquals(4, reloadedSet.size());

        // 第4步: 验证数据一致性
        System.out.println("\n[诊断] 第4步 - 验证一致性");
        for (String domain : blacklistSet) {
            assertTrue(reloadedSet.contains(domain),
                "重新加载后应该包含域名: " + domain);
            System.out.println("  ✓ " + domain + " 一致");
        }
    }
}

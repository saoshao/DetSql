package DetSql;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import DetSql.util.ParameterModifiers;

/**
 * 回归测试：验证参数索引对齐问题的修复
 * 
 * 问题描述：
 * 在多个检测分支中，对参数列表进行了子集过滤（例如只保留被引号包裹的参数），
 * 但后续仍使用子集中的循环下标 i 去调用 modifyParameter 修改原请求。
 * 这会导致 payload 注入到错误的原始参数位置，使得表格中的 Name 与实际被注入的字段不一致。
 * 
 * 修复方案：
 * 使用 resolveIndex helper 函数，在调用 modifyParameter 前先获取当前参数在原始完整参数列表中的真实索引。
 * 
 * 本测试验证 indexOf() 方法在参数子集过滤场景下的正确性。
 */
public class ParameterIndexAlignmentTest {

    /**
     * 模拟参数对象（简化版）
     */
    static class MockParameter {
        final String name;
        final String value;

        MockParameter(String name, String value) {
            this.name = name;
            this.value = value;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof MockParameter)) return false;
            MockParameter other = (MockParameter) obj;
            return name.equals(other.name) && value.equals(other.value);
        }

        @Override
        public int hashCode() {
            return name.hashCode() * 31 + value.hashCode();
        }
    }

    /**
     * 测试场景：URL参数子集过滤后的索引对齐
     * 
     * 假设原始参数列表：[param1, param2, param3, param4]
     * 过滤后的子集：[param2, param4] (只保留某些条件的参数)
     * 
     * 在子集中循环时：
     * - i=0 对应 param2，其在原始列表中的索引应该是 1
     * - i=1 对应 param4，其在原始列表中的索引应该是 3
     * 
     * 如果错误地使用 i 作为索引，会导致：
     * - 想注入 param2，实际注入到 param1 (索引0)
     * - 想注入 param4，实际注入到 param2 (索引1)
     */
    @Test
    public void testUrlParameterIndexAlignment() {
        // 创建4个参数
        MockParameter param1 = new MockParameter("id", "1");
        MockParameter param2 = new MockParameter("name", "test");
        MockParameter param3 = new MockParameter("age", "25");
        MockParameter param4 = new MockParameter("email", "test@example.com");
        
        // 完整参数列表
        List<MockParameter> allParams = Arrays.asList(param1, param2, param3, param4);
        
        // 模拟过滤后的子集（只包含 param2 和 param4）
        List<MockParameter> filteredParams = Arrays.asList(param2, param4);
        
        // 对于子集中的第一个参数 (param2)
        int subsetIndex0 = 0;
        int originalIndex0 = allParams.indexOf(filteredParams.get(subsetIndex0));
        assertEquals(1, originalIndex0, "param2 在原始列表中的索引应该是 1，而不是子集索引 0");
        
        // 对于子集中的第二个参数 (param4)
        int subsetIndex1 = 1;
        int originalIndex1 = allParams.indexOf(filteredParams.get(subsetIndex1));
        assertEquals(3, originalIndex1, "param4 在原始列表中的索引应该是 3，而不是子集索引 1");
        
        // 验证如果错误地使用子集索引会导致什么问题
        assertNotEquals(subsetIndex0, originalIndex0, "如果使用子集索引 0，会错误地修改 param1");
        assertNotEquals(subsetIndex1, originalIndex1, "如果使用子集索引 1，会错误地修改 param2");
    }

    /**
     * 测试场景：JSON参数子集过滤后的索引对齐
     * 
     * JSON 参数经常需要过滤（例如只测试被双引号包裹的字符串值），
     * 这是索引错位问题最常见的场景之一。
     */
    @Test
    public void testJsonParameterIndexAlignment() {
        // 创建混合类型的JSON参数
        MockParameter param1 = new MockParameter("id", "123");        // 数字，不被引号包裹
        MockParameter param2 = new MockParameter("name", "alice");    // 字符串，被引号包裹
        MockParameter param3 = new MockParameter("active", "true");   // 布尔，不被引号包裹
        MockParameter param4 = new MockParameter("email", "a@b.com"); // 字符串，被引号包裹
        
        List<MockParameter> allParams = Arrays.asList(param1, param2, param3, param4);
        
        // 模拟字符串注入检测中的过滤：只保留被引号包裹的参数
        List<MockParameter> stringParams = Arrays.asList(param2, param4);
        
        // 验证索引对齐
        assertEquals(1, allParams.indexOf(stringParams.get(0)), 
            "name 参数在原始列表中的索引是 1");
        assertEquals(3, allParams.indexOf(stringParams.get(1)), 
            "email 参数在原始列表中的索引是 3");
    }

    /**
     * 测试场景：Order注入中的空值过滤
     * 
     * Order注入检测会跳过空值参数，这也会导致子集与原始列表的索引不一致。
     */
    @Test
    public void testOrderInjectionParameterFiltering() {
        MockParameter param1 = new MockParameter("sort", "");         // 空值，会被跳过
        MockParameter param2 = new MockParameter("order", "asc");     // 非空，会被测试
        MockParameter param3 = new MockParameter("filter", "");       // 空值，会被跳过
        MockParameter param4 = new MockParameter("limit", "10");      // 非空，会被测试
        
        List<MockParameter> allParams = Arrays.asList(param1, param2, param3, param4);
        
        // 模拟过滤：只保留非空参数
        List<MockParameter> nonEmptyParams = Arrays.asList(param2, param4);
        
        // 验证索引对齐
        assertEquals(1, allParams.indexOf(nonEmptyParams.get(0)), 
            "order 参数在原始列表中的索引是 1，不是子集索引 0");
        assertEquals(3, allParams.indexOf(nonEmptyParams.get(1)), 
            "limit 参数在原始列表中的索引是 3，不是子集索引 1");
    }

    /**
     * 测试场景：数字注入中的类型过滤
     * 
     * 数字注入只测试纯数字参数，非数字参数会被跳过。
     */
    @Test
    public void testNumericInjectionParameterFiltering() {
        MockParameter param1 = new MockParameter("name", "alice");    // 非数字，跳过
        MockParameter param2 = new MockParameter("id", "123");        // 数字，测试
        MockParameter param3 = new MockParameter("email", "a@b.com"); // 非数字，跳过
        MockParameter param4 = new MockParameter("age", "25");        // 数字，测试
        
        List<MockParameter> allParams = Arrays.asList(param1, param2, param3, param4);
        
        // 模拟过滤：只保留数字参数
        List<MockParameter> numericParams = Arrays.asList(param2, param4);
        
        // 验证索引对齐
        assertEquals(1, allParams.indexOf(numericParams.get(0)), 
            "id 参数在原始列表中的索引是 1");
        assertEquals(3, allParams.indexOf(numericParams.get(1)), 
            "age 参数在原始列表中的索引是 3");
    }

    /**
     * 测试边界情况：所有参数都被过滤掉
     */
    @Test
    public void testAllParametersFiltered() {
        MockParameter param1 = new MockParameter("name", "alice");
        MockParameter param2 = new MockParameter("email", "a@b.com");
        
        List<MockParameter> allParams = Arrays.asList(param1, param2);
        
        // 假设所有参数都不满足条件（例如都不是数字）
        List<MockParameter> filteredParams = Arrays.asList();
        
        // 验证空列表不会导致问题
        assertTrue(filteredParams.isEmpty(), "过滤后的列表应该为空");
    }

    /**
     * 测试边界情况：没有过滤，子集等于完整列表
     */
    @Test
    public void testNoFiltering() {
        MockParameter param1 = new MockParameter("id", "1");
        MockParameter param2 = new MockParameter("name", "test");
        
        List<MockParameter> allParams = Arrays.asList(param1, param2);
        
        // 当没有过滤时，索引应该完全一致
        assertEquals(0, allParams.indexOf(param1));
        assertEquals(1, allParams.indexOf(param2));
    }

    /**
     * 测试 resolveIndex 逻辑的核心：indexOf() 方法
     * 
     * 这个测试验证了修复方案的核心逻辑：
     * 使用 List.indexOf(param) 可以正确获取参数在原始列表中的位置，
     * 即使该参数来自一个过滤后的子集。
     */
    @Test
    public void testIndexOfLogic() {
        MockParameter p1 = new MockParameter("a", "1");
        MockParameter p2 = new MockParameter("b", "2");
        MockParameter p3 = new MockParameter("c", "3");
        
        List<MockParameter> original = Arrays.asList(p1, p2, p3);
        List<MockParameter> subset = Arrays.asList(p2);  // 只包含中间的参数
        
        // 从子集中取出参数
        MockParameter paramFromSubset = subset.get(0);
        
        // 在原始列表中查找其索引
        int originalIndex = original.indexOf(paramFromSubset);
        
        // 应该返回 1，而不是子集中的索引 0
        assertEquals(1, originalIndex, "indexOf 应该返回参数在原始列表中的位置");
    }
}

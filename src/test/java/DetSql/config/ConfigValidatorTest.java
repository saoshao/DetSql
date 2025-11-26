/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql.config;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * ConfigValidator 单元测试
 * 验证配置验证器的正确性
 */
class ConfigValidatorTest {

    @Test
    void testValidConfigPasses() {
        // 创建有效的配置
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setDelaytime(3000);
        config.setStatictime(100);
        config.setStarttime(0);
        config.setEndtime(0);
        config.setLanguageindex(0);

        // 验证应该通过
        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertTrue(result.isValid(), "有效配置应该通过验证");
        assertTrue(result.getErrors().isEmpty(), "不应该有错误");
    }

    @Test
    void testNullConfigFails() {
        // null 配置应该失败
        ConfigValidator.ValidationResult result = ConfigValidator.validate(null);
        assertFalse(result.isValid(), "null 配置应该失败");
        assertEquals(1, result.getErrors().size());
        assertTrue(result.getErrorMessage().contains("null"));
    }

    @Test
    void testNegativeDelaytimeFails() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setDelaytime(-100);

        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertFalse(result.isValid(), "负数延迟时间应该失败");
        assertTrue(result.getErrorMessage().contains("delaytime"));
        assertTrue(result.getErrorMessage().contains("负数"));
    }

    @Test
    void testNegativeStatictimeFails() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setStatictime(-50);

        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("statictime"));
    }

    @Test
    void testNegativeStarttimeFails() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setStarttime(-1000);

        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("starttime"));
    }

    @Test
    void testNegativeEndtimeFails() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setEndtime(-2000);

        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("endtime"));
    }

    @Test
    void testInvalidLanguageIndexFails() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setLanguageindex(-1);

        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("语言索引"));

        // 测试超出范围
        config.setLanguageindex(2);
        result = ConfigValidator.validate(config);
        assertFalse(result.isValid());
    }

    @Test
    void testValidLanguageIndexPasses() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();

        // 0 应该有效
        config.setLanguageindex(0);
        assertTrue(ConfigValidator.validate(config).isValid());

        // 1 应该有效
        config.setLanguageindex(1);
        assertTrue(ConfigValidator.validate(config).isValid());
    }

    @Test
    void testInvalidTimeRangeFails() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setStarttime(5000);
        config.setEndtime(3000); // 结束时间小于开始时间

        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("开始时间不能大于结束时间"));
    }

    @Test
    void testValidTimeRangePasses() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setStarttime(3000);
        config.setEndtime(5000);

        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertTrue(result.isValid());
    }

    @Test
    void testInvalidRegexFails() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setDiyregex("[invalid regex("); // 无效的正则表达式

        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("无效的正则表达式"));
    }

    @Test
    void testValidRegexPasses() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setDiyregex("\\d+\n[a-z]+\n.*test.*"); // 有效的正则表达式

        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertTrue(result.isValid());
    }

    @Test
    void testEmptyRegexPasses() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setDiyregex("");

        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertTrue(result.isValid());
    }

    @Test
    void testMultipleErrorsReported() {
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setDelaytime(-100);
        config.setStatictime(-50);
        config.setLanguageindex(5);

        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertFalse(result.isValid());
        assertEquals(3, result.getErrors().size(), "应该报告3个错误");
    }

    @Test
    void testZeroDelayTimeIsValid() {
        // 0 延迟时间应该是有效的 (表示无延迟)
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setDelaytime(0);

        ConfigValidator.ValidationResult result = ConfigValidator.validate(config);
        assertTrue(result.isValid(), "0 延迟时间应该是有效的");
    }

    @Test
    void testValidationResultToString() {
        ConfigValidator.ValidationResult validResult = ConfigValidator.ValidationResult.valid();
        assertTrue(validResult.toString().contains("valid=true"));

        ConfigValidator.ValidationResult invalidResult = ConfigValidator.ValidationResult.invalid("test error");
        assertTrue(invalidResult.toString().contains("valid=false"));
        assertTrue(invalidResult.toString().contains("test error"));
    }
}

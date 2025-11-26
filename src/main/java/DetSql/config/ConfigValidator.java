/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql.config;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 配置验证器
 * 验证配置值的有效性,防止无效配置导致运行时异常
 */
public class ConfigValidator {

    /**
     * 验证配置对象
     * 
     * @param config 待验证的配置对象
     * @return 验证结果
     */
    public static ValidationResult validate(DetSqlYamlConfig config) {
        if (config == null) {
            return ValidationResult.invalid("配置对象不能为 null");
        }

        List<String> errors = new ArrayList<>();

        // 验证时间配置
        validateTimeConfig(config, errors);

        // 验证语言索引
        validateLanguageIndex(config, errors);

        // 验证正则表达式
        validateRegex(config, errors);

        return errors.isEmpty()
                ? ValidationResult.valid()
                : ValidationResult.invalid(errors);
    }

    /**
     * 验证时间配置
     */
    private static void validateTimeConfig(DetSqlYamlConfig config, List<String> errors) {
        if (config.getDelaytime() < 0) {
            errors.add("延迟时间 (delaytime) 不能为负数: " + config.getDelaytime());
        }

        if (config.getStatictime() < 0) {
            errors.add("固定间隔 (statictime) 不能为负数: " + config.getStatictime());
        }

        if (config.getStarttime() < 0) {
            errors.add("开始时间 (starttime) 不能为负数: " + config.getStarttime());
        }

        if (config.getEndtime() < 0) {
            errors.add("结束时间 (endtime) 不能为负数: " + config.getEndtime());
        }

        // 验证时间范围的逻辑性
        if (config.getStarttime() > 0 && config.getEndtime() > 0
                && config.getStarttime() > config.getEndtime()) {
            errors.add("开始时间不能大于结束时间: starttime="
                    + config.getStarttime() + ", endtime=" + config.getEndtime());
        }
    }

    /**
     * 验证语言索引
     */
    private static void validateLanguageIndex(DetSqlYamlConfig config, List<String> errors) {
        int languageIndex = config.getLanguageindex();
        if (languageIndex < 0 || languageIndex > 1) {
            errors.add("语言索引必须在 [0, 1] 范围内: " + languageIndex);
        }
    }

    /**
     * 验证正则表达式
     */
    private static void validateRegex(DetSqlYamlConfig config, List<String> errors) {
        String diyregex = config.getDiyregex();
        if (diyregex != null && !diyregex.trim().isEmpty()) {
            // 按行分割正则表达式
            String[] regexLines = diyregex.split("\\r?\\n");
            for (int i = 0; i < regexLines.length; i++) {
                String regex = regexLines[i].trim();
                if (!regex.isEmpty()) {
                    try {
                        Pattern.compile(regex);
                    } catch (PatternSyntaxException e) {
                        errors.add("无效的正则表达式 (第 " + (i + 1) + " 行): "
                                + regex + " - " + e.getMessage());
                    }
                }
            }
        }
    }

    /**
     * 验证结果类
     */
    public static class ValidationResult {
        private final boolean valid;
        private final List<String> errors;

        private ValidationResult(boolean valid, List<String> errors) {
            this.valid = valid;
            this.errors = errors != null ? errors : new ArrayList<>();
        }

        public static ValidationResult valid() {
            return new ValidationResult(true, new ArrayList<>());
        }

        public static ValidationResult invalid(String error) {
            List<String> errors = new ArrayList<>();
            errors.add(error);
            return new ValidationResult(false, errors);
        }

        public static ValidationResult invalid(List<String> errors) {
            return new ValidationResult(false, errors);
        }

        public boolean isValid() {
            return valid;
        }

        public List<String> getErrors() {
            return new ArrayList<>(errors);
        }

        public String getErrorMessage() {
            if (errors.isEmpty()) {
                return "";
            }
            return String.join("; ", errors);
        }

        @Override
        public String toString() {
            if (valid) {
                return "ValidationResult{valid=true}";
            }
            return "ValidationResult{valid=false, errors=" + errors + "}";
        }
    }
}

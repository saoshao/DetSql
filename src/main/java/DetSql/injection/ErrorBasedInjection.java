/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import DetSql.config.DetSqlConfig;
import DetSql.logging.DetSqlLogger;
import DetSql.model.PocLogEntry;
import DetSql.ui.DetSqlUI;
import DetSql.util.MyCompare;
import DetSql.util.ParameterModifiers;
import DetSql.util.RegexUtils;
import DetSql.util.Statistics;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.Arrays;
import DetSql.util.ParameterModifier;

/**
 * 错误注入策略
 * 通过注入特殊字符触发 SQL 错误信息
 */
public class ErrorBasedInjection extends AbstractInjectionStrategy {

    private static final String VULN_TYPE = "errsql";
    private final DetSqlUI ui;

    private final List<Pattern> compiledErrorPatterns;
    private static final Pattern NEWLINE_PATTERN = Pattern.compile("\\n|\\r|\\r\\n");

    public ErrorBasedInjection(
            MontoyaApi api,
            DetSqlConfig config,
            DetSqlLogger logger,
            Statistics statistics,
            Map<String, List<PocLogEntry>> attackMap,
            DetSqlUI ui) {
        super(api, config, logger, statistics, attackMap);
        this.ui = ui;

        // 从配置读取错误检测规则并编译为正则模式
        String[] rules = config.getErrorDetectionRules();
        this.compiledErrorPatterns = Arrays.stream(rules)
                .map(rule -> Pattern.compile(rule, Pattern.CASE_INSENSITIVE))
                .collect(Collectors.toList());
    }

    @Override
    public String getName() {
        return "Error-Based";
    }

    @Override
    public String getVulnType() {
        return VULN_TYPE;
    }

    @Override
    public boolean isEnabled() {
        return ui.isErrorCheckSelected();
    }

    @Override
    public boolean testParameter(
            HttpRequest sourceRequest,
            String sourceBody,
            boolean htmlFlag,
            ParsedHttpParameter param,
            ParameterModifier modifier,
            String requestHash) throws InterruptedException {

        checkInterrupted();

        String paramName = param.name();
        if (shouldSkipParameter(paramName)) {
            return false;
        }

        boolean foundVuln = false;
        String[] payloads = config.getErrorPayloads();

        for (String payload : payloads) {
            HttpRequest pocRequest = modifier.modifyParameter(sourceRequest, param, payload, 0);
            HttpRequestResponse pocResponse = sendHttpRequest(pocRequest, 2);
            String responseBody = extractResponseBody(pocResponse);

            String matchedRule = checkErrorPattern(responseBody);
            if (matchedRule != null) {
                PocLogEntry logEntry = PocLogEntry.fromResponse(
                        paramName, payload, null,
                        VULN_TYPE + "(" + matchedRule + ")",
                        pocResponse, requestHash);
                addPocEntry(requestHash, logEntry);
                foundVuln = true;
            }
        }

        return foundVuln;
    }

    /**
     * 检查响应中是否包含 SQL 错误信息
     */
    private String checkErrorPattern(String text) {
        String cleanedText = NEWLINE_PATTERN.matcher(text).replaceAll("");
        for (Pattern pattern : compiledErrorPatterns) {
            if (RegexUtils.safeMatchPrecompiled(pattern, cleanedText)) {
                return pattern.pattern();
            }
        }
        return null;
    }
}

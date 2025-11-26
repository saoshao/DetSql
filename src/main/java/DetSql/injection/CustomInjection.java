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
import DetSql.util.ParameterModifier;


/**
 * 自定义注入策略（DIY）
 * 支持 regex 匹配和 time 延迟两种检测方式
 */
public class CustomInjection extends AbstractInjectionStrategy {
    
    private static final String VULN_TYPE = "diypoc";
    private final DetSqlUI ui;
    
    public CustomInjection(
        MontoyaApi api,
        DetSqlConfig config,
        DetSqlLogger logger,
        Statistics statistics,
        Map<String, List<PocLogEntry>> attackMap,
        DetSqlUI ui
    ) {
        super(api, config, logger, statistics, attackMap);
        this.ui = ui;
    }
    
    @Override
    public String getName() {
        return "Custom (DIY)";
    }
    
    @Override
    public String getVulnType() {
        return VULN_TYPE;
    }
    
    @Override
    public boolean isEnabled() {
        return ui.isDiyCheckSelected()
            && !config.getDiyPayloads().isEmpty()
            && (config.getDelayTimeMs() > 0 || !config.getDiyRegexs().isEmpty());
    }
    
    @Override
    public boolean testParameter(
        HttpRequest sourceRequest,
        String sourceBody,
        boolean htmlFlag,
        ParsedHttpParameter param,
        ParameterModifier modifier,
        String requestHash
    ) throws InterruptedException {
        
        checkInterrupted();
        
        String paramName = param.name();
        if (shouldSkipParameter(paramName)) {
            return false;
        }
        
        boolean foundVuln = false;
        
        // 测试所有 DIY Payload
        for (String payload : config.getDiyPayloads()) {
            HttpRequest pocRequest = modifier.modifyParameter(sourceRequest, param, payload, 0);
            HttpRequestResponse pocResponse = sendHttpRequest(pocRequest, 2);
            String responseBody = extractResponseBody(pocResponse);
            
            // 检测方式 1: Regex 匹配
            if (!config.getDiyRegexs().isEmpty()) {
                String matchedRegex = checkRegexMatch(responseBody);
                if (matchedRegex != null) {
                    addPocEntry(requestHash, PocLogEntry.fromResponse(
                        paramName, payload, null,
                        VULN_TYPE + "(" + matchedRegex + ")",
                        pocResponse, requestHash
                    ));
                    foundVuln = true;
                }
            }
            
            // 检测方式 2: Time 延迟
            if (config.getDelayTimeMs() > 0) {
                long responseTime = pocResponse.timingData()
                    .map(timing -> timing.timeBetweenRequestSentAndEndOfResponse().toMillis())
                    .orElse(0L);
                if (responseTime > config.getDelayTimeMs()) {
                    addPocEntry(requestHash, PocLogEntry.fromResponse(
                        paramName, payload, null,
                        VULN_TYPE + "(time)",
                        pocResponse, requestHash
                    ));
                    foundVuln = true;
                }
            }
        }
        
        return foundVuln;
    }
    
    /**
     * 检查响应中是否匹配自定义正则表达式
     */
    private String checkRegexMatch(String text) {
        String cleanedText = text.replaceAll("\\n|\\r|\\r\\n", "");
        for (String pattern : config.getDiyRegexs()) {
            if (RegexUtils.safeMatch(pattern, cleanedText)) {
                return pattern;
            }
        }
        return null;
    }
}

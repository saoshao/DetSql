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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import DetSql.util.ParameterModifier;


/**
 * 数字注入策略
 * 
 * 检测逻辑（2 步）：
 * 1. value-0-0-0 - 期望与原始响应相似（有效算术）
 * 2. value-abc - 期望与原始和步骤 1 都不相似（无效算术）
 */
public class NumericInjection extends AbstractInjectionStrategy {
    
    private static final String VULN_TYPE = "numsql";
    private final DetSqlUI ui;
    
    public NumericInjection(
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
        return "Numeric";
    }
    
    @Override
    public String getVulnType() {
        return VULN_TYPE;
    }
    
    @Override
    public boolean isEnabled() {
        return ui.isNumCheckSelected();
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
        String paramValue = param.value();
        
        if (shouldSkipParameter(paramName)) {
            return false;
        }
        
        // 检查是否为纯数字参数
        if (!isNumeric(paramValue)) {
            return false;
        }
        
        List<PocLogEntry> pocEntries = new ArrayList<>();
        
        // 测试 1: value-0-0-0 - 期望与原始响应相似
        String payload1 = "-0-0-0";
        HttpRequest req1 = modifier.modifyParameter(sourceRequest, param, payload1, 0);
        HttpRequestResponse resp1 = sendHttpRequest(req1, 2);
        String body1 = extractResponseBody(resp1);
        
        List<Double> sim1 = MyCompare.averageLevenshtein(sourceBody, body1, "", payload1, htmlFlag);
        double maxSim1 = Collections.max(sim1);
        
        if (maxSim1 <= config.getSimilarityThreshold()) {
            return false; // 测试失败，跳过此参数
        }
        
        pocEntries.add(PocLogEntry.fromResponse(
            paramName, payload1, MyCompare.formatPercent(maxSim1),
            VULN_TYPE, resp1, requestHash
        ));
        
        // 测试 2: value-abc - 期望与原始响应和测试 1 响应都不相似
        String payload2 = "-abc";
        HttpRequest req2 = modifier.modifyParameter(sourceRequest, param, payload2, 0);
        HttpRequestResponse resp2 = sendHttpRequest(req2, 2);
        String body2 = extractResponseBody(resp2);
        
        // 检查与原始响应的相似度
        List<Double> sim2Source = MyCompare.averageLevenshtein(sourceBody, body2, "", "-abc", htmlFlag);
        double minSim2Source = Collections.min(sim2Source);
        
        if (minSim2Source > config.getSimilarityThreshold()) {
            return false; // 测试失败，跳过此参数
        }
        
        pocEntries.add(PocLogEntry.fromResponse(
            paramName, payload2, MyCompare.formatPercent(minSim2Source),
            VULN_TYPE, resp2, requestHash
        ));
        
        // 检查与测试 1 响应的相似度
        List<Double> sim2First = MyCompare.averageLevenshtein(body1, body2, "0-0-0", "abc", htmlFlag);
        double minSim2First = Collections.min(sim2First);
        
        if (minSim2First <= config.getSimilarityThreshold()) {
            getAttackList(requestHash).addAll(pocEntries);
            return true;
        }
        
        return false;
    }
    
    /**
     * 检查字符串是否为纯数字
     */
    private boolean isNumeric(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        try {
            Long.parseLong(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}

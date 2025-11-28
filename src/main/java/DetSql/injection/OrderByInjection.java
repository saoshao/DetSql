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
 * ORDER BY 注入策略
 * 
 * 检测逻辑（4 步）：
 * 1. value,0 - 期望与原始不相似（无效列索引）
 * 2. value,xxxxxx - 期望与原始不相似（无效列名）
 * 3. 验证步骤 1 和 2 相似（都是错误响应）
 * 4. value,1 或 value,2 - 期望与原始相似（有效列索引）
 */
public class OrderByInjection extends AbstractInjectionStrategy {
    
    private static final String VULN_TYPE = "ordersql";
    private final DetSqlUI ui;
    
    public OrderByInjection(
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
        return "Order By";
    }
    
    @Override
    public String getVulnType() {
        return VULN_TYPE;
    }
    
    @Override
    public boolean isEnabled() {
        return ui.isOrderCheckSelected();
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
        
        // 跳过空值参数
        if (paramValue.isBlank()) {
            return false;
        }
        
        List<PocLogEntry> pocEntries = new ArrayList<>();
        
        // 测试 1: value,0 - 期望与原始响应不相似（无效列索引）
        HttpRequest req1 = modifier.modifyParameter(sourceRequest, param, ",0", 0);
        HttpRequestResponse resp1 = sendHttpRequest(req1, 2);
        String body1 = extractResponseBody(resp1);
        
        List<Double> sim1 = MyCompare.averageJaccard(sourceBody, body1, "", "", htmlFlag);
        double minSim1 = Collections.min(sim1);
        
        if (minSim1 > config.getSimilarityThreshold()) {
            return false; // 测试失败，跳过此参数
        }
        
        pocEntries.add(PocLogEntry.fromResponse(
            paramName, ",0", MyCompare.formatPercent(minSim1),
            VULN_TYPE, resp1, requestHash
        ));
        
        // 测试 2: value,xxxxxx - 期望与原始响应不相似（无效列名）
        HttpRequest req2 = modifier.modifyParameter(sourceRequest, param, ",XXXXXX", 0);
        HttpRequestResponse resp2 = sendHttpRequest(req2, 2);
        String body2 = extractResponseBody(resp2);
        
        List<Double> sim2 = MyCompare.averageJaccard(sourceBody, body2, "", "", htmlFlag);
        double minSim2 = Collections.min(sim2);
        
        if (minSim2 > config.getSimilarityThreshold()) {
            return false; // 测试失败，跳过此参数
        }
        
        pocEntries.add(PocLogEntry.fromResponse(
            paramName, ",XXXXXX", MyCompare.formatPercent(minSim2),
            VULN_TYPE, resp2, requestHash
        ));
        
        // 测试 3: 验证两个无效输入响应相似（都是错误响应）
        List<Double> sim3 = MyCompare.averageJaccard(body1, body2, "", "", htmlFlag);
        double maxSim3 = Collections.max(sim3);
        
        if (maxSim3 <= config.getSimilarityThreshold()) {
            return false; // 测试失败，两个错误响应应该相似
        }
        
        // 测试 4a: value,1 - 期望与原始响应相似（有效列索引）
        HttpRequest req4a = modifier.modifyParameter(sourceRequest, param, ",1", 0);
        HttpRequestResponse resp4a = sendHttpRequest(req4a, 2);
        String body4a = extractResponseBody(resp4a);
        
        List<Double> sim4a = MyCompare.averageJaccard(sourceBody, body4a, "", "", htmlFlag);
        double maxSim4a = Collections.max(sim4a);
        
        // 同时检查 ,1 与 ,0 不相似（避免所有响应都相同的情况）
        List<Double> sim4aVs1 = MyCompare.averageJaccard(body1, body4a, "", "", htmlFlag);
        double minSim4aVs1 = Collections.min(sim4aVs1);
        
        if (maxSim4a > config.getSimilarityThreshold() && minSim4aVs1 <= config.getSimilarityThreshold()) {
            // 成功：,1 与原始相似，且与 ,0 不相似
            pocEntries.add(PocLogEntry.fromResponse(
                paramName, ",1", MyCompare.formatPercent(maxSim4a),
                VULN_TYPE, resp4a, requestHash
            ));
            getAttackList(requestHash).addAll(pocEntries);
            return true;
        }
        
        // 测试 4b: value,2 - 备选测试（另一个有效列索引）
        HttpRequest req4b = modifier.modifyParameter(sourceRequest, param, ",2", 0);
        HttpRequestResponse resp4b = sendHttpRequest(req4b, 2);
        String body4b = extractResponseBody(resp4b);
        
        List<Double> sim4b = MyCompare.averageJaccard(sourceBody, body4b, "", "", htmlFlag);
        double maxSim4b = Collections.max(sim4b);
        
        // 同时检查 ,2 与 ,0 不相似
        List<Double> sim4bVs1 = MyCompare.averageJaccard(body1, body4b, "", "", htmlFlag);
        double minSim4bVs1 = Collections.min(sim4bVs1);
        
        if (maxSim4b > config.getSimilarityThreshold() && minSim4bVs1 <= config.getSimilarityThreshold()) {
            // 成功：,2 与原始相似，且与 ,0 不相似
            pocEntries.add(PocLogEntry.fromResponse(
                paramName, ",2", MyCompare.formatPercent(maxSim4b),
                VULN_TYPE, resp4b, requestHash
            ));
            getAttackList(requestHash).addAll(pocEntries);
            return true;
        }
        
        return false;
    }
}

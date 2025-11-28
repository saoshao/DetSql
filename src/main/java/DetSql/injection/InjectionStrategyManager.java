/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import DetSql.config.DetSqlConfig;
import DetSql.logging.DetSqlLogger;
import DetSql.model.PocLogEntry;
import DetSql.util.Statistics;
import DetSql.ui.DetSqlUI;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import DetSql.util.ParameterModifier;


/**
 * 注入策略管理器
 * 统一管理所有注入策略，提供统一的测试接口
 */
public class InjectionStrategyManager {
    
    
    private final List<InjectionStrategy> strategies;
    private final DetSqlLogger logger;
    private final Statistics statistics;
    
    public InjectionStrategyManager(
        MontoyaApi api,
        DetSqlConfig config,
        DetSqlLogger logger,
        Statistics statistics,
        Map<String, List<PocLogEntry>> attackMap,
        DetSqlUI ui
    ) {
        this.logger = logger;
        this.statistics = statistics;
        this.strategies = new ArrayList<>();
        
        // 按照检测顺序添加策略
        // 1. 错误注入（最快，最明显）
        strategies.add(new ErrorBasedInjection(api, config, logger, statistics, attackMap, ui));
        
        // 2. 自定义注入（用户配置的特定检测）
        strategies.add(new CustomInjection(api, config, logger, statistics, attackMap, ui));
        
        // 3. 字符串注入（常见类型）
        strategies.add(new StringInjection(api, config, logger, statistics, attackMap, ui));
        
        // 4. 数字注入（需要参数为数字）
        strategies.add(new NumericInjection(api, config, logger, statistics, attackMap, ui));
        
        // 5. ORDER BY 注入（特定场景）
        strategies.add(new OrderByInjection(api, config, logger, statistics, attackMap, ui));
        
        // 6. 布尔注入（最慢，最复杂）
        strategies.add(new BooleanInjection(api, config, logger, statistics, attackMap, ui));
        
        logger.info("注入策略管理器初始化完成，共加载 " + strategies.size() + " 个策略");
    }
    
    /**
     * 测试单个参数的所有启用策略
     * 
     * @param sourceRequest 原始请求
     * @param sourceBody 原始响应体
     * @param htmlFlag 是否为 HTML 响应
     * @param param 要测试的参数
     * @param modifier 参数修改器
     * @param requestHash 请求哈希
     * @return 检测到的漏洞类型列表
     * @throws InterruptedException 线程中断异常
     */
    public List<String> testParameter(
        HttpRequest sourceRequest,
        String sourceBody,
        boolean htmlFlag,
        ParsedHttpParameter param,
        ParameterModifier modifier,
        String requestHash
    ) throws InterruptedException {
        
        List<String> detectedVulns = new ArrayList<>();
        
        for (InjectionStrategy strategy : strategies) {
            // 跳过未启用的策略
            if (!strategy.isEnabled()) {
                continue;
            }
            
            try {
                // 直接调用策略,移除 Future 包装以避免单线程瓶颈
                // 策略已在 SCAN_EXECUTOR 线程池中执行,无需额外包装
                boolean found = strategy.testParameter(
                    sourceRequest, sourceBody, htmlFlag,
                    param, modifier, requestHash
                );

                if (found) {
                    detectedVulns.add(strategy.getVulnType());
                    logger.debug("策略 [" + strategy.getName() + "] 在参数 [" + param.name() + "] 中检测到漏洞");
                }
            } catch (InterruptedException e) {
                // 重新抛出中断异常
                throw e;
            } catch (Exception e) {
                logger.error("策略 [" + strategy.getName() + "] 执行失败: " + e.getMessage(), e);
            }
        }
        
        return detectedVulns;
    }
    
    /**
     * 测试参数列表的所有启用策略
     * 
     * @param sourceRequest 原始请求
     * @param sourceBody 原始响应体
     * @param htmlFlag 是否为 HTML 响应
     * @param params 要测试的参数列表
     * @param modifier 参数修改器
     * @param requestHash 请求哈希
     * @return 是否检测到任何漏洞
     * @throws InterruptedException 线程中断异常
     */
    public boolean testParameters(
        HttpRequest sourceRequest,
        String sourceBody,
        boolean htmlFlag,
        List<ParsedHttpParameter> params,
        ParameterModifier modifier,
        String requestHash
    ) throws InterruptedException {
        
        boolean foundAny = false;
        
        for (ParsedHttpParameter param : params) {
            List<String> vulns = testParameter(
                sourceRequest, sourceBody, htmlFlag,
                param, modifier, requestHash
            );
            
            if (!vulns.isEmpty()) {
                foundAny = true;
            }
        }
        
        return foundAny;
    }
    
    /**
     * 获取所有启用的策略数量
     */
    public int getEnabledStrategyCount() {
        return (int) strategies.stream()
            .filter(InjectionStrategy::isEnabled)
            .count();
    }
    
    /**
     * 获取所有策略列表
     */
    public List<InjectionStrategy> getStrategies() {
        return new ArrayList<>(strategies);
    }
    
    /**
     * 关闭策略管理器，释放资源
     * 注：移除了 executor 后此方法保留为空实现，以保持 API 兼容性
     */
    public void shutdown() {
        // 不再需要关闭 executor（已移除）
        logger.debug("策略管理器关闭");
    }
}

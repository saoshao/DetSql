/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.injection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import DetSql.util.ParameterModifier;

import java.util.List;

/**
 * 注入策略接口
 * 定义了 SQL 注入测试的通用流程
 */
public interface InjectionStrategy {
    
    /**
     * 获取策略名称（用于日志和漏洞类型标识）
     */
    String getName();
    
    /**
     * 获取漏洞类型标识符
     */
    String getVulnType();
    
    /**
     * 检测是否启用此策略
     */
    boolean isEnabled();
    
    /**
     * 测试单个参数是否存在注入漏洞
     * 
     * @param sourceRequest 原始请求
     * @param sourceBody 原始响应体
     * @param htmlFlag 是否为 HTML 响应
     * @param param 要测试的参数
     * @param modifier 参数修改器
     * @param requestHash 请求哈希
     * @return 是否发现漏洞
     * @throws InterruptedException 线程中断异常
     */
    boolean testParameter(
        HttpRequest sourceRequest,
        String sourceBody,
        boolean htmlFlag,
        ParsedHttpParameter param,
        ParameterModifier modifier,
        String requestHash
    ) throws InterruptedException;
    
    /**
     * 检查参数是否应该被跳过
     * 
     * @param paramName 参数名
     * @return true 表示跳过
     */
    default boolean shouldSkipParameter(String paramName) {
        return false;
    }
}

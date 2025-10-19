package DetSql;

import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * 参数修改策略接口 - 封装不同参数类型的修改方式
 *
 * 设计理念:
 * - 函数式接口 (可用Lambda实现)
 * - 不可变 (不修改原请求)
 * - 无状态 (线程安全)
 * - 直接传递 ParsedHttpParameter，从根本上消除索引错位问题
 *
 * @author DetSql Team
 * @version 3.0
 */
@FunctionalInterface
public interface ParameterModifier {
    /**
     * 修改指定参数的值,添加payload
     *
     * 重构说明 (v3.0):
     * - 移除了 paramIndex 参数，直接传递 ParsedHttpParameter
     * - 从根本上消除了"子集过滤导致索引错位"的问题
     * - 实现类内部通过 sourceRequest.parameters(type).indexOf(param) 获取真实索引
     *
     * @param sourceRequest 原始HTTP请求 (不会被修改)
     * @param param 要修改的参数对象 (包含名称、值、偏移量等完整信息)
     * @param payload 要追加的payload
     * @return 修改后的新请求 (新对象)
     */
    HttpRequest modifyParameter(
        HttpRequest sourceRequest,
        ParsedHttpParameter param,
        String payload
    );

    /**
     * 默认方法: 判断是否需要URL编码
     * URL参数覆盖此方法返回true
     *
     * @return true表示需要URL编码, false表示不需要
     */
    default boolean needsUrlEncoding() {
        return false;
    }
}

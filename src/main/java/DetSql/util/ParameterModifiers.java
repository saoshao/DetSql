package DetSql.util;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

/**
 * 参数修改策略集合
 *
 * 使用场景:
 * - testStringInjection(params, ParameterModifiers.URL, ...)
 * - testNumericInjection(params, ParameterModifiers.BODY, ...)
 *
 * @author kenyon
 * @version 3.0
 */
public final class ParameterModifiers {

    private ParameterModifiers() {
        // 工具类不允许实例化
    }

    /**
     * P3 修复：通用参数值修改逻辑
     * 消除 URL/BODY/COOKIE 修改器中的代码重复
     * 
     * @param originalValue 原始值
     * @param payload 载荷
     * @param jsonIndex 插入位置（0=追加到末尾）
     * @return 修改后的值
     */
    private static String applyPayload(String originalValue, String payload, int jsonIndex) {
        if (jsonIndex == 0) {
            return originalValue + payload;
        } else if (jsonIndex > 0 && jsonIndex <= originalValue.length()) {
            return originalValue.substring(0, jsonIndex) + payload + originalValue.substring(jsonIndex);
        }
        // jsonIndex 超出范围，抛出异常
        throw new IllegalArgumentException(
            String.format("jsonIndex (%d) out of range for value length (%d)", jsonIndex, originalValue.length())
        );
    }

    /**
     * 私有辅助方法：基于偏移量修改请求体
     * 用于 JSON/XML 修改器的公共逻辑
     * 
     * @param sourceRequest 原始请求
     * @param param 参数对象
     * @param payload 注入载荷
     * @return 修改后的请求
     */
    private static HttpRequest modifyByOffset(
            HttpRequest sourceRequest,
            ParsedHttpParameter param,
            String payload) {
        
        // 1. 直接从 param 对象获取偏移量信息
        int valueStart = param.valueOffsets().startIndexInclusive();
        int valueEnd = param.valueOffsets().endIndexExclusive();

        // 2. 获取完整请求体
        String body = sourceRequest.body().toString();
        int bodyOffset = sourceRequest.bodyOffset();

        // 3. 计算相对于 body 的偏移量
        int relativeValueStart = valueStart - bodyOffset;
        int relativeValueEnd = valueEnd - bodyOffset;

        // 4. 安全边界检查
        if (relativeValueStart < 0 || relativeValueEnd > body.length() || relativeValueStart > relativeValueEnd) {
            throw new IllegalStateException(
                String.format("Invalid offset for parameter '%s': body length=%d, valueStart=%d, valueEnd=%d",
                    param.name(), body.length(), relativeValueStart, relativeValueEnd)
            );
        }

        // 5. 拼接新的 body
        String prefix = body.substring(0, relativeValueEnd);
        String suffix = body.substring(relativeValueEnd);
        String newBody = prefix + payload + suffix;

        return sourceRequest.withBody(newBody);
    }

    /**
     * URL参数修改器
     *
     * 特点:
     * - 使用 HttpParameter.urlParameter()
     * - 使用 withUpdatedParameters()
     * - Payload需URL编码
     * - 直接通过 param 对象获取索引，消除索引错位问题
     */
    public static final ParameterModifier URL = new ParameterModifier() {
        @Override
        public HttpRequest modifyParameter(
                HttpRequest sourceRequest,
                ParsedHttpParameter param,
                String payload,int jsonIndex) {

            // 1. 获取所有URL参数
            List<ParsedHttpParameter> parsedParams =
                sourceRequest.parameters(HttpParameterType.URL);

            // 2. 获取目标参数在完整列表中的真实索引
            int paramIndex = parsedParams.indexOf(param);
            if (paramIndex == -1) {
                throw new IllegalArgumentException(
                    "Parameter not found in URL parameters: " + param.name()
                );
            }

            // 3. 构建新参数列表
            List<HttpParameter> newParams = new ArrayList<>(parsedParams.size());
            for (int i = 0; i < parsedParams.size(); i++) {
                ParsedHttpParameter p = parsedParams.get(i);
                if (i == paramIndex) {
                    // P3 修复：使用公共方法处理 jsonIndex 逻辑
                    newParams.add(HttpParameter.urlParameter(
                        param.name(),
                        applyPayload(param.value(), payload, jsonIndex)
                    ));
                } else {
                    // 保持其他参数不变
                    newParams.add(HttpParameter.urlParameter(p.name(), p.value()));
                }
            }

            // 4. 返回新请求
            return sourceRequest.withUpdatedParameters(newParams);
        }

        @Override
        public boolean needsUrlEncoding() {
            return true;  // URL参数需要编码
        }
    };

    /**
     * BODY参数修改器
     *
     * 特点:
     * - 使用 HttpParameter.bodyParameter()
     * - 使用 withUpdatedParameters()
     * - 直接通过 param 对象获取索引，消除索引错位问题
     */
    public static final ParameterModifier BODY = new ParameterModifier() {
        @Override
        public HttpRequest modifyParameter(
                HttpRequest sourceRequest,
                ParsedHttpParameter param,
                String payload,int jsonIndex) {

            // 1. 获取所有BODY参数
            List<ParsedHttpParameter> parsedParams =
                sourceRequest.parameters(HttpParameterType.BODY);

            // 2. 获取目标参数在完整列表中的真实索引
            int paramIndex = parsedParams.indexOf(param);
            if (paramIndex == -1) {
                throw new IllegalArgumentException(
                    "Parameter not found in BODY parameters: " + param.name()
                );
            }

            // 3. 构建新参数列表
            List<HttpParameter> newParams = new ArrayList<>(parsedParams.size());
            for (int i = 0; i < parsedParams.size(); i++) {
                ParsedHttpParameter p = parsedParams.get(i);
                if (i == paramIndex) {
                    // P3 修复：使用公共方法处理 jsonIndex 逻辑
                    newParams.add(HttpParameter.bodyParameter(
                        param.name(),
                        applyPayload(param.value(), payload, jsonIndex)
                    ));
                } else {
                    newParams.add(HttpParameter.bodyParameter(p.name(), p.value()));
                }
            }

            return sourceRequest.withUpdatedParameters(newParams);
        }
    };

    /**
     * JSON参数修改器
     *
     * 特点:
     * - 使用字符串拼接 (prefix + payload + suffix)
     * - 使用 withBody()
     * - 需要引号检查
     * - 直接使用 param 对象的偏移量信息，无需索引
     */
    public static final ParameterModifier JSON = new ParameterModifier() {
        @Override
        public HttpRequest modifyParameter(
                HttpRequest sourceRequest,
                ParsedHttpParameter param,
                String payload,int jsonIndex) {
            // 使用公共辅助方法
            return modifyByOffset(sourceRequest, param, payload);
        }
    };

    /**
     * XML参数修改器
     *
     * 特点:
     * - 与JSON类似,使用字符串拼接
     * - 不需要引号检查
     * - 直接使用 param 对象的偏移量信息，无需索引
     */
    public static final ParameterModifier XML = new ParameterModifier() {
        @Override
        public HttpRequest modifyParameter(
                HttpRequest sourceRequest,
                ParsedHttpParameter param,
                String payload,int jsonIndex) {
            // 使用公共辅助方法
            return modifyByOffset(sourceRequest, param, payload);
        }
    };

    /**
     * COOKIE参数修改器
     *
     * 特点:
     * - 使用 HttpParameter.cookieParameter()
     * - 使用 withUpdatedParameters()
     * - 直接通过 param 对象获取索引，消除索引错位问题
     */
    public static final ParameterModifier COOKIE = new ParameterModifier() {
        @Override
        public HttpRequest modifyParameter(
                HttpRequest sourceRequest,
                ParsedHttpParameter param,
                String payload,int jsonIndex) {

            // 1. 获取所有COOKIE参数
            List<ParsedHttpParameter> parsedParams =
                sourceRequest.parameters(HttpParameterType.COOKIE);

            // 2. 获取目标参数在完整列表中的真实索引
            int paramIndex = parsedParams.indexOf(param);
            if (paramIndex == -1) {
                throw new IllegalArgumentException(
                    "Parameter not found in COOKIE parameters: " + param.name()
                );
            }

            // 3. 构建新参数列表
            List<HttpParameter> newParams = new ArrayList<>(parsedParams.size());
            for (int i = 0; i < parsedParams.size(); i++) {
                ParsedHttpParameter p = parsedParams.get(i);
                if (i == paramIndex) {
                    // P3 修复：使用公共方法处理 jsonIndex 逻辑，修复未处理 jsonIndex 的 bug
                    newParams.add(HttpParameter.cookieParameter(
                        param.name(),
                        applyPayload(param.value(), payload, jsonIndex)
                    ));
                } else {
                    newParams.add(HttpParameter.cookieParameter(p.name(), p.value()));
                }
            }

            return sourceRequest.withUpdatedParameters(newParams);
        }
    };
}

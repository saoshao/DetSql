package DetSql;

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
 * @author DetSql Team
 * @version 3.0
 */
public final class ParameterModifiers {


    private ParameterModifiers() {
        // 工具类不允许实例化
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
                    if(jsonIndex==0){
                        // 修改目标参数
                        newParams.add(HttpParameter.urlParameter(
                                param.name(),
                                param.value() + payload
                        ));
                    }else if(jsonIndex>0&&jsonIndex<=param.value().length()){
                        // 修改目标参数
                        newParams.add(HttpParameter.urlParameter(
                                param.name(),
                                param.value().substring(0,jsonIndex) + payload+param.value().substring(jsonIndex)
                        ));
                    }

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
                    if(jsonIndex==0){
                        newParams.add(HttpParameter.bodyParameter(
                                param.name(),
                                param.value() + payload
                        ));
                    } else if (jsonIndex>0&&jsonIndex<=param.value().length()) {
                        newParams.add(HttpParameter.bodyParameter(
                                param.name(),
                                param.value().substring(0,jsonIndex) + payload+param.value().substring(jsonIndex)
                        ));
                    }

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
                    newParams.add(HttpParameter.cookieParameter(
                        param.name(),
                        param.value() + payload
                    ));
                } else {
                    newParams.add(HttpParameter.cookieParameter(p.name(), p.value()));
                }
            }

            return sourceRequest.withUpdatedParameters(newParams);
        }
    };
}

public class TimeBasedInjection extends AbstractInjectionStrategy {
    
    private static final int TIMEOUT_THRESHOLD = 5; // 秒
    private static final int NORMAL_TIMEOUT = 2;
    private static final String[] TIME_PAYLOADS = {
        "' AND SLEEP(5) -- ",
        "' OR SLEEP(5) -- ",
        " AND SLEEP(5) -- ",
        " OR SLEEP(5) -- "
    };
    
    @Override
    public boolean detect(String paramName, String paramValue, HttpRequest request) {
        // 1. 发送原始请求，记录响应时间
        long normalTime = measureResponseTime(request);
        
        // 2. 对每个时间payload进行测试
        for (String payload : TIME_PAYLOADS) {
            String modifiedValue = paramValue + payload;
            HttpRequest modifiedRequest = modifyRequest(request, paramName, modifiedValue);
            
            long delayedTime = measureResponseTime(modifiedRequest);
            
            // 3. 判断是否存在延迟 (超过阈值)
            if (delayedTime - normalTime > TIMEOUT_THRESHOLD) {
                return true; // 检测到时间盲注
            }
        }
        return false;
    }
    
    private long measureResponseTime(HttpRequest request) {
        long startTime = System.currentTimeMillis();
        // 发送请求
        long endTime = System.currentTimeMillis();
        return endTime - startTime;
    }
}

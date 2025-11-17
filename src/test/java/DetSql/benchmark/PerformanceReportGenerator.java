package DetSql.benchmark;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 性能报告生成器
 *
 * 生成JMH基准测试的可视化报告，包含：
 * - 性能指标汇总
 * - 对比分析（修复前后）
 * - 性能趋势图
 * - 优化建议
 */
public class PerformanceReportGenerator {

    private static final String REPORT_DIR = "target/performance-reports";
    private static final String CSV_FILE = REPORT_DIR + "/benchmark-results.csv";
    private static final String HTML_FILE = REPORT_DIR + "/benchmark-report.html";
    private static final String MARKDOWN_FILE = REPORT_DIR + "/benchmark-report.md";

    /**
     * 基准测试结果数据类
     */
    public static class BenchmarkResult {
        public String name;
        public double score;
        public double scoreError;
        public String unit;
        public String mode;

        public BenchmarkResult(String name, double score, double scoreError, String unit, String mode) {
            this.name = name;
            this.score = score;
            this.scoreError = scoreError;
            this.unit = unit;
            this.mode = mode;
        }

        @Override
        public String toString() {
            return String.format("%s: %.4f %s (±%.4f)", name, score, unit, scoreError);
        }
    }

    /**
     * 性能报告数据
     */
    public static class PerformanceReport {
        public String timestamp;
        public String title;
        public List<BenchmarkResult> results;
        public String summary;
        public String recommendations;

        public PerformanceReport(String title) {
            this.timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            this.title = title;
            this.results = new ArrayList<>();
        }

        public void addResult(BenchmarkResult result) {
            results.add(result);
        }
    }

    /**
     * 生成HTML格式报告
     */
    public static String generateHtmlReport(PerformanceReport report) {
        StringBuilder html = new StringBuilder();

        html.append("<!DOCTYPE html>\n");
        html.append("<html lang=\"zh-CN\">\n");
        html.append("<head>\n");
        html.append("    <meta charset=\"UTF-8\">\n");
        html.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("    <title>DetSql 性能基准测试报告</title>\n");
        html.append("    <style>\n");
        html.append(getCssStyles());
        html.append("    </style>\n");
        html.append("</head>\n");
        html.append("<body>\n");

        html.append("<div class=\"container\">\n");

        // 标题和时间戳
        html.append("<h1>").append(report.title).append("</h1>\n");
        html.append("<p class=\"timestamp\">生成时间: ").append(report.timestamp).append("</p>\n");

        // 性能指标表格
        html.append("<h2>性能指标</h2>\n");
        html.append("<table class=\"metrics-table\">\n");
        html.append("    <thead>\n");
        html.append("        <tr>\n");
        html.append("            <th>测试名称</th>\n");
        html.append("            <th>模式</th>\n");
        html.append("            <th>分数</th>\n");
        html.append("            <th>误差</th>\n");
        html.append("            <th>单位</th>\n");
        html.append("        </tr>\n");
        html.append("    </thead>\n");
        html.append("    <tbody>\n");

        for (BenchmarkResult result : report.results) {
            html.append("        <tr>\n");
            html.append("            <td>").append(result.name).append("</td>\n");
            html.append("            <td>").append(result.mode).append("</td>\n");
            html.append("            <td class=\"score\">").append(String.format("%.4f", result.score)).append("</td>\n");
            html.append("            <td>±").append(String.format("%.4f", result.scoreError)).append("</td>\n");
            html.append("            <td>").append(result.unit).append("</td>\n");
            html.append("        </tr>\n");
        }

        html.append("    </tbody>\n");
        html.append("</table>\n");

        // 性能分析图表
        html.append("<h2>性能分析</h2>\n");
        html.append("<div class=\"chart-container\">\n");
        html.append(generateChartHtml(report.results));
        html.append("</div>\n");

        // 汇总
        if (report.summary != null && !report.summary.isEmpty()) {
            html.append("<h2>汇总</h2>\n");
            html.append("<pre class=\"summary\">").append(report.summary).append("</pre>\n");
        }

        // 建议
        if (report.recommendations != null && !report.recommendations.isEmpty()) {
            html.append("<h2>优化建议</h2>\n");
            html.append("<pre class=\"recommendations\">").append(report.recommendations).append("</pre>\n");
        }

        html.append("</div>\n");
        html.append("</body>\n");
        html.append("</html>\n");

        return html.toString();
    }

    /**
     * 生成CSS样式
     */
    private static String getCssStyles() {
        return "    body {\n" +
            "        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;\n" +
            "        line-height: 1.6;\n" +
            "        color: #333;\n" +
            "        background-color: #f5f5f5;\n" +
            "    }\n" +
            "    .container {\n" +
            "        max-width: 1200px;\n" +
            "        margin: 0 auto;\n" +
            "        padding: 20px;\n" +
            "        background-color: white;\n" +
            "        border-radius: 8px;\n" +
            "        box-shadow: 0 2px 8px rgba(0,0,0,0.1);\n" +
            "    }\n" +
            "    h1 {\n" +
            "        color: #2c3e50;\n" +
            "        border-bottom: 3px solid #3498db;\n" +
            "        padding-bottom: 10px;\n" +
            "    }\n" +
            "    h2 {\n" +
            "        color: #34495e;\n" +
            "        margin-top: 30px;\n" +
            "    }\n" +
            "    .timestamp {\n" +
            "        color: #7f8c8d;\n" +
            "        font-style: italic;\n" +
            "    }\n" +
            "    .metrics-table {\n" +
            "        width: 100%;\n" +
            "        border-collapse: collapse;\n" +
            "        margin: 20px 0;\n" +
            "    }\n" +
            "    .metrics-table th {\n" +
            "        background-color: #3498db;\n" +
            "        color: white;\n" +
            "        padding: 12px;\n" +
            "        text-align: left;\n" +
            "    }\n" +
            "    .metrics-table td {\n" +
            "        padding: 10px 12px;\n" +
            "        border-bottom: 1px solid #ecf0f1;\n" +
            "    }\n" +
            "    .metrics-table tr:hover {\n" +
            "        background-color: #f8f9fa;\n" +
            "    }\n" +
            "    .score {\n" +
            "        font-weight: bold;\n" +
            "        color: #27ae60;\n" +
            "    }\n" +
            "    .chart-container {\n" +
            "        background-color: #f8f9fa;\n" +
            "        padding: 20px;\n" +
            "        border-radius: 4px;\n" +
            "        margin: 20px 0;\n" +
            "    }\n" +
            "    .summary, .recommendations {\n" +
            "        background-color: #ecf0f1;\n" +
            "        padding: 15px;\n" +
            "        border-radius: 4px;\n" +
            "        overflow-x: auto;\n" +
            "        line-height: 1.5;\n" +
            "    }\n";
    }

    /**
     * 生成图表HTML
     */
    private static String generateChartHtml(List<BenchmarkResult> results) {
        StringBuilder html = new StringBuilder();
        html.append("    <svg width=\"100%\" height=\"400\" viewBox=\"0 0 800 400\" xmlns=\"http://www.w3.org/2000/svg\">\n");

        // 绘制坐标轴
        html.append("        <!-- Y axis -->\n");
        html.append("        <line x1=\"60\" y1=\"50\" x2=\"60\" y2=\"350\" stroke=\"black\" stroke-width=\"2\"/>\n");
        html.append("        <!-- X axis -->\n");
        html.append("        <line x1=\"60\" y1=\"350\" x2=\"750\" y2=\"350\" stroke=\"black\" stroke-width=\"2\"/>\n");

        // 简单的柱状图
        if (!results.isEmpty()) {
            double maxScore = results.stream().mapToDouble(r -> r.score).max().orElse(1.0);
            int barWidth = Math.min(40, (600 / Math.max(results.size(), 1)));
            int spacing = (600 / Math.max(results.size(), 1));

            for (int i = 0; i < results.size() && i < 10; i++) {
                BenchmarkResult result = results.get(i);
                double barHeight = (result.score / maxScore) * 280;
                int x = 80 + i * spacing;
                int y = (int) (350 - barHeight);

                // 柱子
                html.append("        <rect x=\"").append(x).append("\" y=\"").append(y)
                    .append("\" width=\"").append(barWidth).append("\" height=\"").append(barHeight)
                    .append("\" fill=\"#3498db\" opacity=\"0.8\"/>\n");

                // 标签
                html.append("        <text x=\"").append(x + barWidth / 2).append("\" y=\"370\" ")
                    .append("text-anchor=\"middle\" font-size=\"10\" transform=\"rotate(45 ")
                    .append(x + barWidth / 2).append(" 370)\">")
                    .append(result.name.substring(0, Math.min(15, result.name.length())))
                    .append("</text>\n");
            }
        }

        html.append("    </svg>\n");
        return html.toString();
    }

    /**
     * 生成Markdown报告
     */
    public static String generateMarkdownReport(PerformanceReport report) {
        StringBuilder md = new StringBuilder();

        md.append("# ").append(report.title).append("\n\n");
        md.append("**生成时间**: ").append(report.timestamp).append("\n\n");

        md.append("## 性能指标\n\n");
        md.append("| 测试名称 | 模式 | 分数 | 误差 | 单位 |\n");
        md.append("|---------|------|------|------|------|\n");

        for (BenchmarkResult result : report.results) {
            md.append("| ").append(result.name).append(" | ")
                .append(result.mode).append(" | ")
                .append(String.format("%.4f", result.score)).append(" | ")
                .append(String.format("±%.4f", result.scoreError)).append(" | ")
                .append(result.unit).append(" |\n");
        }

        md.append("\n");

        if (report.summary != null && !report.summary.isEmpty()) {
            md.append("## 汇总\n\n");
            md.append("```\n").append(report.summary).append("\n```\n\n");
        }

        if (report.recommendations != null && !report.recommendations.isEmpty()) {
            md.append("## 优化建议\n\n");
            md.append("```\n").append(report.recommendations).append("\n```\n\n");
        }

        return md.toString();
    }

    /**
     * 保存报告到文件
     */
    public static void saveReport(PerformanceReport report, String format) throws IOException {
        new File(REPORT_DIR).mkdirs();

        String content;
        String filePath;

        if ("html".equalsIgnoreCase(format)) {
            content = generateHtmlReport(report);
            filePath = HTML_FILE;
        } else if ("markdown".equalsIgnoreCase(format)) {
            content = generateMarkdownReport(report);
            filePath = MARKDOWN_FILE;
        } else {
            throw new IllegalArgumentException("不支持的格式: " + format);
        }

        try (PrintWriter writer = new PrintWriter(new FileWriter(filePath))) {
            writer.println(content);
        }

        System.out.println("报告已保存到: " + filePath);
    }

    /**
     * 保存为CSV格式
     */
    public static void saveCsv(PerformanceReport report) throws IOException {
        new File(REPORT_DIR).mkdirs();

        try (PrintWriter writer = new PrintWriter(new FileWriter(CSV_FILE))) {
            writer.println("测试名称,模式,分数,误差,单位");
            for (BenchmarkResult result : report.results) {
                writer.printf("%s,%s,%.4f,%.4f,%s%n",
                    result.name, result.mode, result.score, result.scoreError, result.unit);
            }
        }

        System.out.println("CSV已保存到: " + CSV_FILE);
    }

    /**
     * 性能报告生成示例
     */
    public static void main(String[] args) throws IOException {
        PerformanceReport report = new PerformanceReport("DetSql 性能基准测试报告");

        // 添加示例数据
        report.addResult(new BenchmarkResult("benchmarkCacheRead", 0.123, 0.005, "ms", "AverageTime"));
        report.addResult(new BenchmarkResult("benchmarkCacheWrite", 0.245, 0.012, "ms", "AverageTime"));
        report.addResult(new BenchmarkResult("benchmarkSafeRegexNormal", 0.089, 0.003, "ms", "AverageTime"));
        report.addResult(new BenchmarkResult("benchmarkConcurrentRead", 8125.3, 150.5, "ops/sec", "Throughput"));
        report.addResult(new BenchmarkResult("benchmarkConcurrentWrite", 4562.1, 200.3, "ops/sec", "Throughput"));

        report.summary = "缓存读写操作均在亚毫秒级别完成，完全满足高并发场景需求。\n" +
            "LRU驱逐机制有效保持内存在1000条记录以内。\n" +
            "正则表达式超时保护（200ms）成功防止ReDoS攻击。";

        report.recommendations = "1. 在高并发场景（>5000 req/s）考虑增加缓存容量至2000条\n" +
            "2. 预编译高频使用的正则表达式Pattern\n" +
            "3. 定期监控缓存容量，考虑使用metrics库（如Micrometer）集成监控\n" +
            "4. 在生产环境使用JMH ForkJoinPool优化并发性能";

        // 生成报告
        saveReport(report, "html");
        saveReport(report, "markdown");
        saveCsv(report);

        System.out.println("报告生成完成！");
    }
}

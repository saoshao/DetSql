package DetSql.ui;

import DetSql.util.Statistics;
import javax.swing.*;
import java.awt.*;

/**
 * 统计面板 - 显示扫描统计信息
 * 从 DetSqlUI 中提取出来，遵循单一职责原则
 */
public class StatisticsPanel extends JPanel {
    private final Statistics statistics;
    
    private JLabel requestsProcessedLabel;
    private JLabel vulnerabilitiesFoundLabel;
    private JLabel requestsFilteredLabel;
    private JLabel detectionErrorsLabel;
    private JLabel strategyTimeoutsLabel;
    private JLabel averageTestTimeLabel;
    private JLabel memoryUsedLabel;
    private JLabel uptimeLabel;
    
    private Timer refreshTimer;
    
    public StatisticsPanel(Statistics statistics) {
        this.statistics = statistics;
        initComponents();
        startAutoRefresh();
    }
    
    private void initComponents() {
        setLayout(new GridBagLayout());
        setBorder(BorderFactory.createTitledBorder("扫描统计"));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 10, 5, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;
        
        // 已处理请求
        gbc.gridx = 0; gbc.gridy = 0;
        add(new JLabel("已处理请求:"), gbc);
        gbc.gridx = 1;
        requestsProcessedLabel = new JLabel("0");
        add(requestsProcessedLabel, gbc);
        
        // 发现漏洞
        gbc.gridx = 0; gbc.gridy = 1;
        add(new JLabel("发现漏洞:"), gbc);
        gbc.gridx = 1;
        vulnerabilitiesFoundLabel = new JLabel("0");
        add(vulnerabilitiesFoundLabel, gbc);
        
        // 已过滤请求
        gbc.gridx = 0; gbc.gridy = 2;
        add(new JLabel("已过滤请求:"), gbc);
        gbc.gridx = 1;
        requestsFilteredLabel = new JLabel("0");
        add(requestsFilteredLabel, gbc);

        // 检测错误
        gbc.gridx = 0; gbc.gridy = 3;
        add(new JLabel("检测错误:"), gbc);
        gbc.gridx = 1;
        detectionErrorsLabel = new JLabel("0");
        add(detectionErrorsLabel, gbc);
        
        // 策略超时
        gbc.gridx = 0; gbc.gridy = 4;
        add(new JLabel("策略超时:"), gbc);
        gbc.gridx = 1;
        strategyTimeoutsLabel = new JLabel("0");
        add(strategyTimeoutsLabel, gbc);
        
        // 平均测试时间
        gbc.gridx = 0; gbc.gridy = 5;
        add(new JLabel("平均测试时间:"), gbc);
        gbc.gridx = 1;
        averageTestTimeLabel = new JLabel("0 ms");
        add(averageTestTimeLabel, gbc);
        
        // 内存使用
        gbc.gridx = 0; gbc.gridy = 6;
        add(new JLabel("内存使用:"), gbc);
        gbc.gridx = 1;
        memoryUsedLabel = new JLabel("0 MB");
        add(memoryUsedLabel, gbc);
        
        // 运行时间
        gbc.gridx = 0; gbc.gridy = 7;
        add(new JLabel("运行时间:"), gbc);
        gbc.gridx = 1;
        uptimeLabel = new JLabel("00:00:00");
        add(uptimeLabel, gbc);
    }
    
    /**
     * 更新统计显示
     */
    public void updateStatistics() {
        SwingUtilities.invokeLater(() -> {
            requestsProcessedLabel.setText(String.valueOf(statistics.getRequestsProcessed()));
            vulnerabilitiesFoundLabel.setText(String.valueOf(statistics.getVulnerabilitiesFound()));
            requestsFilteredLabel.setText(String.valueOf(statistics.getRequestsFiltered()));
            detectionErrorsLabel.setText(String.valueOf(statistics.getDetectionErrors()));
            strategyTimeoutsLabel.setText(String.valueOf(statistics.getStrategyTimeouts()));
            averageTestTimeLabel.setText(statistics.getAverageTestTime() + " ms");
            memoryUsedLabel.setText(statistics.getMemoryUsedMB() + " / " + statistics.getMaxMemoryMB() + " MB");
            
            long uptimeSeconds = statistics.getUptimeMillis() / 1000;
            long hours = uptimeSeconds / 3600;
            long minutes = (uptimeSeconds % 3600) / 60;
            long seconds = uptimeSeconds % 60;
            uptimeLabel.setText(String.format("%02d:%02d:%02d", hours, minutes, seconds));
        });
    }
    
    /**
     * 启动自动刷新（每秒更新一次）
     */
    private void startAutoRefresh() {
        refreshTimer = new Timer(1000, e -> updateStatistics());
        refreshTimer.start();
    }
    
    /**
     * 停止自动刷新
     */
    public void stopAutoRefresh() {
        if (refreshTimer != null) {
            refreshTimer.stop();
        }
    }
}

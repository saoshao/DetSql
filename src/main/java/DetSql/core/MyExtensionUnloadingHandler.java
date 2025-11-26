/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql.core;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Properties;
import DetSql.config.ConfigManager;
import DetSql.config.DetSqlYamlConfig;
import DetSql.logging.DetSqlLogger;
import DetSql.ui.DetSqlUI;


public class MyExtensionUnloadingHandler implements ExtensionUnloadingHandler {
    private final DetSqlUI ui;
    private final MyHttpHandler httpHandler;
    private final DetSqlLogger logger;

    public MyExtensionUnloadingHandler(DetSqlUI ui, MyHttpHandler httpHandler, DetSqlLogger logger) {
        this.ui = ui;
        this.httpHandler = httpHandler;
        this.logger = logger;
    }

    @Override
    public void extensionUnloaded() {
        try {
            // 1. 关闭线程池和其他资源（防止僵尸线程）
            logger.info("扩展卸载：开始清理资源...");
            httpHandler.shutdown();
            
            // 2. 保存配置
            logger.info("扩展卸载：保存配置...");
            saveConfiguration();
            
            logger.info("DetSql 扩展已安全卸载");
        } catch (Exception e) {
            logger.error("扩展卸载时发生错误", e);
        }
    }

    /**
     * 保存配置到 YAML 文件
     */
    private void saveConfiguration() {
        try {
            // 1. 从 UI 构建 YamlConfig 对象
            DetSqlYamlConfig yamlConfig = ui.buildYamlConfig();
            
            // 2. 使用 ConfigManager 保存到 YAML
            ConfigManager configManager = new ConfigManager();
            configManager.saveConfig(yamlConfig);
            
            logger.info("配置已保存到: " + configManager.getConfigPath());
        } catch (Exception ex) {
            logger.error("保存配置失败", ex);
        }
    }
}

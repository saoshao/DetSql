package DetSql.config;

import org.junit.jupiter.api.*;
import java.nio.file.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 调试配置保存/加载的测试
 */
@DisplayName("Debug Config Save/Load")
public class ConfigDebugTest {
    
    @Test
    @DisplayName("Debug: Check what is actually saved to YAML")
    public void testDebugYamlContent() throws IOException {
        ConfigManager configManager = new ConfigManager();
        Path configPath = configManager.getConfigPath();
        
        // Clean up
        Files.deleteIfExists(configPath);
        
        // Create a config with specific values
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setLanguageindex(0);
        config.setDelaytime(1000);
        config.setStatictime(2000);
        
        // Save it
        configManager.saveConfig(config);
        
        // Read the actual YAML file content
        String yamlContent = Files.readString(configPath, StandardCharsets.UTF_8);
        System.out.println("=== YAML Content ===");
        System.out.println(yamlContent);
        System.out.println("=== End YAML Content ===");
        
        // Check if delaytime is in the file
        assertTrue(yamlContent.contains("delaytime"), "YAML should contain delaytime field");
        assertTrue(yamlContent.contains("1000"), "YAML should contain delaytime value 1000");
        
        // Clean up
        Files.deleteIfExists(configPath);
    }
    
    @Test
    @DisplayName("Debug: Load and check values")
    public void testDebugLoadedValues() throws IOException {
        ConfigManager configManager = new ConfigManager();
        Path configPath = configManager.getConfigPath();
        
        // Clean up
        Files.deleteIfExists(configPath);
        
        // Create a config
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setDelaytime(1000);
        
        // Save it
        configManager.saveConfig(config);
        
        // Load it
        DetSqlYamlConfig loaded = configManager.loadConfig();
        
        // Debug output
        System.out.println("=== Loaded Config Values ===");
        System.out.println("delaytime: " + loaded.getDelaytime());
        System.out.println("statictime: " + loaded.getStatictime());
        System.out.println("starttime: " + loaded.getStarttime());
        System.out.println("endtime: " + loaded.getEndtime());
        
        // Check
        assertEquals(1000, loaded.getDelaytime(), "Loaded delaytime should match saved value");
        
        // Clean up
        Files.deleteIfExists(configPath);
    }
}

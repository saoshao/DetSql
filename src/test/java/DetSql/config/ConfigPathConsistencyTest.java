package DetSql.config;

import org.junit.jupiter.api.*;
import java.nio.file.*;
import java.io.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 配置路径一致性测试
 * 确保加载和保存的配置文件是同一个
 */
@DisplayName("Config Path Consistency Tests")
public class ConfigPathConsistencyTest {
    
    private ConfigManager configManager;
    private Path expectedConfigPath;
    
    @BeforeEach
    public void setUp() {
        configManager = new ConfigManager();
        String userHome = System.getProperty("user.home");
        expectedConfigPath = Paths.get(userHome, ".config/DetSql/config.yaml");
    }
    
    @Test
    @DisplayName("Configuration manager should use consistent YAML path")
    public void testConfigPathConsistency() {
        Path actualPath = configManager.getConfigPath();
        assertEquals(expectedConfigPath, actualPath, 
            "Config path should match expected YAML location");
    }
    
    @Test
    @DisplayName("Saved config should be at the same path where it's loaded")
    public void testSaveLoadPathConsistency() throws IOException {
        // Clean up if exists
        if (Files.exists(expectedConfigPath)) {
            Files.delete(expectedConfigPath);
        }
        
        // Create a config
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        config.setLanguageindex(0);  // 使用有效值 (0 或 1)
        config.setDelaytime(1000);
        
        // Save the config
        configManager.saveConfig(config);
        
        // Verify file exists at expected path
        assertTrue(Files.exists(expectedConfigPath), 
            "Config file should exist at expected path after save");
        
        // Load the config
        DetSqlYamlConfig loadedConfig = configManager.loadConfig();
        
        // Verify loaded config matches saved config
        assertEquals(0, loadedConfig.getLanguageindex(), 
            "Loaded config should match saved config");
        assertEquals(1000, loadedConfig.getDelaytime(), 
            "Loaded config should match saved config");
        
        // Clean up
        Files.deleteIfExists(expectedConfigPath);
    }
    
    @Test
    @DisplayName("Should not use legacy Properties path for saving")
    public void testNoLegacyPathForSaving() throws IOException {
        Path legacyPath = Paths.get(System.getProperty("user.home"), "DetSqlConfig.txt");
        
        // Clean up
        Files.deleteIfExists(legacyPath);
        Files.deleteIfExists(expectedConfigPath);
        
        // Save a config
        DetSqlYamlConfig config = new DetSqlYamlConfig();
        configManager.saveConfig(config);
        
        // Verify legacy path is NOT used
        assertFalse(Files.exists(legacyPath), 
            "Should NOT save to legacy Properties path");
        
        // Verify YAML path IS used
        assertTrue(Files.exists(expectedConfigPath), 
            "Should save to YAML path");
        
        // Clean up
        Files.deleteIfExists(expectedConfigPath);
    }
    
    @Test
    @DisplayName("Should migrate legacy config and delete old file")
    public void testLegacyConfigMigration() throws IOException {
        Path legacyPath = Paths.get(System.getProperty("user.home"), "DetSqlConfig.txt");
        
        // Clean up
        Files.deleteIfExists(expectedConfigPath);
        Files.deleteIfExists(legacyPath);
        
        // Create a legacy Properties file
        try (OutputStream output = Files.newOutputStream(legacyPath);
             OutputStreamWriter writer = new OutputStreamWriter(output, "UTF-8")) {
            writer.write("languageindex=1\n");
            writer.write("delaytime=2000\n");
            writer.write("whitelist=example.com\n");
        }
        
        // Load config (should trigger migration)
        DetSqlYamlConfig config = configManager.loadConfig();
        
        // Verify migration succeeded
        assertEquals(1, config.getLanguageindex(), 
            "Should migrate languageindex correctly");
        assertEquals(2000, config.getDelaytime(), 
            "Should migrate delaytime correctly");
        
        // Verify YAML file was created
        assertTrue(Files.exists(expectedConfigPath), 
            "YAML config file should exist after migration");
        
        // Verify legacy file was deleted
        assertFalse(Files.exists(legacyPath), 
            "Legacy config file should be deleted after migration");
        
        // Clean up
        Files.deleteIfExists(expectedConfigPath);
    }
    
    @AfterEach
    public void tearDown() throws IOException {
        // Clean up test files
        Files.deleteIfExists(expectedConfigPath);
        Path legacyPath = Paths.get(System.getProperty("user.home"), "DetSqlConfig.txt");
        Files.deleteIfExists(legacyPath);
    }
}

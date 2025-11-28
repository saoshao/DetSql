package DetSql.ui;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.BeforeEach;

import javax.swing.JTextArea;
import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CodeToolPanel UI 设计测试
 * 验证输入/输出文本框分离设计
 */
@DisplayName("CodeToolPanel UI Tests")
public class CodeToolPanelUITest {
    
    private CodeToolPanel panel;
    
    @BeforeEach
    public void setUp() {
        panel = new CodeToolPanel();
    }
    
    @Test
    @DisplayName("Should have separate input/output areas for Unicode")
    public void testUnicodeSeparateAreas() throws Exception {
        Field unicodeInputField = CodeToolPanel.class.getDeclaredField("unicodeInputArea");
        Field unicodeOutputField = CodeToolPanel.class.getDeclaredField("unicodeOutputArea");
        
        unicodeInputField.setAccessible(true);
        unicodeOutputField.setAccessible(true);
        
        JTextArea unicodeInput = (JTextArea) unicodeInputField.get(panel);
        JTextArea unicodeOutput = (JTextArea) unicodeOutputField.get(panel);
        
        assertNotNull(unicodeInput, "Unicode input area should exist");
        assertNotNull(unicodeOutput, "Unicode output area should exist");
        assertNotSame(unicodeInput, unicodeOutput, 
            "Unicode input and output should be separate text areas");
    }
    
    @Test
    @DisplayName("Should have separate input/output areas for URL")
    public void testUrlSeparateAreas() throws Exception {
        Field urlInputField = CodeToolPanel.class.getDeclaredField("urlInputArea");
        Field urlOutputField = CodeToolPanel.class.getDeclaredField("urlOutputArea");
        
        urlInputField.setAccessible(true);
        urlOutputField.setAccessible(true);
        
        JTextArea urlInput = (JTextArea) urlInputField.get(panel);
        JTextArea urlOutput = (JTextArea) urlOutputField.get(panel);
        
        assertNotNull(urlInput, "URL input area should exist");
        assertNotNull(urlOutput, "URL output area should exist");
        assertNotSame(urlInput, urlOutput, 
            "URL input and output should be separate text areas");
    }
    
    @Test
    @DisplayName("Should preserve Base64 separate areas design")
    public void testBase64SeparateAreas() throws Exception {
        Field base64Field = CodeToolPanel.class.getDeclaredField("base64TextArea");
        Field decodedField = CodeToolPanel.class.getDeclaredField("decodedTextArea");
        
        base64Field.setAccessible(true);
        decodedField.setAccessible(true);
        
        JTextArea base64 = (JTextArea) base64Field.get(panel);
        JTextArea decoded = (JTextArea) decodedField.get(panel);
        
        assertNotNull(base64, "Base64 input area should exist");
        assertNotNull(decoded, "Base64 output area should exist");
        assertNotSame(base64, decoded, 
            "Base64 input and output should be separate text areas");
    }
    
    @Test
    @DisplayName("Panel should be created without exceptions")
    public void testPanelCreation() {
        assertNotNull(panel, "CodeToolPanel should be created successfully");
        assertDoesNotThrow(() -> new CodeToolPanel(), 
            "Creating CodeToolPanel should not throw exceptions");
    }
}

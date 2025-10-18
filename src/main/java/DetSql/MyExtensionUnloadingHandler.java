/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Properties;

public class MyExtensionUnloadingHandler implements ExtensionUnloadingHandler {
    //textField.getText(),blackTextField.getText(),suffixTextField.getText(),errorPocTextField.getText(),String.valueOf(switchCheck.isSelected()),String.valueOf(cookieCheck.isSelected()),String.valueOf(errorCheck.isSelected()),String.valueOf(vulnCheck.isSelected())

    @Override
    public void extensionUnloaded() {
        Properties prop = DetSql.buildConfigProperties();

        try (java.io.OutputStreamWriter writer = new java.io.OutputStreamWriter(
                new java.io.FileOutputStream(System.getProperty("user.home")+ File.separator+"DetSqlConfig.txt"),
                java.nio.charset.StandardCharsets.UTF_8)) {
            prop.store(writer, null);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}

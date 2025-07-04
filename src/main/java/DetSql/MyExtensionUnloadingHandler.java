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
    //textField.getText(),blackTextField.getText(),suffixTextField.getText(),errorPocTextField.getText(),String.valueOf(switchChexk.isSelected()),String.valueOf(cookieChexk.isSelected()),String.valueOf(errorChexk.isSelected()),String.valueOf(vulnChexk.isSelected())

    @Override
    public void extensionUnloaded() {
        Properties prop = new Properties();
        prop.setProperty("whitelist", DetSql.textField.getText());//
        prop.setProperty("blacklist", DetSql.blackTextField.getText());//
        prop.setProperty("suffixlist", DetSql.suffixTextField.getText());//
        prop.setProperty("errpoclist", DetSql.errorPocTextField.getText());//
        prop.setProperty("paramslist", DetSql.blackParamsField.getText());//
        prop.setProperty("delaytime", DetSql.timeTextField.getText());//
        prop.setProperty("statictime", DetSql.staticTimeTextField.getText());//
        prop.setProperty("starttime", DetSql.startTimeTextField.getText());//
        prop.setProperty("endtime", DetSql.endTimeTextField.getText());//
        prop.setProperty("switch", String.valueOf(DetSql.switchChexk.isSelected()));
        prop.setProperty("cookiecheck", String.valueOf(DetSql.cookieChexk.isSelected()));
        prop.setProperty("errorcheck", String.valueOf(DetSql.errorChexk.isSelected()));
        prop.setProperty("numcheck", String.valueOf(DetSql.numChexk.isSelected()));
        prop.setProperty("stringcheck", String.valueOf(DetSql.stringChexk.isSelected()));
        prop.setProperty("ordercheck", String.valueOf(DetSql.orderChexk.isSelected()));
        prop.setProperty("repeatercheck", String.valueOf(DetSql.vulnChexk.isSelected()));
        prop.setProperty("boolcheck", String.valueOf(DetSql.boolChexk.isSelected()));
        prop.setProperty("diycheck", String.valueOf(DetSql.diyChexk.isSelected()));
        prop.setProperty("diypayloads", DetSql.diyTextArea.getText());
        prop.setProperty("diyregex", DetSql.regexTextArea.getText());
        prop.setProperty("blackpath", DetSql.blackPathTextArea.getText());
        prop.setProperty("languageindex", String.valueOf(DetSql.index));

        try {
            FileWriter fw = new FileWriter(System.getProperty("user.home")+ File.separator+"DetSqlConfig.txt");
            prop.store(fw, null);
            fw.close();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}

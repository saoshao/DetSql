/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.utilities.CryptoUtils;
import burp.api.montoya.utilities.DigestAlgorithm;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang3.StringEscapeUtils;

import javax.swing.*;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

import javax.swing.event.MouseInputListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Element;

public class DetSql implements BurpExtension, ContextMenuItemsProvider{
    MontoyaApi api;
    public MyHttpHandler myHttpHandler;
    public SourceTableModel sourceTableModel;
    public ConcurrentHashMap<String, List<PocLogEntry>> attackMap;
    public static JCheckBox switchChexk;
    public static JCheckBox cookieChexk;
    public static JCheckBox errorChexk;//
    public static JCheckBox vulnChexk;
    public static JTable table1;
    public static JTable table2;
    //补充4个
    public static JCheckBox numChexk;//
    public static JCheckBox stringChexk;//
    public static JCheckBox orderChexk;//
    public static JCheckBox boolChexk;//

    public static JCheckBox diyChexk;//

    public static JTextField textField;
    public static JTextField blackTextField;
    public static JTextField suffixTextField;
    public static JTextField errorPocTextField;
    //新加参数黑名单框
    public static JTextField blackParamsField;
    public static JTextField whiteParamsField;
    JTextField configTextField;
    public static JTextArea diyTextArea;
    public static JTextArea regexTextArea;
    public static JTextArea blackPathTextArea;
    public static JTextField timeTextField;
    public static JTextField staticTimeTextField;
    public static JTextField startTimeTextField;
    public static JTextField endTimeTextField;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        api.extension().setName("DetSql");
        sourceTableModel = new SourceTableModel();
        PocTableModel pocTableModel = new PocTableModel();
        Component component = getComponent(sourceTableModel, pocTableModel);
        api.userInterface().registerSuiteTab("DetSql", component);
        attackMap = new ConcurrentHashMap<>();
        myHttpHandler = new MyHttpHandler(api, sourceTableModel, pocTableModel, attackMap);
        api.http().registerHttpHandler(myHttpHandler);
        api.extension().registerUnloadingHandler(new MyExtensionUnloadingHandler());
        api.userInterface().registerContextMenuItemsProvider(this);
        File configFile = new File(System.getProperty("user.home")+ File.separator+"DetSqlConfig.txt");
        if (configFile.exists()) {
            Properties prop = new Properties();
            try {
                FileReader fileReader = new FileReader(System.getProperty("user.home")+ File.separator+"DetSqlConfig.txt");
                configTextField.setText(System.getProperty("user.home")+ File.separator+"DetSqlConfig.txt");
                prop.load(fileReader);
                textField.setText(prop.getProperty("whitelist", ""));
                if (!prop.getProperty("whitelist", "").isBlank()) {
                    MyFilterRequest.whiteListSet = new HashSet<>(Arrays.asList(prop.getProperty("whitelist", "").split("\\|")));
                } else {
                    MyFilterRequest.whiteListSet = new HashSet<>();
                }
                blackTextField.setText(prop.getProperty("blacklist", ""));
                if (!prop.getProperty("blacklist", "").isBlank()) {
                    MyFilterRequest.blackListSet = new HashSet<>(Arrays.asList(prop.getProperty("blacklist", "").split("\\|")));
                } else {
                    MyFilterRequest.blackListSet = new HashSet<>();
                }
                blackParamsField.setText(prop.getProperty("paramslist", ""));
                if (!prop.getProperty("paramslist", "").isBlank()) {
                    MyHttpHandler.blackParamsSet = new HashSet<>(Arrays.asList(prop.getProperty("paramslist", "").split("\\|")));
                } else {
                    MyHttpHandler.blackParamsSet = new HashSet<>();
                }
                suffixTextField.setText(prop.getProperty("suffixlist", "wma|csv|mov|doc|3g2|mp4|7z|3gp|xbm|jar|avi|ogv|mpv2|tiff|pnm|jpg|xpm|xul|epub|au|aac|midi|weba|tar|js|rtf|bin|woff|wmv|tif|css|gif|flv|ttf|html|eot|ods|odt|webm|mpg|mjs|bz|ics|ras|aifc|mpa|ppt|mpeg|pptx|oga|ra|aiff|asf|woff2|snd|xwd|csh|webp|xlsx|mpkg|vsd|mid|wav|svg|mp3|bz2|ico|jpe|pbm|gz|pdf|log|jpeg|rmi|txt|arc|rm|ppm|cod|jfif|ram|docx|mpe|odp|otf|pgm|cmx|m3u|mp2|cab|rar|bmp|rgb|png|azw|ogx|aif|zip|ief|htm|xls|mpp|swf|rmvb|abw"));
                if (!prop.getProperty("suffixlist", "wma|csv|mov|doc|3g2|mp4|7z|3gp|xbm|jar|avi|ogv|mpv2|tiff|pnm|jpg|xpm|xul|epub|au|aac|midi|weba|tar|js|rtf|bin|woff|wmv|tif|css|gif|flv|ttf|html|eot|ods|odt|webm|mpg|mjs|bz|ics|ras|aifc|mpa|ppt|mpeg|pptx|oga|ra|aiff|asf|woff2|snd|xwd|csh|webp|xlsx|mpkg|vsd|mid|wav|svg|mp3|bz2|ico|jpe|pbm|gz|pdf|log|jpeg|rmi|txt|arc|rm|ppm|cod|jfif|ram|docx|mpe|odp|otf|pgm|cmx|m3u|mp2|cab|rar|bmp|rgb|png|azw|ogx|aif|zip|ief|htm|xls|mpp|swf|rmvb|abw").isBlank()) {
                    MyFilterRequest.unLegalExtensionSet = new HashSet<>(Arrays.asList(prop.getProperty("suffixlist", "wma|csv|mov|doc|3g2|mp4|7z|3gp|xbm|jar|avi|ogv|mpv2|tiff|pnm|jpg|xpm|xul|epub|au|aac|midi|weba|tar|js|rtf|bin|woff|wmv|tif|css|gif|flv|ttf|html|eot|ods|odt|webm|mpg|mjs|bz|ics|ras|aifc|mpa|ppt|mpeg|pptx|oga|ra|aiff|asf|woff2|snd|xwd|csh|webp|xlsx|mpkg|vsd|mid|wav|svg|mp3|bz2|ico|jpe|pbm|gz|pdf|log|jpeg|rmi|txt|arc|rm|ppm|cod|jfif|ram|docx|mpe|odp|otf|pgm|cmx|m3u|mp2|cab|rar|bmp|rgb|png|azw|ogx|aif|zip|ief|htm|xls|mpp|swf|rmvb|abw").split("\\|")));
                } else {
                    MyFilterRequest.unLegalExtensionSet = new HashSet<>(Arrays.asList("wma", "csv", "mov", "doc", "3g2", "mp4", "7z", "3gp", "xbm", "jar", "avi", "ogv", "mpv2", "tiff", "pnm", "jpg", "xpm", "xul", "epub", "au", "aac", "midi", "weba", "tar", "js", "rtf", "bin", "woff", "wmv", "tif", "css", "gif", "flv", "ttf", "html", "eot", "ods", "odt", "webm", "mpg", "mjs", "bz", "ics", "ras", "aifc", "mpa", "ppt", "mpeg", "pptx", "oga", "ra", "aiff", "asf", "woff2", "snd", "xwd", "csh", "webp", "xlsx", "mpkg", "vsd", "mid", "wav", "svg", "mp3", "bz2", "ico", "jpe", "pbm", "gz", "pdf", "log", "jpeg", "rmi", "txt", "arc", "rm", "ppm", "cod", "jfif", "ram", "docx", "mpe", "odp", "otf", "pgm", "cmx", "m3u", "mp2", "cab", "rar", "bmp", "rgb", "png", "azw", "ogx", "aif", "zip", "ief", "htm", "xls", "mpp", "swf", "rmvb", "abw"));
                }
                errorPocTextField.setText(prop.getProperty("errpoclist", ""));
                if (!prop.getProperty("errpoclist", "").isBlank()) {
                    MyHttpHandler.errPocs = prop.getProperty("errpoclist", "").split("\\|");
                    MyHttpHandler.errPocsj = prop.getProperty("errpoclist", "").split("\\|");
                } else {
                    MyHttpHandler.errPocs = new String[]{"'", "%27", "%DF'", "%DF%27", "\"", "%22", "%DF\"", "%DF%22", "`"};
                    MyHttpHandler.errPocsj = new String[]{"'", "%27", "%DF'", "%DF%27", "\\\"", "%22", "%DF\\\"", "%DF%22", "\\u0022", "%DF\\u0022", "\\u0027", "%DF\\u0027", "`"};
                }
                timeTextField.setText(prop.getProperty("delaytime", ""));
                String timeStr =prop.getProperty("delaytime", "").trim();
                try{
                    MyHttpHandler.intTime = Integer.parseInt(timeStr);
                }catch (NumberFormatException ne){
                    MyHttpHandler.intTime=1000000;
                }
                staticTimeTextField.setText(prop.getProperty("statictime", "100"));
                String staticTimeStr =prop.getProperty("statictime", "").trim();
                try{
                    MyHttpHandler.staticTime = Integer.parseInt(staticTimeStr);
                }catch (NumberFormatException ne){
                    MyHttpHandler.staticTime=100;
                }
                startTimeTextField.setText(prop.getProperty("starttime", "0"));
                String startTimeStr =prop.getProperty("starttime", "").trim();
                try{
                    MyHttpHandler.startTime = Integer.parseInt(startTimeStr);
                }catch (NumberFormatException ne){
                    MyHttpHandler.startTime=0;
                }
                endTimeTextField.setText(prop.getProperty("endtime", "0"));
                String endTimeStr =prop.getProperty("endtime", "").trim();
                try{
                    MyHttpHandler.endTime = Integer.parseInt(endTimeStr);
                }catch (NumberFormatException ne){
                    MyHttpHandler.endTime=0;
                }
                diyTextArea.setText(prop.getProperty("diypayloads", ""));
                if (!prop.getProperty("diypayloads", "").isBlank()) {
                    MyHttpHandler.diyPayloads.clear();
                    Element paragraph = diyTextArea.getDocument().getDefaultRootElement();
                    int contentCount = paragraph.getElementCount();
                    for (int i = 0; i < contentCount; i++) {
                        Element ee = paragraph.getElement(i);
                        int rangeStart = ee.getStartOffset();
                        int rangeEnd = ee.getEndOffset();
                        String line = null;
                        try {
                            line = diyTextArea.getText(rangeStart, rangeEnd - rangeStart).replaceFirst("[\n\r]+$", "");
                            MyHttpHandler.diyPayloads.add(line);
                        } catch (BadLocationException ex) {
                            throw new RuntimeException(ex);
                        }

                    }
                } else {
                    MyHttpHandler.diyPayloads.clear();
                }
                regexTextArea.setText(prop.getProperty("diyregex", ""));
                if (!prop.getProperty("diyregex", "").isBlank()) {
                    MyHttpHandler.diyRegexs.clear();
                    Element paragraph = regexTextArea.getDocument().getDefaultRootElement();
                    int contentCount = paragraph.getElementCount();
                    for (int i = 0; i < contentCount; i++) {
                        Element ee = paragraph.getElement(i);
                        int rangeStart = ee.getStartOffset();
                        int rangeEnd = ee.getEndOffset();
                        String line = null;
                        try {
                            line = regexTextArea.getText(rangeStart, rangeEnd - rangeStart).replaceFirst("[\n\r]+$", "");
                            //api.logging().logToOutput(line);
                            MyHttpHandler.diyRegexs.add(line);
                        } catch (BadLocationException ex) {
                            throw new RuntimeException(ex);
                        }

                    }
                } else {
                    MyHttpHandler.diyRegexs.clear();
                }
                blackPathTextArea.setText(prop.getProperty("blackpath", ""));
                if (!prop.getProperty("blackpath", "").isBlank()) {
                    MyFilterRequest.blackPathSet.clear();
                    Element paragraph = blackPathTextArea.getDocument().getDefaultRootElement();
                    int contentCount = paragraph.getElementCount();
                    for (int i = 0; i < contentCount; i++) {
                        Element ee = paragraph.getElement(i);
                        int rangeStart = ee.getStartOffset();
                        int rangeEnd = ee.getEndOffset();
                        String line = null;
                        try {
                            line = blackPathTextArea.getText(rangeStart, rangeEnd - rangeStart).replaceFirst("[\n\r]+$", "");
                            MyFilterRequest.blackPathSet.add(line);

                        } catch (BadLocationException ex) {
                            throw new RuntimeException(ex);
                        }

                    }
                    //api.logging().logToOutput(MyFilterRequest.blackPathSet.toString());
                } else {
                    MyFilterRequest.blackPathSet.clear();
                }

                switchChexk.setSelected(Boolean.parseBoolean(prop.getProperty("switch")));
                cookieChexk.setSelected(Boolean.parseBoolean(prop.getProperty("cookiecheck")));
                errorChexk.setSelected(Boolean.parseBoolean(prop.getProperty("errorcheck")));
                vulnChexk.setSelected(Boolean.parseBoolean(prop.getProperty("repeatercheck")));
                numChexk.setSelected(Boolean.parseBoolean(prop.getProperty("numcheck")));
                stringChexk.setSelected(Boolean.parseBoolean(prop.getProperty("stringcheck")));
                orderChexk.setSelected(Boolean.parseBoolean(prop.getProperty("ordercheck")));
                boolChexk.setSelected(Boolean.parseBoolean(prop.getProperty("boolcheck")));
                diyChexk.setSelected(Boolean.parseBoolean(prop.getProperty("diycheck")));

                fileReader.close();
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }


        api.logging().logToOutput("################################################");
        api.logging().logToOutput("[#]  load successfully");
        api.logging().logToOutput("[#]  DetSql v2.4");
        api.logging().logToOutput("[#]  Author: saoshao");
        api.logging().logToOutput("[#]  Email: 1224165231@qq.com");
        api.logging().logToOutput("[#]  Github: https://github.com/saoshao/DetSql");
        api.logging().logToOutput("################################################");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> listMenuItems = new ArrayList<>();
        JMenu jMenu2 = new JMenu("DetSql");
        JMenuItem menuItem2 = new JMenuItem("End this data");
        JMenuItem menuItem3 = new JMenuItem("Send to DetSql");

        listMenuItems.add(jMenu2);
        jMenu2.add(menuItem2);
        jMenu2.add(menuItem3);

        menuItem2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                HttpRequestResponse selectHttpRequestResponse = event.messageEditorRequestResponse().get().requestResponse();
                CryptoUtils cryptoUtils = api.utilities().cryptoUtils();
                String requestSm3Hash = MyHttpHandler.byteToHex(cryptoUtils.generateDigest(ByteArray.byteArray(MyFilterRequest.getUnique(selectHttpRequestResponse)), DigestAlgorithm.SM3).getBytes());
                Thread currentThread = null;
                for (Map.Entry<Thread, StackTraceElement[]> entry : Thread.getAllStackTraces().entrySet()) {
                    if (entry.getKey().getName().equals(requestSm3Hash)) {
                        currentThread = entry.getKey();
                        currentThread.interrupt();
                        break;
                    }
                }
            }
        });
        menuItem3.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                HttpRequestResponse selectHttpRequestResponse = event.messageEditorRequestResponse().get().requestResponse();
                myHttpHandler.createProcessThread(selectHttpRequestResponse);
            }
        });
        return listMenuItems;
    }

    private Component getComponent(SourceTableModel tableModel, PocTableModel pocTableModel) {
        JPanel root = new JPanel();
        JTabbedPane tabbedPane1 = new JTabbedPane();
        JSplitPane splitPane1 = new JSplitPane();
        JSplitPane splitPane2 = new JSplitPane();
        JScrollPane scrollPane1 = new JScrollPane();
        JScrollPane scrollPane2 = new JScrollPane();
        JSplitPane splitPane3 = new JSplitPane();
        UserInterface userInterface = api.userInterface();
        HttpRequestEditor requestViewer = userInterface.createHttpRequestEditor(READ_ONLY);
        HttpResponseEditor responseViewer = userInterface.createHttpResponseEditor(READ_ONLY);
        JTabbedPane tabbedPane2 = new JTabbedPane();
        JPanel finRoot = new JPanel();
        SpringLayout springLayout = new SpringLayout();
        finRoot.setLayout(springLayout);
        finRoot.add(requestViewer.uiComponent());
        springLayout.putConstraint(SpringLayout.NORTH, requestViewer.uiComponent(), 0, SpringLayout.NORTH, finRoot);
        springLayout.putConstraint(SpringLayout.WEST, requestViewer.uiComponent(), 0, SpringLayout.WEST, finRoot);
        springLayout.putConstraint(SpringLayout.EAST, requestViewer.uiComponent(), 0, SpringLayout.EAST, finRoot);
        springLayout.putConstraint(SpringLayout.SOUTH, requestViewer.uiComponent(), 0, SpringLayout.SOUTH, finRoot);
        tabbedPane2.addTab("Request", finRoot);

        JTabbedPane tabbedPane3 = new JTabbedPane();
        JPanel rfinRoot = new JPanel();
        SpringLayout rspringLayout = new SpringLayout();
        rfinRoot.setLayout(rspringLayout);
        rfinRoot.add(responseViewer.uiComponent());
        rspringLayout.putConstraint(SpringLayout.NORTH, responseViewer.uiComponent(), 0, SpringLayout.NORTH, rfinRoot);
        rspringLayout.putConstraint(SpringLayout.WEST, responseViewer.uiComponent(), 0, SpringLayout.WEST, rfinRoot);
        rspringLayout.putConstraint(SpringLayout.EAST, responseViewer.uiComponent(), 0, SpringLayout.EAST, rfinRoot);
        rspringLayout.putConstraint(SpringLayout.SOUTH, responseViewer.uiComponent(), 0, SpringLayout.SOUTH, rfinRoot);
        tabbedPane3.addTab("Response", rfinRoot);
        table1 = new JTable(tableModel) {
            @Override
            public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
                SourceLogEntry logEntry = tableModel.get(DetSql.table1.convertRowIndexToModel(rowIndex));
                if (logEntry.getHttpRequestResponse() != null) {
                    requestViewer.setRequest(logEntry.getHttpRequestResponse().request());
                    responseViewer.setResponse(logEntry.getHttpRequestResponse().response());
                    super.changeSelection(rowIndex, columnIndex, toggle, extend);
                    String sm3Hash = logEntry.getMyHash();
                    List<PocLogEntry> pocLogEntries = myHttpHandler.attackMap.get(sm3Hash);
                    pocTableModel.add(pocLogEntries);
                }else{
                    requestViewer.setRequest(HttpRequest.httpRequest());
                    super.changeSelection(rowIndex, columnIndex, toggle, extend);
                }



            }
        };
        //table1.setRowSorter(null);
//        if(tableModel.getRowCount()>0){
//            table1.setAutoCreateRowSorter(true);
//            tableModel.fireTableDataChanged();
//        }

//        //设置点击表头，数据自动排序
        TableRowSorter<SourceTableModel> sorter = new TableRowSorter<>(tableModel);
//        //获得列的数量
//        //int columnCount = tableModel.getColumnCount();
//            //这里可以根据需要修改
        sorter.setComparator(0, new Comparator<Object>() {
            @Override
            public int compare(Object o1, Object o2) {
                String str1 = o1.toString();
                String str2 = o2.toString();
                return Integer.parseInt(str1) - Integer.parseInt(str2);
            }
        });
        sorter.setComparator(5, new Comparator<Object>() {
            @Override
            public int compare(Object o1, Object o2) {
                String str1 = o1.toString();
                String str2 = o2.toString();
                return Integer.parseInt(str1) - Integer.parseInt(str2);
            }
        });
//
        table1.setRowSorter(sorter);
        table1.setEnabled(true);
        table1.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        final JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem menuItem1 = new JMenuItem("delete selected rows");
        JMenuItem menuItem2 = new JMenuItem("delete novuln history");
        popupMenu.add(menuItem1);
        popupMenu.add(menuItem2);
        menuItem1.addActionListener(e -> {
            //api.logging().logToOutput("delete selected rows");
            int[] selectedRows = table1.getSelectedRows();
            for (int i = selectedRows.length - 1; i >= 0; i--) {
                if (!sourceTableModel.getValueAt(table1.convertRowIndexToModel(selectedRows[i]),6).equals("run")){
                    //api.logging().logToOutput("rows:"+selectedRows[i]);
                    //api.logging().logToOutput("ID:"+table1.convertRowIndexToModel(selectedRows[i]));
                    sourceTableModel.log.remove(new SourceLogEntry((int)sourceTableModel.getValueAt(table1.convertRowIndexToModel(selectedRows[i]),0),null,null,null,0,null,null,null,null));
                    tableModel.fireTableRowsDeleted(selectedRows[i],selectedRows[i]);
                }


            }
            //api.logging().logToOutput("left id：");
//            for (SourceLogEntry sourceLogEntry : sourceTableModel.log) {
//                api.logging().logToOutput(sourceLogEntry.getId()+"");
//            }
        });
        menuItem2.addActionListener(e -> {
            for (int i = sourceTableModel.log.size() - 1; i >= 0; i--) {
                if (sourceTableModel.getValueAt(table1.convertRowIndexToModel(i),6).equals("")||sourceTableModel.getValueAt(table1.convertRowIndexToModel(i),6).equals("手动停止")){
                    //api.logging().logToOutput("rows:"+i);
                    //api.logging().logToOutput("ID:"+table1.convertRowIndexToModel(i));
                    sourceTableModel.log.remove(new SourceLogEntry((int)sourceTableModel.getValueAt(table1.convertRowIndexToModel(i),0),null,null,null,0,null,null,null,null));
                    tableModel.fireTableRowsDeleted(i,i);
                }


            }
        });
// 为弹出菜单添加事件监听器
        popupMenu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                // 当菜单即将可见时的处理逻辑
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                // 当菜单即将不可见时的处理逻辑
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
                // 当右键点击但未显示菜单（例如点击其他地方）时的处理逻辑
            }
        });
// 为JTable添加鼠标监听器来显示弹出菜单
        table1.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupMenu.show(table1, e.getX(), e.getY());
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupMenu.show(table1, e.getX(), e.getY());
                }
            }
        });
        table2 = new JTable(pocTableModel) {
            @Override
            public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
                // show the log entry for the selected row
                PocLogEntry logEntry = pocTableModel.get(DetSql.table2.convertRowIndexToModel(rowIndex));
                if (logEntry.getHttpRequestResponse() != null) {
                    requestViewer.setRequest(logEntry.getHttpRequestResponse().request());
                    responseViewer.setResponse(logEntry.getHttpRequestResponse().response());
                    super.changeSelection(rowIndex, columnIndex, toggle, extend);
                }

            }
        };
        TableRowSorter<PocTableModel> sorter1 = new TableRowSorter<>(pocTableModel);
//        //获得列的数量
//        //int columnCount = tableModel.getColumnCount();
//            //这里可以根据需要修改

        sorter1.setComparator(5, new Comparator<Object>() {
            @Override
            public int compare(Object o1, Object o2) {
                String str1 = o1.toString();
                String str2 = o2.toString();
                return (int) (Double.parseDouble(str1)*1000-Double.parseDouble(str2)*1000);
            }
        });
//
        table2.setRowSorter(sorter1);

        //======== root ========
        {
            root.setLayout(new BorderLayout());

            //======== tabbedPane1 ========
            {

                //======== splitPane1 ========
                {
                    splitPane1.setOrientation(JSplitPane.VERTICAL_SPLIT);

                    //======== splitPane2 ========
                    {

                        //======== scrollPane1 ========
                        {
                            scrollPane1.setViewportView(table1);
                        }
                        splitPane2.setLeftComponent(scrollPane1);

                        //======== scrollPane2 ========
                        {
                            scrollPane2.setViewportView(table2);
                        }
                        splitPane2.setRightComponent(scrollPane2);
                    }
                    splitPane2.setResizeWeight(0.5);
                    splitPane1.setTopComponent(splitPane2);

                    //======== splitPane3 ========
                    {
                        splitPane3.setLeftComponent(tabbedPane2);
                        splitPane3.setRightComponent(tabbedPane3);
                    }
                    splitPane3.setResizeWeight(0.5);
                    splitPane1.setBottomComponent(splitPane3);
                }

                tabbedPane1.addTab("DashBoard", splitPane1);

                //======== panel1 ========
                tabbedPane1.addTab("Config", getConfigComponent());
                tabbedPane1.addTab("CodeTool", getToolComponent());
            }
            root.add(tabbedPane1);
            tabbedPane1.setSize(Toolkit.getDefaultToolkit().getScreenSize());

            {
                Dimension preferredSize = new Dimension();
                for (int i = 0; i < root.getComponentCount(); i++) {
                    Rectangle bounds = root.getComponent(i).getBounds();
                    preferredSize.width = Math.max(bounds.x + bounds.width, preferredSize.width);
                    preferredSize.height = Math.max(bounds.y + bounds.height, preferredSize.height);
                }
                Insets insets = root.getInsets();
                preferredSize.width += insets.right;
                preferredSize.height += insets.bottom;
                root.setMinimumSize(preferredSize);
                root.setPreferredSize(preferredSize);
            }
        }
//        JPanel finRoot = new JPanel();
//        SpringLayout springLayout = new SpringLayout();
//        finRoot.setLayout(springLayout);
//        finRoot.add(root);
//        springLayout.putConstraint(SpringLayout.NORTH, root, 0, SpringLayout.NORTH, finRoot);
//        springLayout.putConstraint(SpringLayout.WEST, root, 0, SpringLayout.WEST, finRoot);
//        springLayout.putConstraint(SpringLayout.EAST, root, 0, SpringLayout.EAST, finRoot);
//        springLayout.putConstraint(SpringLayout.SOUTH, root, 40, SpringLayout.SOUTH, finRoot);

        return root;
    }



    private Component getConfigComponent() {
        Container container = new JPanel();
        SpringLayout springLayout = new SpringLayout();
        container.setLayout(springLayout);
        JLabel topicLabel = new JLabel("域名白名单:");
        textField = new JTextField(30);
        JLabel blackLabel = new JLabel("域名黑名单:");
        blackTextField = new JTextField(30);
        JLabel suffixLabel = new JLabel("禁止后缀:");
        suffixTextField = new JTextField(30);
        suffixTextField.setText("xul|mpa|mp3|bz2|m3u|pdf|pbm|docx|rm|jpe|jar|flv|svg|bz|tar|mp4|cod|log|xwd|mpp|css|jpeg|weba|odt|wma|azw|woff|mpe|ttf|mpkg|ogx|cmx|jpg|rar|png|bin|ppt|ico|webm|xpm|mov|doc|csh|au|rmvb|aif|vsd|ram|cab|ief|odp|js|mp2|xls|aac|woff2|tif|eot|mpv2|gz|ras|abw|xbm|html|asf|7z|oga|tiff|epub|ppm|gif|pptx|bmp|aiff|pnm|pgm|zip|3g2|wmv|ods|webp|swf|rtf|avi|ra|xlsx|csv|rgb|otf|mpg|ics|htm|mid|arc|snd|3gp|txt|jfif|midi|mpeg|rmi|aifc|ogv|wav|mjs");
        JLabel errorPocLabel = new JLabel("报错poc:");
        errorPocTextField = new JTextField(30);
        //新加参数黑名单
        JLabel blackParams = new JLabel("参数黑名单:");
        blackParamsField= new JTextField(30);

        JLabel configLabel = new JLabel("配置目录:");
        configTextField = new JTextField(30);
        configTextField.setEditable(false);
        switchChexk = new JCheckBox("开关", false);
        cookieChexk = new JCheckBox("测试cookie", false);
        errorChexk = new JCheckBox("测试报错类型", false);
        vulnChexk = new JCheckBox("接受repeater", false);

        numChexk= new JCheckBox("测试数字类型", false);
        stringChexk= new JCheckBox("测试字符类型", false);
        orderChexk= new JCheckBox("测试order类型", false);
        boolChexk= new JCheckBox("测试bool类型", false);
        diyChexk=new JCheckBox("测试diypayloads",false);
        JLabel diyLabel = new JLabel("自定义payloads：");
        diyTextArea=new JTextArea(20, 6);
        JScrollPane diyScrollPane = new JScrollPane();
        diyScrollPane.setViewportView(diyTextArea);
        diyTextArea.setLineWrap(true);

        JLabel resRegexLabel = new JLabel("响应正则匹配规则：");
        regexTextArea=new JTextArea(10, 6);
        JScrollPane regexScrollPane = new JScrollPane();
        regexScrollPane.setViewportView(regexTextArea);
        regexTextArea.setLineWrap(true);

        JLabel timeLabel = new JLabel("延迟时间(ms)：");
        timeTextField=new JTextField(6);

        JLabel staticTimeLabel = new JLabel("请求间固定间隔(ms)：");
        staticTimeTextField=new JTextField(6);
        staticTimeTextField.setText("100");

        JLabel startTimeLabel = new JLabel("请求间间隔范围(ms)：");
        startTimeTextField=new JTextField(6);
        startTimeTextField.setText("0");

        JLabel endTimeLabel = new JLabel("-");
        endTimeTextField=new JTextField(6);
        endTimeTextField.setText("0");

        JLabel blackPathLabel = new JLabel("路径黑名单：");
        blackPathTextArea=new JTextArea(5, 6);
        JScrollPane blackPathScrollPane = new JScrollPane();
        blackPathScrollPane.setViewportView(blackPathTextArea);
        blackPathTextArea.setLineWrap(true);

        JButton conBt = new JButton("确认");
        conBt.addActionListener(e -> {
            String whiteList = textField.getText();
            if (!whiteList.isBlank()) {
                MyFilterRequest.whiteListSet = new HashSet<>(Arrays.asList(whiteList.trim().split("\\|")));
            } else {
                MyFilterRequest.whiteListSet.clear();
            }
            String blackList = blackTextField.getText();
            if (!blackList.isBlank()) {
                MyFilterRequest.blackListSet = new HashSet<>(Arrays.asList(blackList.trim().split("\\|")));
            } else {
                MyFilterRequest.blackListSet.clear();
            }
            String blackParamsList = blackParamsField.getText();
//            api.logging().logToOutput(blackParamsList);
//            api.logging().logToOutput(!blackParamsList.isBlank()+"");
            if (!blackParamsList.isBlank()) {
                MyHttpHandler.blackParamsSet = new HashSet<>(Arrays.asList(blackParamsList.trim().split("\\|")));
//                for (String s : MyHttpHandler.blackParamsSet) {
//                    api.logging().logToOutput(s);
//                }

            } else {
                MyHttpHandler.blackParamsSet.clear();
            }
            String unLegalExtension = suffixTextField.getText();
            if (!unLegalExtension.isBlank()) {
                MyFilterRequest.unLegalExtensionSet = new HashSet<>(Arrays.asList(unLegalExtension.trim().split("\\|")));
            } else {
                MyFilterRequest.unLegalExtensionSet = new HashSet<>(Arrays.asList("wma", "csv", "mov", "doc", "3g2", "mp4", "7z", "3gp", "xbm", "jar", "avi", "ogv", "mpv2", "tiff", "pnm", "jpg", "xpm", "xul", "epub", "au", "aac", "midi", "weba", "tar", "js", "rtf", "bin", "woff", "wmv", "tif", "css", "gif", "flv", "ttf", "html", "eot", "ods", "odt", "webm", "mpg", "mjs", "bz", "ics", "ras", "aifc", "mpa", "ppt", "mpeg", "pptx", "oga", "ra", "aiff", "asf", "woff2", "snd", "xwd", "csh", "webp", "xlsx", "mpkg", "vsd", "mid", "wav", "svg", "mp3", "bz2", "ico", "jpe", "pbm", "gz", "pdf", "log", "jpeg", "rmi", "txt", "arc", "rm", "ppm", "cod", "jfif", "ram", "docx", "mpe", "odp", "otf", "pgm", "cmx", "m3u", "mp2", "cab", "rar", "bmp", "rgb", "png", "azw", "ogx", "aif", "zip", "ief", "htm", "xls", "mpp", "swf", "rmvb", "abw"));
            }
            String errorPocList = errorPocTextField.getText();
            if (!errorPocList.isBlank()) {
                MyHttpHandler.errPocs = errorPocList.trim().split("\\|");
                MyHttpHandler.errPocsj = errorPocList.trim().split("\\|");
            } else {
                MyHttpHandler.errPocs = new String[]{"'", "%27", "%DF'", "%DF%27", "\"", "%22", "%DF\"", "%DF%22", "`"};
                MyHttpHandler.errPocsj = new String[]{"'", "%27", "%DF'", "%DF%27", "\\\"", "%22", "%DF\\\"", "%DF%22", "\\u0022", "%DF\\u0022", "\\u0027", "%DF\\u0027", "`"};
            }
            String diyPayloadsStr=diyTextArea.getText();
            if (!diyPayloadsStr.isBlank()) {
                MyHttpHandler.diyPayloads.clear();
                Element paragraph = diyTextArea.getDocument().getDefaultRootElement();
                int contentCount = paragraph.getElementCount();
                for (int i = 0; i < contentCount; i++) {
                    Element ee = paragraph.getElement(i);
                    int rangeStart = ee.getStartOffset();
                    int rangeEnd = ee.getEndOffset();
                    String line = null;
                    try {
                        line = diyTextArea.getText(rangeStart, rangeEnd - rangeStart).replaceFirst("[\n\r]+$", "");
                        MyHttpHandler.diyPayloads.add(line);
                    } catch (BadLocationException ex) {
                        throw new RuntimeException(ex);
                    }

                }
            } else {
                MyHttpHandler.diyPayloads.clear();
            }
            String diyRegexsStr=regexTextArea.getText();
            if (!diyRegexsStr.isBlank()) {
                MyHttpHandler.diyRegexs.clear();
                Element paragraph = regexTextArea.getDocument().getDefaultRootElement();
                int contentCount = paragraph.getElementCount();
                for (int i = 0; i < contentCount; i++) {
                    Element ee = paragraph.getElement(i);
                    int rangeStart = ee.getStartOffset();
                    int rangeEnd = ee.getEndOffset();
                    String line = null;
                    try {
                        line = regexTextArea.getText(rangeStart, rangeEnd - rangeStart).replaceFirst("[\n\r]+$", "");
                        MyHttpHandler.diyRegexs.add(line);
                    } catch (BadLocationException ex) {
                        throw new RuntimeException(ex);
                    }

                }
            } else {
                MyHttpHandler.diyRegexs.clear();
            }
            String timeStr =timeTextField.getText().trim();
            try{
                MyHttpHandler.intTime = Integer.parseInt(timeStr);
            }catch (NumberFormatException ne){
                MyHttpHandler.intTime=1000000;
            }

            String staticTimeStr =staticTimeTextField.getText().trim();
            try{
                MyHttpHandler.staticTime = Integer.parseInt(staticTimeStr);
            }catch (NumberFormatException ne){
                MyHttpHandler.staticTime=100;
            }

            String startTimeStr =startTimeTextField.getText().trim();
            try{
                MyHttpHandler.startTime = Integer.parseInt(startTimeStr);
            }catch (NumberFormatException ne){
                MyHttpHandler.startTime=0;
            }

            String endTimeStr =endTimeTextField.getText().trim();
            try{
                MyHttpHandler.endTime = Integer.parseInt(endTimeStr);
            }catch (NumberFormatException ne){
                MyHttpHandler.endTime=0;
            }
            String blackPathStr=blackPathTextArea.getText();
            if (!blackPathStr.isBlank()) {
                MyFilterRequest.blackPathSet.clear();
                Element paragraph = blackPathTextArea.getDocument().getDefaultRootElement();
                int contentCount = paragraph.getElementCount();
                for (int i = 0; i < contentCount; i++) {
                    Element ee = paragraph.getElement(i);
                    int rangeStart = ee.getStartOffset();
                    int rangeEnd = ee.getEndOffset();
                    String line = null;
                    try {
                        line = blackPathTextArea.getText(rangeStart, rangeEnd - rangeStart).replaceFirst("[\n\r]+$", "");
                        MyFilterRequest.blackPathSet.add(line);
                    } catch (BadLocationException ex) {
                        throw new RuntimeException(ex);
                    }

                }
            } else {
                MyFilterRequest.blackPathSet.clear();
            }

        });
        JButton loadBt = new JButton("载入");
        loadBt.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setCurrentDirectory(new File("."));
            fileChooser.setPreferredSize(new Dimension(800, 600));
            int result = fileChooser.showSaveDialog(null);
            String message = "";
            if (result == JFileChooser.APPROVE_OPTION) {
                message = "Load success";
                configTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
                Properties prop = new Properties();
                try {
                    FileReader fileReader = new FileReader(fileChooser.getSelectedFile());
                    prop.load(fileReader);
                    textField.setText(prop.getProperty("whitelist", ""));
                    if (!prop.getProperty("whitelist", "").isBlank()) {
                        MyFilterRequest.whiteListSet = new HashSet<>(Arrays.asList(prop.getProperty("whitelist", "").split("\\|")));
                    } else {
                        MyFilterRequest.whiteListSet = new HashSet<>();
                    }
                    blackTextField.setText(prop.getProperty("blacklist", ""));
                    if (!prop.getProperty("blacklist", "").isBlank()) {
                        MyFilterRequest.blackListSet = new HashSet<>(Arrays.asList(prop.getProperty("blacklist", "").split("\\|")));
                    } else {
                        MyFilterRequest.blackListSet = new HashSet<>();
                    }
                    blackParamsField.setText(prop.getProperty("paramslist", ""));
                    if (!prop.getProperty("paramslist", "").isBlank()) {
                        MyHttpHandler.blackParamsSet = new HashSet<>(Arrays.asList(prop.getProperty("paramslist", "").split("\\|")));
                    } else {
                        MyHttpHandler.blackParamsSet = new HashSet<>();
                    }
                    suffixTextField.setText(prop.getProperty("suffixlist", "wma|csv|mov|doc|3g2|mp4|7z|3gp|xbm|jar|avi|ogv|mpv2|tiff|pnm|jpg|xpm|xul|epub|au|aac|midi|weba|tar|js|rtf|bin|woff|wmv|tif|css|gif|flv|ttf|html|eot|ods|odt|webm|mpg|mjs|bz|ics|ras|aifc|mpa|ppt|mpeg|pptx|oga|ra|aiff|asf|woff2|snd|xwd|csh|webp|xlsx|mpkg|vsd|mid|wav|svg|mp3|bz2|ico|jpe|pbm|gz|pdf|log|jpeg|rmi|txt|arc|rm|ppm|cod|jfif|ram|docx|mpe|odp|otf|pgm|cmx|m3u|mp2|cab|rar|bmp|rgb|png|azw|ogx|aif|zip|ief|htm|xls|mpp|swf|rmvb|abw"));
                    if (!prop.getProperty("suffixlist", "wma|csv|mov|doc|3g2|mp4|7z|3gp|xbm|jar|avi|ogv|mpv2|tiff|pnm|jpg|xpm|xul|epub|au|aac|midi|weba|tar|js|rtf|bin|woff|wmv|tif|css|gif|flv|ttf|html|eot|ods|odt|webm|mpg|mjs|bz|ics|ras|aifc|mpa|ppt|mpeg|pptx|oga|ra|aiff|asf|woff2|snd|xwd|csh|webp|xlsx|mpkg|vsd|mid|wav|svg|mp3|bz2|ico|jpe|pbm|gz|pdf|log|jpeg|rmi|txt|arc|rm|ppm|cod|jfif|ram|docx|mpe|odp|otf|pgm|cmx|m3u|mp2|cab|rar|bmp|rgb|png|azw|ogx|aif|zip|ief|htm|xls|mpp|swf|rmvb|abw").isBlank()) {
                        MyFilterRequest.unLegalExtensionSet = new HashSet<>(Arrays.asList(prop.getProperty("suffixlist", "wma|csv|mov|doc|3g2|mp4|7z|3gp|xbm|jar|avi|ogv|mpv2|tiff|pnm|jpg|xpm|xul|epub|au|aac|midi|weba|tar|js|rtf|bin|woff|wmv|tif|css|gif|flv|ttf|html|eot|ods|odt|webm|mpg|mjs|bz|ics|ras|aifc|mpa|ppt|mpeg|pptx|oga|ra|aiff|asf|woff2|snd|xwd|csh|webp|xlsx|mpkg|vsd|mid|wav|svg|mp3|bz2|ico|jpe|pbm|gz|pdf|log|jpeg|rmi|txt|arc|rm|ppm|cod|jfif|ram|docx|mpe|odp|otf|pgm|cmx|m3u|mp2|cab|rar|bmp|rgb|png|azw|ogx|aif|zip|ief|htm|xls|mpp|swf|rmvb|abw").split("\\|")));
                    } else {
                        MyFilterRequest.unLegalExtensionSet = new HashSet<>(Arrays.asList("wma", "csv", "mov", "doc", "3g2", "mp4", "7z", "3gp", "xbm", "jar", "avi", "ogv", "mpv2", "tiff", "pnm", "jpg", "xpm", "xul", "epub", "au", "aac", "midi", "weba", "tar", "js", "rtf", "bin", "woff", "wmv", "tif", "css", "gif", "flv", "ttf", "html", "eot", "ods", "odt", "webm", "mpg", "mjs", "bz", "ics", "ras", "aifc", "mpa", "ppt", "mpeg", "pptx", "oga", "ra", "aiff", "asf", "woff2", "snd", "xwd", "csh", "webp", "xlsx", "mpkg", "vsd", "mid", "wav", "svg", "mp3", "bz2", "ico", "jpe", "pbm", "gz", "pdf", "log", "jpeg", "rmi", "txt", "arc", "rm", "ppm", "cod", "jfif", "ram", "docx", "mpe", "odp", "otf", "pgm", "cmx", "m3u", "mp2", "cab", "rar", "bmp", "rgb", "png", "azw", "ogx", "aif", "zip", "ief", "htm", "xls", "mpp", "swf", "rmvb", "abw"));
                    }
                    errorPocTextField.setText(prop.getProperty("errpoclist", ""));
                    if (!prop.getProperty("errpoclist", "").isBlank()) {
                        MyHttpHandler.errPocs = prop.getProperty("errpoclist", "").split("\\|");
                        MyHttpHandler.errPocsj = prop.getProperty("errpoclist", "").split("\\|");
                    } else {
                        MyHttpHandler.errPocs = new String[]{"'", "%27", "%DF'", "%DF%27", "\"", "%22", "%DF\"", "%DF%22", "`"};
                        MyHttpHandler.errPocsj = new String[]{"'", "%27", "%DF'", "%DF%27", "\\\"", "%22", "%DF\\\"", "%DF%22", "\\u0022", "%DF\\u0022", "\\u0027", "%DF\\u0027", "`"};
                    }
                    timeTextField.setText(prop.getProperty("delaytime", "5000"));
                    String timeStr =prop.getProperty("delaytime", "").trim();
                    try{
                        MyHttpHandler.intTime = Integer.parseInt(timeStr);
                    }catch (NumberFormatException ne){
                        MyHttpHandler.intTime=1000000;
                    }
                    staticTimeTextField.setText(prop.getProperty("statictime", "100"));
                    String staticTimeStr =prop.getProperty("statictime", "").trim();
                    try{
                        MyHttpHandler.staticTime = Integer.parseInt(staticTimeStr);
                    }catch (NumberFormatException ne){
                        MyHttpHandler.staticTime=100;
                    }
                    startTimeTextField.setText(prop.getProperty("starttime", "0"));
                    String startTimeStr =prop.getProperty("starttime", "").trim();
                    try{
                        MyHttpHandler.startTime = Integer.parseInt(startTimeStr);
                    }catch (NumberFormatException ne){
                        MyHttpHandler.startTime=0;
                    }
                    endTimeTextField.setText(prop.getProperty("endtime", "0"));
                    String endTimeStr =prop.getProperty("endtime", "").trim();
                    try{
                        MyHttpHandler.endTime = Integer.parseInt(endTimeStr);
                    }catch (NumberFormatException ne){
                        MyHttpHandler.endTime=0;
                    }
                    diyTextArea.setText(prop.getProperty("diypayloads", ""));
                    if (!prop.getProperty("diypayloads", "").isBlank()) {
                        MyHttpHandler.diyPayloads.clear();
                        Element paragraph = diyTextArea.getDocument().getDefaultRootElement();
                        int contentCount = paragraph.getElementCount();
                        for (int i = 0; i < contentCount; i++) {
                            Element ee = paragraph.getElement(i);
                            int rangeStart = ee.getStartOffset();
                            int rangeEnd = ee.getEndOffset();
                            String line = null;
                            try {
                                line = diyTextArea.getText(rangeStart, rangeEnd - rangeStart).replaceFirst("[\n\r]+$", "");
                                MyHttpHandler.diyPayloads.add(line);
                            } catch (BadLocationException ex) {
                                throw new RuntimeException(ex);
                            }

                        }
                    } else {
                        MyHttpHandler.diyPayloads.clear();
                    }
                    regexTextArea.setText(prop.getProperty("diyregex", ""));
                    if (!prop.getProperty("diyregex", "").isBlank()) {
                        MyHttpHandler.diyRegexs.clear();
                        Element paragraph = regexTextArea.getDocument().getDefaultRootElement();
                        int contentCount = paragraph.getElementCount();
                        for (int i = 0; i < contentCount; i++) {
                            Element ee = paragraph.getElement(i);
                            int rangeStart = ee.getStartOffset();
                            int rangeEnd = ee.getEndOffset();
                            String line = null;
                            try {
                                line = regexTextArea.getText(rangeStart, rangeEnd - rangeStart).replaceFirst("[\n\r]+$", "");
                                //api.logging().logToOutput(line);
                                MyHttpHandler.diyRegexs.add(line);
                            } catch (BadLocationException ex) {
                                throw new RuntimeException(ex);
                            }

                        }
                    } else {
                        MyHttpHandler.diyRegexs.clear();
                    }
                    blackPathTextArea.setText(prop.getProperty("blackpath", ""));
                    if (!prop.getProperty("blackpath", "").isBlank()) {
                        MyFilterRequest.blackPathSet.clear();
                        Element paragraph = blackPathTextArea.getDocument().getDefaultRootElement();
                        int contentCount = paragraph.getElementCount();
                        for (int i = 0; i < contentCount; i++) {
                            Element ee = paragraph.getElement(i);
                            int rangeStart = ee.getStartOffset();
                            int rangeEnd = ee.getEndOffset();
                            String line = null;
                            try {
                                line = blackPathTextArea.getText(rangeStart, rangeEnd - rangeStart).replaceFirst("[\n\r]+$", "");
                                MyFilterRequest.blackPathSet.add(line);

                            } catch (BadLocationException ex) {
                                throw new RuntimeException(ex);
                            }

                        }
                        //api.logging().logToOutput(MyFilterRequest.blackPathSet.toString());
                    } else {
                        MyFilterRequest.blackPathSet.clear();
                    }

                    switchChexk.setSelected(Boolean.parseBoolean(prop.getProperty("switch")));
                    cookieChexk.setSelected(Boolean.parseBoolean(prop.getProperty("cookiecheck")));
                    errorChexk.setSelected(Boolean.parseBoolean(prop.getProperty("errorcheck")));
                    vulnChexk.setSelected(Boolean.parseBoolean(prop.getProperty("repeatercheck")));
                    numChexk.setSelected(Boolean.parseBoolean(prop.getProperty("numcheck")));
                    stringChexk.setSelected(Boolean.parseBoolean(prop.getProperty("stringcheck")));
                    orderChexk.setSelected(Boolean.parseBoolean(prop.getProperty("ordercheck")));
                    boolChexk.setSelected(Boolean.parseBoolean(prop.getProperty("boolcheck")));
                    diyChexk.setSelected(Boolean.parseBoolean(prop.getProperty("diycheck")));
                    fileReader.close();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            } else if (result == JFileChooser.CANCEL_OPTION) {
                message = "Load cancel";
            }
            JOptionPane.showMessageDialog(null, message, "Load", JOptionPane.INFORMATION_MESSAGE);
        });
        JButton saveBt = new JButton("保存");
        saveBt.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setPreferredSize(new Dimension(800, 600));
            int result = fileChooser.showSaveDialog(null);
            String message = "";
            if (result == JFileChooser.APPROVE_OPTION) {
                message = "Save success";
                Properties prop = new Properties();
                prop.setProperty("whitelist", DetSql.textField.getText());
                prop.setProperty("blacklist", DetSql.blackTextField.getText());
                prop.setProperty("suffixlist", DetSql.suffixTextField.getText());
                prop.setProperty("errpoclist", DetSql.errorPocTextField.getText());
                prop.setProperty("paramslist", DetSql.blackParamsField.getText());
                prop.setProperty("delaytime", DetSql.timeTextField.getText());
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
                try {
                    FileWriter fw = new FileWriter(fileChooser.getSelectedFile());
                    prop.store(fw, null);
                    fw.close();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            } else if (result == JFileChooser.CANCEL_OPTION) {
                message = "Save cancel";
            }
            JOptionPane.showMessageDialog(null, message, "Save", JOptionPane.INFORMATION_MESSAGE);
        });


        Spring st = Spring.constant(10);
        Spring st2 = Spring.constant(35);
        Spring st3 = Spring.constant(100);
        Spring st4 = Spring.constant(200);


        container.add(topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, topicLabel, st, SpringLayout.NORTH, container);
        springLayout.putConstraint(SpringLayout.WEST, topicLabel, st, SpringLayout.WEST, container);

        container.add(textField);
        springLayout.putConstraint(SpringLayout.WEST, textField, st2, SpringLayout.EAST, topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, textField, 0, SpringLayout.NORTH, topicLabel);
        springLayout.putConstraint(SpringLayout.EAST, textField, Spring.minus(st), SpringLayout.EAST, container);
        //白名单
        container.add(blackLabel);
        springLayout.putConstraint(SpringLayout.WEST, blackLabel, 0, SpringLayout.WEST, topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, blackLabel, st, SpringLayout.SOUTH, topicLabel);

        container.add(blackTextField);
        springLayout.putConstraint(SpringLayout.WEST, blackTextField, 0, SpringLayout.WEST, textField);
        springLayout.putConstraint(SpringLayout.NORTH, blackTextField, 0, SpringLayout.NORTH, blackLabel);
        springLayout.putConstraint(SpringLayout.EAST, blackTextField, Spring.minus(st), SpringLayout.EAST, container);
        //后缀
        container.add(suffixLabel);
        springLayout.putConstraint(SpringLayout.WEST, suffixLabel, 0, SpringLayout.WEST, blackLabel);
        springLayout.putConstraint(SpringLayout.NORTH, suffixLabel, st, SpringLayout.SOUTH, blackLabel);

        container.add(suffixTextField);
        springLayout.putConstraint(SpringLayout.WEST, suffixTextField, 0, SpringLayout.WEST, textField);
        springLayout.putConstraint(SpringLayout.NORTH, suffixTextField, 0, SpringLayout.NORTH, suffixLabel);
        springLayout.putConstraint(SpringLayout.EAST, suffixTextField, Spring.minus(st), SpringLayout.EAST, container);
        //自定义报错poc
        container.add(errorPocLabel);
        springLayout.putConstraint(SpringLayout.WEST, errorPocLabel, 0, SpringLayout.WEST, suffixLabel);
        springLayout.putConstraint(SpringLayout.NORTH, errorPocLabel, st, SpringLayout.SOUTH, suffixLabel);

        container.add(errorPocTextField);
        springLayout.putConstraint(SpringLayout.WEST, errorPocTextField, 0, SpringLayout.WEST, textField);
        springLayout.putConstraint(SpringLayout.NORTH, errorPocTextField, 0, SpringLayout.NORTH, errorPocLabel);
        springLayout.putConstraint(SpringLayout.EAST, errorPocTextField, Spring.minus(st), SpringLayout.EAST, container);
        //新加参数黑名单
        container.add(blackParams);
        springLayout.putConstraint(SpringLayout.WEST, blackParams, 0, SpringLayout.WEST, errorPocLabel);
        springLayout.putConstraint(SpringLayout.NORTH, blackParams, st, SpringLayout.SOUTH, errorPocLabel);

        container.add(blackParamsField);
        springLayout.putConstraint(SpringLayout.WEST, blackParamsField, 0, SpringLayout.WEST, textField);
        springLayout.putConstraint(SpringLayout.NORTH, blackParamsField, 0, SpringLayout.NORTH, blackParams);
        springLayout.putConstraint(SpringLayout.EAST, blackParamsField, Spring.minus(st), SpringLayout.EAST, container);

        container.add(switchChexk);
        springLayout.putConstraint(SpringLayout.WEST, switchChexk, 0, SpringLayout.WEST, blackParams);
        springLayout.putConstraint(SpringLayout.NORTH, switchChexk, st, SpringLayout.SOUTH, blackParams);

        container.add(cookieChexk);
        springLayout.putConstraint(SpringLayout.WEST, cookieChexk, st2, SpringLayout.EAST, switchChexk);
        springLayout.putConstraint(SpringLayout.NORTH, cookieChexk, 0, SpringLayout.NORTH, switchChexk);

        //container.add(errorChexk);
        //springLayout.putConstraint(SpringLayout.WEST, errorChexk, st2, SpringLayout.EAST, cookieChexk);
        //springLayout.putConstraint(SpringLayout.NORTH, errorChexk, 0, SpringLayout.NORTH, switchChexk);

        container.add(vulnChexk);
        springLayout.putConstraint(SpringLayout.WEST, vulnChexk, st2, SpringLayout.EAST, cookieChexk);
        springLayout.putConstraint(SpringLayout.NORTH, vulnChexk, 0, SpringLayout.NORTH, switchChexk);

        container.add(errorChexk);
        springLayout.putConstraint(SpringLayout.WEST, errorChexk, st2, SpringLayout.EAST, vulnChexk);
        springLayout.putConstraint(SpringLayout.NORTH, errorChexk, 0, SpringLayout.NORTH, switchChexk);

        container.add(numChexk);
        springLayout.putConstraint(SpringLayout.WEST, numChexk, st2, SpringLayout.EAST, errorChexk);
        springLayout.putConstraint(SpringLayout.NORTH, numChexk, 0, SpringLayout.NORTH, switchChexk);

        container.add(stringChexk);
        springLayout.putConstraint(SpringLayout.WEST, stringChexk, st2, SpringLayout.EAST, numChexk);
        springLayout.putConstraint(SpringLayout.NORTH, stringChexk, 0, SpringLayout.NORTH, switchChexk);

        container.add(orderChexk);
        springLayout.putConstraint(SpringLayout.WEST, orderChexk, st2, SpringLayout.EAST, stringChexk);
        springLayout.putConstraint(SpringLayout.NORTH, orderChexk, 0, SpringLayout.NORTH, switchChexk);

        container.add(boolChexk);
        springLayout.putConstraint(SpringLayout.WEST, boolChexk, st2, SpringLayout.EAST, orderChexk);
        springLayout.putConstraint(SpringLayout.NORTH, boolChexk, 0, SpringLayout.NORTH, switchChexk);

        container.add(diyChexk);
        springLayout.putConstraint(SpringLayout.WEST, diyChexk, st2, SpringLayout.EAST, boolChexk);
        springLayout.putConstraint(SpringLayout.NORTH, diyChexk, 0, SpringLayout.NORTH, switchChexk);

        container.add(conBt);
        springLayout.putConstraint(SpringLayout.WEST, conBt, st2, SpringLayout.EAST, diyChexk);
        springLayout.putConstraint(SpringLayout.NORTH, conBt, 0, SpringLayout.NORTH, switchChexk);

        container.add(configLabel);
        springLayout.putConstraint(SpringLayout.WEST, configLabel, 0, SpringLayout.WEST, blackLabel);
        springLayout.putConstraint(SpringLayout.NORTH, configLabel, st, SpringLayout.SOUTH, switchChexk);

        container.add(configTextField);
        springLayout.putConstraint(SpringLayout.WEST, configTextField, 0, SpringLayout.WEST, blackTextField);
        springLayout.putConstraint(SpringLayout.NORTH, configTextField, 0, SpringLayout.NORTH, configLabel);
        springLayout.putConstraint(SpringLayout.EAST, configTextField, Spring.minus(st4), SpringLayout.EAST, container);

        container.add(loadBt);
        springLayout.putConstraint(SpringLayout.NORTH, loadBt, 0, SpringLayout.NORTH, configLabel);
        springLayout.putConstraint(SpringLayout.EAST, loadBt, Spring.minus(st3), SpringLayout.EAST, container);

        container.add(saveBt);
        springLayout.putConstraint(SpringLayout.NORTH, saveBt, 0, SpringLayout.NORTH, configLabel);
        springLayout.putConstraint(SpringLayout.EAST, saveBt, Spring.minus(st), SpringLayout.EAST, container);

        container.add(blackPathLabel);
        springLayout.putConstraint(SpringLayout.WEST, blackPathLabel, 0, SpringLayout.WEST, configLabel);
        springLayout.putConstraint(SpringLayout.NORTH, blackPathLabel, st, SpringLayout.SOUTH, configLabel);

        container.add(blackPathScrollPane);
        springLayout.putConstraint(SpringLayout.WEST, blackPathScrollPane, 0, SpringLayout.WEST, textField);
        springLayout.putConstraint(SpringLayout.NORTH, blackPathScrollPane, 0, SpringLayout.NORTH, blackPathLabel);
        springLayout.putConstraint(SpringLayout.EAST, blackPathScrollPane, Spring.minus(st), SpringLayout.EAST, container);
        //springLayout.putConstraint(SpringLayout.EAST, diyScrollPane, -10, SpringLayout.HORIZONTAL_CENTER, container);

        container.add(diyLabel);
        springLayout.putConstraint(SpringLayout.NORTH, diyLabel, st, SpringLayout.SOUTH, blackPathScrollPane);
        springLayout.putConstraint(SpringLayout.WEST, diyLabel, 0, SpringLayout.WEST, blackParams);
        container.add(resRegexLabel);
        //SpringLayout.Constraints contentLabeln = springLayout.getConstraints(resRegexLabel);
        springLayout.putConstraint(SpringLayout.WEST, resRegexLabel, 10, SpringLayout.HORIZONTAL_CENTER, container);
        springLayout.putConstraint(SpringLayout.NORTH, resRegexLabel, st, SpringLayout.SOUTH, blackPathScrollPane);

        container.add(diyScrollPane);
        springLayout.putConstraint(SpringLayout.WEST, diyScrollPane, 0, SpringLayout.WEST, textField);
        springLayout.putConstraint(SpringLayout.NORTH, diyScrollPane, 0, SpringLayout.NORTH, diyLabel);
        springLayout.putConstraint(SpringLayout.EAST, diyScrollPane, -10, SpringLayout.HORIZONTAL_CENTER, container);

        container.add(regexScrollPane);
        springLayout.putConstraint(SpringLayout.WEST, regexScrollPane, 10, SpringLayout.EAST, resRegexLabel);
        springLayout.putConstraint(SpringLayout.NORTH, regexScrollPane, 0, SpringLayout.NORTH, diyLabel);
        springLayout.putConstraint(SpringLayout.EAST, regexScrollPane, Spring.minus(st), SpringLayout.EAST, container);

        container.add(timeLabel);
        springLayout.putConstraint(SpringLayout.WEST, timeLabel, 0, SpringLayout.WEST, resRegexLabel);
        springLayout.putConstraint(SpringLayout.NORTH, timeLabel, st, SpringLayout.SOUTH, regexScrollPane);

        container.add(timeTextField);
        springLayout.putConstraint(SpringLayout.WEST, timeTextField, 0, SpringLayout.WEST, regexScrollPane);
        springLayout.putConstraint(SpringLayout.NORTH, timeTextField, 0, SpringLayout.NORTH, timeLabel);

        container.add(staticTimeLabel);
        springLayout.putConstraint(SpringLayout.WEST, staticTimeLabel, 0, SpringLayout.WEST, resRegexLabel);
        springLayout.putConstraint(SpringLayout.NORTH, staticTimeLabel, st, SpringLayout.SOUTH, timeLabel);

        container.add(staticTimeTextField);
        springLayout.putConstraint(SpringLayout.WEST, staticTimeTextField, 0, SpringLayout.WEST, regexScrollPane);
        springLayout.putConstraint(SpringLayout.NORTH, staticTimeTextField, 0, SpringLayout.NORTH, staticTimeLabel);

        container.add(startTimeLabel);
        springLayout.putConstraint(SpringLayout.WEST, startTimeLabel, 0, SpringLayout.WEST, resRegexLabel);
        springLayout.putConstraint(SpringLayout.NORTH, startTimeLabel, st, SpringLayout.SOUTH, staticTimeLabel);

        container.add(startTimeTextField);
        springLayout.putConstraint(SpringLayout.WEST, startTimeTextField, 0, SpringLayout.WEST, regexScrollPane);
        springLayout.putConstraint(SpringLayout.NORTH, startTimeTextField, 0, SpringLayout.NORTH, startTimeLabel);

        container.add(endTimeLabel);
        springLayout.putConstraint(SpringLayout.WEST, endTimeLabel, st, SpringLayout.EAST, startTimeTextField);
        springLayout.putConstraint(SpringLayout.NORTH, endTimeLabel, 0, SpringLayout.NORTH, startTimeLabel);

        container.add(endTimeTextField);
        springLayout.putConstraint(SpringLayout.WEST, endTimeTextField, st, SpringLayout.EAST, endTimeLabel);
        springLayout.putConstraint(SpringLayout.NORTH, endTimeTextField, 0, SpringLayout.NORTH, startTimeLabel);
        return container;
    }

    public String myBase64Decode(String base64Str) {
        byte[] decodedBytes = Base64.getDecoder().decode(base64Str);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }

    public String myBase64Encode(String text) {
        byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
        return Base64.getEncoder().encodeToString(textBytes);
    }

    public String decodeUnicode(String unicodeStr) {
        StringBuffer sb = new StringBuffer();
        Matcher matcher = Pattern.compile("\\\\u([0-9a-fA-F]{4})").matcher(unicodeStr);
        while (matcher.find()) {
            String ch = String.valueOf((char) Integer.parseInt(matcher.group(1), 16));
            sb.append(ch);
        }
        return sb.toString();
    }

    public String unicodeEncode(String string) {
        char[] utfBytes = string.toCharArray();
        String unicodeBytes = "";
        for (int i = 0; i < utfBytes.length; i++) {
            String hexB = Integer.toHexString(utfBytes[i]);
            if (hexB.length() <= 2) {
                hexB = "00" + hexB;
            }
            unicodeBytes = unicodeBytes + "\\u" + hexB;
        }
        return unicodeBytes;
    }

    public String encodeUrl(String text) {
        return URLEncoder.encode(text, StandardCharsets.UTF_8);
    }

    public String decodeUrl(String urlStr) {
        return URLDecoder.decode(urlStr, StandardCharsets.UTF_8);
    }

    private String toPrettyFormat(String json) {
        JsonParser jsonParser = new JsonParser();
        JsonObject jsonObject = jsonParser.parse(json).getAsJsonObject();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(jsonObject);
    }

    private Component getToolComponent() {

        Container container = new JPanel();
        SpringLayout springLayout = new SpringLayout();
        container.setLayout(springLayout);
        JLabel topicLabel = new JLabel("base64编码值:");
        JLabel contentLabel = new JLabel("base64解码值:");
        JLabel unicodeLabel = new JLabel("unicode编解码:");
        JLabel unicodexLabel = new JLabel("unicode解码值:");

        JLabel urlLabel = new JLabel("url中文编解码:");

        JTextArea textArea = new JTextArea(14, 6);
        JScrollPane scrollPane = new JScrollPane();
        scrollPane.setViewportView(textArea);
        textArea.setLineWrap(true);

        JTextArea textArea2 = new JTextArea(30, 6);
        JScrollPane scrollPane2 = new JScrollPane();
        scrollPane2.setViewportView(textArea2);
        textArea2.setLineWrap(true);

        JTextArea textArea3 = new JTextArea(6, 6);
        JScrollPane scrollPane3 = new JScrollPane();
        scrollPane3.setViewportView(textArea3);
        textArea3.setLineWrap(true);

        JTextArea textArea4 = new JTextArea(6, 6);
        JScrollPane scrollPane4 = new JScrollPane();
        scrollPane4.setViewportView(textArea4);
        textArea4.setLineWrap(true);

        JTextArea textArea5 = new JTextArea(6, 6);
        JScrollPane scrollPane5 = new JScrollPane();
        scrollPane5.setViewportView(textArea5);
        textArea5.setLineWrap(true);

        JButton encBt = new JButton("base64解码->");
        int offsetx = Spring.width(encBt).getValue() / 2;
        encBt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String text = textArea.getText();
                if (!text.isEmpty()) {
                    String decodedText = myBase64Decode(text);
                    textArea2.setText(decodedText);
                }
            }
        });
        JButton dedBt = new JButton("<-base64编码");
        dedBt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String text = textArea2.getText();
                if (!text.isEmpty()) {
                    String encodedText = myBase64Encode(text);
                    textArea.setText(encodedText);
                }
            }
        });

        JButton unBt = new JButton("unicode解码");
        unBt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String text = textArea3.getText();
                if (!text.isEmpty()) {
                    String mytext = decodeUnicode(text);
                    textArea3.setText(mytext);
                }
            }
        });
        JButton unxBt = new JButton("unicode编码");
        unxBt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String text = textArea3.getText();
                if (!text.isEmpty()) {
                    String mytext = unicodeEncode(text);
                    textArea3.setText(mytext);
                }
            }
        });
        JButton urlBt = new JButton("url编码");
        urlBt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String text = textArea5.getText();
                if (!text.isEmpty()) {
                    String encodedText = encodeUrl(text);
                    textArea5.setText(encodedText);
                }
            }
        });
        JButton urlxBt = new JButton("url解码");
        urlxBt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String text = textArea5.getText();
                if (!text.isEmpty()) {
                    String mytext = decodeUrl(text);
                    textArea5.setText(mytext);
                }
            }
        });
        JButton formatbt = new JButton("JSON格式化");
        formatbt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String text = textArea2.getText();
                if (!text.isEmpty()) {
                    String prettyText = toPrettyFormat(StringEscapeUtils.unescapeJava(text));
                    textArea2.setText(prettyText);
                }
            }
        });
        Spring st = Spring.constant(15);
        Spring st2 = Spring.constant(35);


        container.add(topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, topicLabel, st, SpringLayout.NORTH, container);
        springLayout.putConstraint(SpringLayout.WEST, topicLabel, st, SpringLayout.WEST, container);
        container.add(contentLabel);
        SpringLayout.Constraints contentLabeln = springLayout.getConstraints(contentLabel);
        springLayout.putConstraint(SpringLayout.WEST, contentLabel, 90, SpringLayout.HORIZONTAL_CENTER, container);
        contentLabeln.setY(st);

        container.add(scrollPane);
        springLayout.putConstraint(SpringLayout.WEST, scrollPane, 0, SpringLayout.WEST, topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, scrollPane, st, SpringLayout.SOUTH, topicLabel);
        springLayout.putConstraint(SpringLayout.EAST, scrollPane, -90, SpringLayout.HORIZONTAL_CENTER, container);

        container.add(scrollPane2);
        springLayout.putConstraint(SpringLayout.WEST, scrollPane2, 0, SpringLayout.WEST, contentLabel);
        springLayout.putConstraint(SpringLayout.NORTH, scrollPane2, 0, SpringLayout.NORTH, scrollPane);
        springLayout.putConstraint(SpringLayout.EAST, scrollPane2, Spring.minus(st), SpringLayout.EAST, container);
        container.add(encBt);
        springLayout.putConstraint(SpringLayout.WEST, encBt, -offsetx, SpringLayout.HORIZONTAL_CENTER, container);
        springLayout.putConstraint(SpringLayout.NORTH, encBt, st2, SpringLayout.NORTH, scrollPane);
        container.add(dedBt);
        springLayout.putConstraint(SpringLayout.WEST, dedBt, 0, SpringLayout.WEST, encBt);
        springLayout.putConstraint(SpringLayout.NORTH, dedBt, st, SpringLayout.SOUTH, encBt);

        container.add(unicodeLabel);
        springLayout.putConstraint(SpringLayout.WEST, unicodeLabel, 0, SpringLayout.WEST, topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, unicodeLabel, st, SpringLayout.SOUTH, scrollPane);
        container.add(scrollPane3);
        springLayout.putConstraint(SpringLayout.WEST, scrollPane3, 0, SpringLayout.WEST, scrollPane);
        springLayout.putConstraint(SpringLayout.NORTH, scrollPane3, st, SpringLayout.SOUTH, unicodeLabel);
        springLayout.putConstraint(SpringLayout.EAST, scrollPane3, 0, SpringLayout.EAST, scrollPane);
        container.add(unBt);
        springLayout.putConstraint(SpringLayout.WEST, unBt, 0, SpringLayout.WEST, encBt);
        springLayout.putConstraint(SpringLayout.NORTH, unBt, st2, SpringLayout.NORTH, scrollPane3);

        container.add(unxBt);
        springLayout.putConstraint(SpringLayout.WEST, unxBt, 0, SpringLayout.WEST, unBt);
        springLayout.putConstraint(SpringLayout.NORTH, unxBt, st, SpringLayout.SOUTH, unBt);
        container.add(urlLabel);
        springLayout.putConstraint(SpringLayout.WEST, urlLabel, 0, SpringLayout.WEST, topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, urlLabel, st, SpringLayout.SOUTH, scrollPane3);
        container.add(scrollPane5);
        springLayout.putConstraint(SpringLayout.WEST, scrollPane5, 0, SpringLayout.WEST, scrollPane);
        springLayout.putConstraint(SpringLayout.NORTH, scrollPane5, st, SpringLayout.SOUTH, urlLabel);
        springLayout.putConstraint(SpringLayout.EAST, scrollPane5, 0, SpringLayout.EAST, scrollPane);
        container.add(urlBt);
        springLayout.putConstraint(SpringLayout.WEST, urlBt, 0, SpringLayout.WEST, encBt);
        springLayout.putConstraint(SpringLayout.NORTH, urlBt, st2, SpringLayout.NORTH, scrollPane5);
        container.add(urlxBt);
        springLayout.putConstraint(SpringLayout.WEST, urlxBt, 0, SpringLayout.WEST, urlBt);
        springLayout.putConstraint(SpringLayout.NORTH, urlxBt, st, SpringLayout.SOUTH, urlBt);
        container.add(formatbt);
        springLayout.putConstraint(SpringLayout.EAST, formatbt, 0, SpringLayout.EAST, scrollPane2);
        springLayout.putConstraint(SpringLayout.NORTH, formatbt, st, SpringLayout.SOUTH, scrollPane2);

        return container;
    }

}
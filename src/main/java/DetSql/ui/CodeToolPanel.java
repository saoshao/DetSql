package DetSql.ui;

import DetSql.util.StringUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import javax.swing.*;
import java.awt.*;

/**
 * 代码工具面板 - 提供编码/解码工具
 * 从 DetSqlUI 中提取出来,遵循单一职责原则
 * 
 * 实现 LanguageChangeListener 以支持动态语言切换
 */
public class CodeToolPanel extends JPanel implements LanguageChangeListener {

    private static final int PADDING_MEDIUM = 15;
    private static final int PADDING_COMPONENT = 35;
    private static final int PADDING_CENTER_OFFSET = 90;

    // Base64: 输入/输出分离 (现有设计,正确)
    private JTextArea base64TextArea;
    private JTextArea decodedTextArea;

    // Unicode: 输入/输出分离 (新设计)
    private JTextArea unicodeInputArea;
    private JTextArea unicodeOutputArea;

    // URL: 输入/输出分离 (新设计)
    private JTextArea urlInputArea;
    private JTextArea urlOutputArea;

    // 保存所有 UI 组件引用以支持语言切换
    private JLabel topicLabel;
    private JLabel contentLabel;
    private JLabel unicodeInputLabel;
    private JLabel unicodeOutputLabel;
    private JLabel urlInputLabel;
    private JLabel urlOutputLabel;
    private JButton encBt;
    private JButton dedBt;
    private JButton unBt;
    private JButton unxBt;
    private JButton urlBt;
    private JButton urlxBt;
    private JButton formatbt;

    public CodeToolPanel() {
        initComponents();
        // 注册语言变更监听器
        LanguageManager.getInstance().addListener(this);
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        Container container = new JPanel();
        SpringLayout springLayout = new SpringLayout();
        container.setLayout(springLayout);

        // 使用 Messages.getString() 替代硬编码
        topicLabel = new JLabel(Messages.getString("codetool.base64_encode"));
        contentLabel = new JLabel(Messages.getString("codetool.base64_decode"));
        unicodeInputLabel = new JLabel(Messages.getString("codetool.unicode_input"));
        unicodeOutputLabel = new JLabel(Messages.getString("codetool.unicode_output"));
        urlInputLabel = new JLabel(Messages.getString("codetool.url_input"));
        urlOutputLabel = new JLabel(Messages.getString("codetool.url_output"));

        // Base64 文本框 (左右分栏，统一高度)
        base64TextArea = new JTextArea(12, 6);
        JScrollPane scrollPane = new JScrollPane();
        scrollPane.setViewportView(base64TextArea);
        base64TextArea.setLineWrap(true);

        decodedTextArea = new JTextArea(12, 6);
        JScrollPane scrollPane2 = new JScrollPane();
        scrollPane2.setViewportView(decodedTextArea);
        decodedTextArea.setLineWrap(true);

        // Unicode 文本框 (左右分栏)
        unicodeInputArea = new JTextArea(6, 6);
        JScrollPane unicodeInputScrollPane = new JScrollPane();
        unicodeInputScrollPane.setViewportView(unicodeInputArea);
        unicodeInputArea.setLineWrap(true);

        unicodeOutputArea = new JTextArea(6, 6);
        JScrollPane unicodeOutputScrollPane = new JScrollPane();
        unicodeOutputScrollPane.setViewportView(unicodeOutputArea);
        unicodeOutputArea.setLineWrap(true);

        // URL 文本框 (左右分栏)
        urlInputArea = new JTextArea(6, 6);
        JScrollPane urlInputScrollPane = new JScrollPane();
        urlInputScrollPane.setViewportView(urlInputArea);
        urlInputArea.setLineWrap(true);

        urlOutputArea = new JTextArea(6, 6);
        JScrollPane urlOutputScrollPane = new JScrollPane();
        urlOutputScrollPane.setViewportView(urlOutputArea);
        urlOutputArea.setLineWrap(true);

        // 按钮使用 Messages.getString() - 调整顺序:编码在前,解码在后
        dedBt = new JButton(Messages.getString("codetool.btn_base64_encode"));
        int offsetx = Spring.width(dedBt).getValue() / 2;
        encBt = new JButton(Messages.getString("codetool.btn_base64_decode"));
        unxBt = new JButton(Messages.getString("codetool.btn_unicode_encode"));
        unBt = new JButton(Messages.getString("codetool.btn_unicode_decode"));
        urlBt = new JButton(Messages.getString("codetool.btn_url_encode"));
        urlxBt = new JButton(Messages.getString("codetool.btn_url_decode"));
        formatbt = new JButton(Messages.getString("codetool.btn_json_format"));

        // 绑定事件处理器 - 输入/输出分离,顺序调整为编码在前
        addTextTransformListener(dedBt, decodedTextArea, base64TextArea, StringUtils::base64Encode);
        addTextTransformListener(encBt, base64TextArea, decodedTextArea, StringUtils::base64Decode);
        addTextTransformListener(unxBt, unicodeOutputArea, unicodeInputArea, StringUtils::unicodeEncode);
        addTextTransformListener(unBt, unicodeInputArea, unicodeOutputArea, StringUtils::unicodeDecode);
        addTextTransformListener(urlBt, urlInputArea, urlOutputArea, StringUtils::urlEncode);
        addTextTransformListener(urlxBt, urlOutputArea, urlInputArea, StringUtils::urlDecode);
        addTextTransformListener(formatbt, decodedTextArea, decodedTextArea,
                text -> toPrettyFormat(org.apache.commons.text.StringEscapeUtils.unescapeJava(text)));

        Spring st = Spring.constant(PADDING_MEDIUM);
        Spring st2 = Spring.constant(PADDING_COMPONENT);

        // 布局组件
        container.add(topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, topicLabel, st, SpringLayout.NORTH, container);
        springLayout.putConstraint(SpringLayout.WEST, topicLabel, st, SpringLayout.WEST, container);

        container.add(contentLabel);
        SpringLayout.Constraints contentLabeln = springLayout.getConstraints(contentLabel);
        springLayout.putConstraint(SpringLayout.WEST, contentLabel, PADDING_CENTER_OFFSET,
                SpringLayout.HORIZONTAL_CENTER, container);
        contentLabeln.setY(st);

        container.add(scrollPane);
        springLayout.putConstraint(SpringLayout.WEST, scrollPane, 0, SpringLayout.WEST, topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, scrollPane, st, SpringLayout.SOUTH, topicLabel);
        springLayout.putConstraint(SpringLayout.EAST, scrollPane, -PADDING_CENTER_OFFSET,
                SpringLayout.HORIZONTAL_CENTER, container);

        container.add(scrollPane2);
        springLayout.putConstraint(SpringLayout.WEST, scrollPane2, 0, SpringLayout.WEST, contentLabel);
        springLayout.putConstraint(SpringLayout.NORTH, scrollPane2, 0, SpringLayout.NORTH, scrollPane);
        springLayout.putConstraint(SpringLayout.EAST, scrollPane2, Spring.minus(st), SpringLayout.EAST, container);

        // 按钮顺序调整:编码在前(dedBt),解码在后(encBt)
        container.add(dedBt);
        springLayout.putConstraint(SpringLayout.WEST, dedBt, -offsetx, SpringLayout.HORIZONTAL_CENTER, container);
        springLayout.putConstraint(SpringLayout.NORTH, dedBt, st2, SpringLayout.NORTH, scrollPane);

        container.add(encBt);
        springLayout.putConstraint(SpringLayout.WEST, encBt, 0, SpringLayout.WEST, dedBt);
        springLayout.putConstraint(SpringLayout.NORTH, encBt, st, SpringLayout.SOUTH, dedBt);

        // Unicode 部分: 左侧输入,右侧输出
        container.add(unicodeInputLabel);
        springLayout.putConstraint(SpringLayout.WEST, unicodeInputLabel, 0, SpringLayout.WEST, topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, unicodeInputLabel, st, SpringLayout.SOUTH, scrollPane);

        container.add(unicodeOutputLabel);
        springLayout.putConstraint(SpringLayout.WEST, unicodeOutputLabel, PADDING_CENTER_OFFSET,
                SpringLayout.HORIZONTAL_CENTER, container);
        springLayout.putConstraint(SpringLayout.NORTH, unicodeOutputLabel, 0, SpringLayout.NORTH, unicodeInputLabel);

        container.add(unicodeInputScrollPane);
        springLayout.putConstraint(SpringLayout.WEST, unicodeInputScrollPane, 0, SpringLayout.WEST, scrollPane);
        springLayout.putConstraint(SpringLayout.NORTH, unicodeInputScrollPane, st, SpringLayout.SOUTH,
                unicodeInputLabel);
        springLayout.putConstraint(SpringLayout.EAST, unicodeInputScrollPane, -PADDING_CENTER_OFFSET,
                SpringLayout.HORIZONTAL_CENTER, container);

        container.add(unicodeOutputScrollPane);
        springLayout.putConstraint(SpringLayout.WEST, unicodeOutputScrollPane, 0, SpringLayout.WEST, contentLabel);
        springLayout.putConstraint(SpringLayout.NORTH, unicodeOutputScrollPane, 0, SpringLayout.NORTH,
                unicodeInputScrollPane);
        springLayout.putConstraint(SpringLayout.EAST, unicodeOutputScrollPane, Spring.minus(st), SpringLayout.EAST,
                container);

        // Unicode 按钮顺序:编码在前(unxBt),解码在后(unBt)
        container.add(unxBt);
        springLayout.putConstraint(SpringLayout.WEST, unxBt, 0, SpringLayout.WEST, dedBt);
        springLayout.putConstraint(SpringLayout.NORTH, unxBt, st2, SpringLayout.NORTH, unicodeInputScrollPane);

        container.add(unBt);
        springLayout.putConstraint(SpringLayout.WEST, unBt, 0, SpringLayout.WEST, unxBt);
        springLayout.putConstraint(SpringLayout.NORTH, unBt, st, SpringLayout.SOUTH, unxBt);

        // URL 部分: 左侧输入,右侧输出
        container.add(urlInputLabel);
        springLayout.putConstraint(SpringLayout.WEST, urlInputLabel, 0, SpringLayout.WEST, topicLabel);
        springLayout.putConstraint(SpringLayout.NORTH, urlInputLabel, st, SpringLayout.SOUTH, unicodeInputScrollPane);

        container.add(urlOutputLabel);
        springLayout.putConstraint(SpringLayout.WEST, urlOutputLabel, PADDING_CENTER_OFFSET,
                SpringLayout.HORIZONTAL_CENTER, container);
        springLayout.putConstraint(SpringLayout.NORTH, urlOutputLabel, 0, SpringLayout.NORTH, urlInputLabel);

        container.add(urlInputScrollPane);
        springLayout.putConstraint(SpringLayout.WEST, urlInputScrollPane, 0, SpringLayout.WEST, scrollPane);
        springLayout.putConstraint(SpringLayout.NORTH, urlInputScrollPane, st, SpringLayout.SOUTH, urlInputLabel);
        springLayout.putConstraint(SpringLayout.EAST, urlInputScrollPane, -PADDING_CENTER_OFFSET,
                SpringLayout.HORIZONTAL_CENTER, container);

        container.add(urlOutputScrollPane);
        springLayout.putConstraint(SpringLayout.WEST, urlOutputScrollPane, 0, SpringLayout.WEST, contentLabel);
        springLayout.putConstraint(SpringLayout.NORTH, urlOutputScrollPane, 0, SpringLayout.NORTH, urlInputScrollPane);
        springLayout.putConstraint(SpringLayout.EAST, urlOutputScrollPane, Spring.minus(st), SpringLayout.EAST,
                container);

        // URL 按钮顺序:编码在前(urlBt),解码在后(urlxBt) - 已经正确,不需调整
        container.add(urlBt);
        springLayout.putConstraint(SpringLayout.WEST, urlBt, 0, SpringLayout.WEST, dedBt);
        springLayout.putConstraint(SpringLayout.NORTH, urlBt, st2, SpringLayout.NORTH, urlInputScrollPane);

        container.add(urlxBt);
        springLayout.putConstraint(SpringLayout.WEST, urlxBt, 0, SpringLayout.WEST, urlBt);
        springLayout.putConstraint(SpringLayout.NORTH, urlxBt, st, SpringLayout.SOUTH, urlBt);

        container.add(formatbt);
        springLayout.putConstraint(SpringLayout.EAST, formatbt, 0, SpringLayout.EAST, scrollPane2);
        springLayout.putConstraint(SpringLayout.NORTH, formatbt, st, SpringLayout.SOUTH, scrollPane2);

        add(new JScrollPane(container), BorderLayout.CENTER);
    }

    /**
     * 添加文本转换监听器
     * 支持选中文本替换:如果有选中文本,只转换选中部分;否则转换整个文本
     */
    private void addTextTransformListener(JButton button, JTextArea source, JTextArea target,
            java.util.function.Function<String, String> transformer) {
        button.addActionListener(e -> {
            String selectedText = source.getSelectedText();

            if (selectedText != null && !selectedText.isEmpty()) {
                // 有选中文本:只转换选中部分并替换
                try {
                    String transformedText = transformer.apply(selectedText);
                    int start = source.getSelectionStart();
                    int end = source.getSelectionEnd();

                    // 替换选中文本
                    String fullText = source.getText();
                    String newText = fullText.substring(0, start) + transformedText + fullText.substring(end);
                    source.setText(newText);

                    // 选中替换后的文本
                    source.setSelectionStart(start);
                    source.setSelectionEnd(start + transformedText.length());
                } catch (Exception ex) {
                    // 转换失败,保持原样
                }
            } else {
                // 无选中文本:转换整个source文本到target
                String text = source.getText();
                if (!text.isEmpty()) {
                    try {
                        String newText = transformer.apply(text);
                        target.setText(newText);

                        // 如果source和target是同一个组件,保持光标在末尾
                        if (source == target) {
                            target.setCaretPosition(newText.length());
                        }
                    } catch (Exception ex) {
                        // 转换失败,保持原样
                    }
                }
            }
        });
    }

    /**
     * 格式化 JSON
     */
    private String toPrettyFormat(String json) {
        JsonObject jsonObject = JsonParser.parseString(json).getAsJsonObject();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(jsonObject);
    }

    /**
     * 实现 LanguageChangeListener 接口
     * 响应全局语言变更事件,更新所有标签和按钮文本
     */
    @Override
    public void onLanguageChanged() {
        SwingUtilities.invokeLater(() -> {
            // 更新所有标签
            if (topicLabel != null) {
                topicLabel.setText(Messages.getString("codetool.base64_encode"));
            }
            if (contentLabel != null) {
                contentLabel.setText(Messages.getString("codetool.base64_decode"));
            }
            if (unicodeInputLabel != null) {
                unicodeInputLabel.setText(Messages.getString("codetool.unicode_input"));
            }
            if (unicodeOutputLabel != null) {
                unicodeOutputLabel.setText(Messages.getString("codetool.unicode_output"));
            }
            if (urlInputLabel != null) {
                urlInputLabel.setText(Messages.getString("codetool.url_input"));
            }
            if (urlOutputLabel != null) {
                urlOutputLabel.setText(Messages.getString("codetool.url_output"));
            }

            // 更新所有按钮
            if (encBt != null) {
                encBt.setText(Messages.getString("codetool.btn_base64_decode"));
            }
            if (dedBt != null) {
                dedBt.setText(Messages.getString("codetool.btn_base64_encode"));
            }
            if (unBt != null) {
                unBt.setText(Messages.getString("codetool.btn_unicode_decode"));
            }
            if (unxBt != null) {
                unxBt.setText(Messages.getString("codetool.btn_unicode_encode"));
            }
            if (urlBt != null) {
                urlBt.setText(Messages.getString("codetool.btn_url_encode"));
            }
            if (urlxBt != null) {
                urlxBt.setText(Messages.getString("codetool.btn_url_decode"));
            }
            if (formatbt != null) {
                formatbt.setText(Messages.getString("codetool.btn_json_format"));
            }
        });
    }
}

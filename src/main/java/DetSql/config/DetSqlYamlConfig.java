/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * YAML 配置文件的 POJO 类
 * 用于序列化和反序列化配置
 */
public class DetSqlYamlConfig {
    // 域名白名单
    private List<String> whitelist = new ArrayList<>();
    
    // 域名黑名单
    private List<String> blacklist = new ArrayList<>();
    
    // 禁止后缀列表
    private List<String> suffixlist = new ArrayList<>();
    
    // 错误类型 POC 列表
    private List<String> errpoclist = new ArrayList<>();
    
    // 参数黑名单
    private List<String> paramslist = new ArrayList<>();
    
    // 路径黑名单（多行文本）
    private String blackpath = "";
    
    // 自定义 Payload（多行文本）
    private String diypayloads = "";
    
    // 自定义正则表达式（多行文本）
    private String diyregex = "";
    
    // 响应延迟时间（毫秒）
    private int delaytime = 3000;
    
    // 固定请求间隔（毫秒）
    private int statictime = 0;
    
    // 请求间隔范围 - 开始时间（毫秒）
    private int starttime = 0;
    
    // 请求间隔范围 - 结束时间（毫秒）
    private int endtime = 0;
    
    // 开关状态
    private boolean switchEnabled = true;
    
    // 测试 Cookie
    private boolean cookiecheck = false;
    
    // 测试错误类型
    private boolean errorcheck = true;
    
    // 接受 Repeater
    private boolean repeatercheck = false;
    
    // 测试数值类型
    private boolean numcheck = true;
    
    // 测试字符串类型
    private boolean stringcheck = true;
    
    // 测试 Order 类型
    private boolean ordercheck = true;
    
    // 测试布尔类型
    private boolean boolcheck = true;
    
    // 测试自定义 Payload
    private boolean diycheck = false;
    
    // 语言索引（0=中文，1=英文）
    private int languageindex = 0;

    // Getters and Setters
    public List<String> getWhitelist() {
        return whitelist;
    }

    public void setWhitelist(List<String> whitelist) {
        this.whitelist = whitelist;
    }

    public List<String> getBlacklist() {
        return blacklist;
    }

    public void setBlacklist(List<String> blacklist) {
        this.blacklist = blacklist;
    }

    public List<String> getSuffixlist() {
        return suffixlist;
    }

    public void setSuffixlist(List<String> suffixlist) {
        this.suffixlist = suffixlist;
    }

    public List<String> getErrpoclist() {
        return errpoclist;
    }

    public void setErrpoclist(List<String> errpoclist) {
        this.errpoclist = errpoclist;
    }

    public List<String> getParamslist() {
        return paramslist;
    }

    public void setParamslist(List<String> paramslist) {
        this.paramslist = paramslist;
    }

    public String getBlackpath() {
        return blackpath;
    }

    public void setBlackpath(String blackpath) {
        this.blackpath = blackpath;
    }

    public String getDiypayloads() {
        return diypayloads;
    }

    public void setDiypayloads(String diypayloads) {
        this.diypayloads = diypayloads;
    }

    public String getDiyregex() {
        return diyregex;
    }

    public void setDiyregex(String diyregex) {
        this.diyregex = diyregex;
    }

    public int getDelaytime() {
        return delaytime;
    }

    public void setDelaytime(int delaytime) {
        this.delaytime = delaytime;
    }

    public int getStatictime() {
        return statictime;
    }

    public void setStatictime(int statictime) {
        this.statictime = statictime;
    }

    public int getStarttime() {
        return starttime;
    }

    public void setStarttime(int starttime) {
        this.starttime = starttime;
    }

    public int getEndtime() {
        return endtime;
    }

    public void setEndtime(int endtime) {
        this.endtime = endtime;
    }

    public boolean isSwitchEnabled() {
        return switchEnabled;
    }

    public void setSwitchEnabled(boolean switchEnabled) {
        this.switchEnabled = switchEnabled;
    }

    public boolean isCookiecheck() {
        return cookiecheck;
    }

    public void setCookiecheck(boolean cookiecheck) {
        this.cookiecheck = cookiecheck;
    }

    public boolean isErrorcheck() {
        return errorcheck;
    }

    public void setErrorcheck(boolean errorcheck) {
        this.errorcheck = errorcheck;
    }

    public boolean isRepeatercheck() {
        return repeatercheck;
    }

    public void setRepeatercheck(boolean repeatercheck) {
        this.repeatercheck = repeatercheck;
    }

    public boolean isNumcheck() {
        return numcheck;
    }

    public void setNumcheck(boolean numcheck) {
        this.numcheck = numcheck;
    }

    public boolean isStringcheck() {
        return stringcheck;
    }

    public void setStringcheck(boolean stringcheck) {
        this.stringcheck = stringcheck;
    }

    public boolean isOrdercheck() {
        return ordercheck;
    }

    public void setOrdercheck(boolean ordercheck) {
        this.ordercheck = ordercheck;
    }

    public boolean isBoolcheck() {
        return boolcheck;
    }

    public void setBoolcheck(boolean boolcheck) {
        this.boolcheck = boolcheck;
    }

    public boolean isDiycheck() {
        return diycheck;
    }

    public void setDiycheck(boolean diycheck) {
        this.diycheck = diycheck;
    }

    public int getLanguageindex() {
        return languageindex;
    }

    public void setLanguageindex(int languageindex) {
        this.languageindex = languageindex;
    }

    /**
     * 转换为 Properties 格式（兼容 UI 的旧配置逻辑）
     *
     * @return Properties 对象，包含所有配置项
     */
    public Properties toProperties() {
        Properties prop = new Properties();

        // 列表字段转换为 | 分隔的字符串
        prop.setProperty("whitelist", joinList(whitelist));
        prop.setProperty("blacklist", joinList(blacklist));
        prop.setProperty("suffixlist", joinList(suffixlist));
        prop.setProperty("errpoclist", joinList(errpoclist));
        prop.setProperty("paramslist", joinList(paramslist));

        // 多行文本字段直接使用（Properties 会处理换行符）
        prop.setProperty("blackpath", blackpath != null ? blackpath : "");
        prop.setProperty("diypayloads", diypayloads != null ? diypayloads : "");
        prop.setProperty("diyregex", diyregex != null ? diyregex : "");

        // 数值字段转换为字符串
        prop.setProperty("delaytime", String.valueOf(delaytime));
        prop.setProperty("statictime", String.valueOf(statictime));
        prop.setProperty("starttime", String.valueOf(starttime));
        prop.setProperty("endtime", String.valueOf(endtime));

        // 布尔字段转换为字符串
        prop.setProperty("switch", String.valueOf(switchEnabled));
        prop.setProperty("cookiecheck", String.valueOf(cookiecheck));
        prop.setProperty("errorcheck", String.valueOf(errorcheck));
        prop.setProperty("repeatercheck", String.valueOf(repeatercheck));
        prop.setProperty("numcheck", String.valueOf(numcheck));
        prop.setProperty("stringcheck", String.valueOf(stringcheck));
        prop.setProperty("ordercheck", String.valueOf(ordercheck));
        prop.setProperty("boolcheck", String.valueOf(boolcheck));
        prop.setProperty("diycheck", String.valueOf(diycheck));

        // 语言索引
        prop.setProperty("languageindex", String.valueOf(languageindex));

        return prop;
    }

    /**
     * 将 List 转换为 | 分隔的字符串
     *
     * @param list 列表
     * @return | 分隔的字符串，如果列表为空或 null 则返回空字符串
     */
    private String joinList(List<String> list) {
        if (list == null || list.isEmpty()) {
            return "";
        }
        return String.join("|", list);
    }
}

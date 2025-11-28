/*
 * @saoshao<1224165231@qq.com>
 */
package DetSql.config;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * 默认配置常量
 */
public class DefaultConfig {
    // 时间配置默认值(毫秒)
    public static final int DEFAULT_DELAY_TIME_MS = 3000;
    public static final int DEFAULT_STATIC_TIME_MS = 0;
    public static final int DEFAULT_START_TIME_MS = 0;
    public static final int DEFAULT_END_TIME_MS = 0;

    // 请求大小限制(字节) - 默认 10MB
    public static final int MAX_REQUEST_SIZE_BYTES = 10 * 1024 * 1024;

    // 默认禁止后缀
    public static final String DEFAULT_SUFFIX_LIST = "wma|csv|mov|doc|3g2|mp4|7z|3gp|xbm|jar|avi|ogv|mpv2|tiff|pnm|jpg|"
            +
            "xpm|xul|epub|au|aac|midi|weba|tar|js|rtf|bin|woff|wmv|tif|css|gif|" +
            "flv|ttf|html|eot|ods|odt|webm|mpg|mjs|bz|ics|ras|aifc|mpa|ppt|mpeg|" +
            "pptx|oga|ra|aiff|asf|woff2|snd|xwd|csh|webp|xlsx|mpkg|vsd|mid|wav|" +
            "svg|mp3|bz2|ico|jpe|pbm|gz|pdf|log|jpeg|rmi|txt|arc|rm|ppm|cod|jfif|" +
            "ram|docx|mpe|odp|otf|pgm|cmx|m3u|mp2|cab|rar|bmp|rgb|png|azw|ogx|aif|" +
            "zip|ief|htm|xls|mpp|swf|rmvb|abw";

    /**
     * Default suffix set - pre-split for direct use
     */
    public static final Set<String> DEFAULT_SUFFIX_SET = new HashSet<>(
            Arrays.asList(DEFAULT_SUFFIX_LIST.split("\\|")));

    // 默认错误 POC
    public static final String[] DEFAULT_ERR_POCS = {
            "'", "\"", "\\", "`", "1'1", "1\"1"
    };

    // 默认错误 POC（JSON 转义版本）
    public static final String[] DEFAULT_ERR_POCS_JSON = deriveJsonErrPocs(DEFAULT_ERR_POCS);

    // 默认 SQL 错误检测规则
    public static final String[] ERROR_DETECTION_RULES = {
            "the\\s+used\\s+select\\s+statements\\s+have\\s+different\\s+number\\s+of\\s+columns",
            "An\\s+illegal\\s+character\\s+has\\s+been\\s+found\\s+in\\s+the\\s+statement",
            "MySQL\\s+server\\s+version\\s+for\\s+the\\s+right\\s+syntax\\s+to\\s+use",
            "supplied\\s+argument\\s+is\\s+not\\s+a\\s+valid\\s+PostgreSQL\\s+result",
            "Unclosed\\s+quotation\\s+mark\\s+before\\s+the\\s+character\\s+string",
            "Unclosed\\s+quotation\\s+mark\\s+after\\s+the\\s+character\\s+string",
            "Column\\s+count\\s+doesn't\\s+match\\s+value\\s+count\\s+at\\s+row",
            "Syntax\\s+error\\s+in\\s+string\\s+in\\s+query\\s+expression",
            "Microsoft\\s+OLE\\s+DB\\s+Provider\\s+for\\s+ODBC\\s+Drivers",
            "Microsoft\\s+OLE\\s+DB\\s+Provider\\s+for\\s+SQL\\s+Server",
            "\\[Microsoft\\]\\[ODBC\\s+Microsoft\\s+Access\\s+Driver\\]",
            "You\\s+have\\s+an\\s+error\\s+in\\s+your\\s+SQL\\s+syntax",
            "supplied\\s+argument\\s+is\\s+not\\s+a\\s+valid\\s+MySQL",
            "Data\\s+type\\s+mismatch\\s+in\\s+criteria\\s+expression",
            "internal\\s+error\\s+\\[IBM\\]\\[CLI\\s+Driver\\]\\[DB2",
            "Unexpected\\s+end\\s+of\\s+command\\s+in\\s+statement",
            "\\[Microsoft\\]\\[ODBC\\s+SQL\\s+Server\\s+Driver\\]",
            "\\[Macromedia\\]\\[SQLServer\\s+JDBC\\s+Driver\\]",
            "has\\s+occurred\\s+in\\s+the\\s+vicinity\\s+of:",
            "A\\s+Parser\\s+Error\\s+\\(syntax\\s+error\\)",
            "Procedure\\s+'[^']+'\\s+requires\\s+parameter",
            "Microsoft\\s+SQL\\s+Native\\s+Client\\s+error",
            "Syntax\\s+error\\s+in\\s+query\\s+expression",
            "System\\.Data\\.SqlClient\\.SqlException",
            "Dynamic\\s+Page\\s+Generation\\s+Error:",
            "System\\.Exception: SQL Execution Error",
            "Microsoft\\s+JET\\s+Database\\s+Engine",
            "System\\.Data\\.OleDb\\.OleDbException",
            "Sintaxis\\s+incorrecta\\s+cerca\\s+de",
            "Table\\s+'[^']+'\\s+doesn't\\s+exist",
            "java\\.sql\\.SQLSyntaxErrorException",
            "Column\\s+count\\s+doesn't\\s+match",
            "your\\s+MySQL\\s+server\\s+version",
            "\\[SQLServer\\s+JDBC\\s+Driver\\]",
            "ADODB\\.Field\\s+\\(0x800A0BCD\\)",
            "com.microsoft\\.sqlserver\\.jdbc",
            "ODBC\\s+SQL\\s+Server\\s+Driver",
            "(PLS|ORA)-[0-9][0-9][0-9][0-9]",
            "PostgreSQL\\s+query\\s+failed:",
            "on\\s+MySQL\\s+result\\s+index",
            "valid\\s+PostgreSQL\\s+result",
            "macromedia\\.jdbc\\.sqlserver",
            "Access\\s+Database\\s+Engine",
            "SQLServer\\s+JDBC\\s+Driver",
            "Incorrect\\s+syntax\\s+near",
            "java\\.sql\\.SQLException",
            "MySQLSyntaxErrorException",
            "<b>Warning</b>:\\s+ibase_",
            "valid\\s+MySQL\\s+result",
            "org\\.postgresql\\.jdbc",
            "com\\.jnetdirect\\.jsql",
            "Dynamic\\s+SQL\\s+Error",
            "\\[DM_QUERY_E_SYNTAX\\]",
            "mysql_fetch_array\\(\\)",
            "pg_query\\(\\)\\s+\\[:",
            "pg_exec\\(\\)\\s+\\[:",
            "com\\.informix\\.jdbc",
            "DB2\\s+SQL\\s+error",
            "Microsoft\\s+Access",
            "\\[CLI\\s+Driver\\]",
            "\\[SQL\\s+Server\\]",
            "com\\.mysql\\.jdbc",
            "Sybase\\s+message:",
            "\\[MySQL\\]\\[ODBC",
            "ADODB\\.Recordset",
            "Unknown\\s+column",
            "mssql_query\\(\\)",
            "Sybase\\s+message",
            "Database\\s+error",
            "PG::SyntaxError:",
            "where\\s+clause",
            "Syntax\\s+error",
            "Oracle\\s+error",
            "SQLite\\s+error",
            "SybSQLException",
            "\\[SqlException",
            "odbc_exec\\(\\)",
            "MySqlException",
            "INSERT\\s+INTO",
            "SQL\\s+syntax",
            "Error\\s+SQL:",
            "SQL\\s+error",
            "PSQLException",
            "SQLSTATE=\\d+",
            "SELECT .{1,30}FROM ",
            "UPDATE .{1,30}SET ",
            "附近有语法错误",
            "MySqlClient",
            "ORA-\\d{5}",
            "引号不完整",
            "数据库出错"
    };

    /**
     * 为 JSON 格式派生错误 POC
     */
    private static String[] deriveJsonErrPocs(String[] base) {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        for (String s : base) {
            if (s == null)
                continue;
            out.add(s);
            if (s.contains("\"")) {
                out.add(s.replace("\"", "\\\""));
                out.add(s.replace("\"", "\\u0022"));
            }
            if (s.contains("'")) {
                out.add(s.replace("'", "\\u0027"));
            }
        }
        return out.toArray(new String[0]);
    }
}

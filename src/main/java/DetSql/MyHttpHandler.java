/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
//import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.utilities.CryptoUtils;
import burp.api.montoya.utilities.DigestAlgorithm;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

public class MyHttpHandler implements HttpHandler {
    public final MontoyaApi api;
    public Semaphore semaphore;
    public Semaphore semaphore2;
    public final SourceTableModel sourceTableModel;//两张表
    public final PocTableModel pocTableModel;
    public final ConcurrentHashMap<String, List<PocLogEntry>> attackMap;
    public CryptoUtils cryptoUtils;
    public Lock lk;
    public static String[] errPocs = {"'", "%27", "%DF'", "%DF%27", "\"", "%22", "%DF\"", "%DF%22", "`"};
    public static String[] errPocsj = {"'", "%27", "%DF'", "%DF%27", "\\\"", "%22", "%DF\\\"", "%DF%22", "\\u0022", "%DF\\u0022", "\\u0027", "%DF\\u0027", "`"};
    public static Set<String> diyPayloads=new HashSet<>();
    public static Set<String> diyRegexs=new HashSet<>();
    public static int intTime;
    private static final String[] rules = {
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
    public int countId;
    public static Set<String> blackParamsSet = new HashSet<>();
    public static Set<String> whiteParamsSet = new HashSet<>();
    public static int staticTime=100;
    public static int startTime=0;
    public static int endTime=0;
    //RequestOptions requestOptions = RequestOptions.requestOptions().withResponseTimeout(timeoutms);
    public MyHttpHandler(MontoyaApi mapi, SourceTableModel sourceTableModel, PocTableModel pocTableModel, ConcurrentHashMap<String, List<PocLogEntry>> attackMap) {
        this.api = mapi;
        this.sourceTableModel = sourceTableModel;
        this.pocTableModel = pocTableModel;
        this.attackMap = attackMap;
        this.semaphore = new Semaphore(4);
        this.semaphore2 = new Semaphore(1);
        this.cryptoUtils = api.utilities().cryptoUtils();
        this.lk = new ReentrantLock();
        this.countId = 0;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        new Thread(() -> {
            try {
                if (DetSql.switchChexk.isSelected() && httpResponseReceived.bodyToString().length() != 0 && httpResponseReceived.bodyToString().length() < 10000) {
                    if (MyFilterRequest.fromProxySource(httpResponseReceived) && MyFilterRequest.filterOneRequest(httpResponseReceived)) {
                        String requestSm3Hash = byteToHex(cryptoUtils.generateDigest(ByteArray.byteArray(MyFilterRequest.getUnique(httpResponseReceived)), DigestAlgorithm.SM3).getBytes());
                        Thread.currentThread().setName(requestSm3Hash);
                        if (!attackMap.containsKey(requestSm3Hash)) {
                            int oneLogSize = 0;
                            lk.lock();
                            try {
                                oneLogSize = countId;
                                sourceTableModel.add(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, "run", httpResponseReceived.bodyToString().length(), HttpRequestResponse.httpRequestResponse(httpResponseReceived.initiatingRequest(), HttpResponse.httpResponse()), httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()));
                            } catch (Exception e) {
                                e.printStackTrace();
                            } finally {
                                lk.unlock();
                                attackMap.put(requestSm3Hash, new ArrayList<>());
                                countId += 1;
                            }
                            try {
                                String oneVuln = "";
                                semaphore.acquire();
                                try {
                                    if (!Thread.currentThread().isInterrupted()) {
                                        oneVuln = processOneRequest(httpResponseReceived, requestSm3Hash);
                                    }

                                } catch (Exception e) {
                                    e.printStackTrace();
                                } finally {
                                    semaphore.release();

                                    if (oneVuln.isBlank()) {
                                        //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                        sourceTableModel.add2(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, "", httpResponseReceived.bodyToString().length(), null, httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                                    } else {
                                        //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                        sourceTableModel.add2(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, oneVuln, httpResponseReceived.bodyToString().length(), HttpRequestResponse.httpRequestResponse(httpResponseReceived.initiatingRequest(), HttpResponse.httpResponse(httpResponseReceived.toByteArray())), httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                                    }
                                }
                            } catch (InterruptedException e) {
                                //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                sourceTableModel.add2(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, "手动停止", httpResponseReceived.bodyToString().length(), null, httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                            } catch (Exception e) {
                                e.printStackTrace();
                            }


                        }

                    } else if (DetSql.vulnChexk.isSelected() && MyFilterRequest.fromRepeaterSource(httpResponseReceived) && MyFilterRequest.filterOneRequest(httpResponseReceived)) {
                        String requestSm3Hash = String.valueOf(System.currentTimeMillis());
                        Thread.currentThread().setName(requestSm3Hash);
                        int oneLogSize = 0;
                        lk.lock();
                        try {
                            oneLogSize = countId;
                            sourceTableModel.add(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, "run", httpResponseReceived.bodyToString().length(), HttpRequestResponse.httpRequestResponse(httpResponseReceived.initiatingRequest(), HttpResponse.httpResponse()), httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()));
                        } catch (Exception e) {
                            e.printStackTrace();
                        } finally {
                            lk.unlock();
                            attackMap.put(requestSm3Hash, new ArrayList<>());
                            countId += 1;
                        }
                        try {
                            String oneVuln = "";
                            semaphore.acquire();
                            try {
                                if (!Thread.currentThread().isInterrupted()) {
                                    oneVuln = processOneRequest(httpResponseReceived, requestSm3Hash);
                                }

                            } catch (Exception e) {
                                e.printStackTrace();
                            } finally {
                                semaphore.release();
                                if (oneVuln.isBlank()) {
                                    //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                    sourceTableModel.add2(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, "", httpResponseReceived.bodyToString().length(), null, httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                                } else {
                                    //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                    sourceTableModel.add2(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, oneVuln, httpResponseReceived.bodyToString().length(), HttpRequestResponse.httpRequestResponse(httpResponseReceived.initiatingRequest(), HttpResponse.httpResponse(httpResponseReceived.toByteArray())), httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                                }

                            }
                        } catch (InterruptedException e) {
                            //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                            sourceTableModel.add2(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, "手动停止", httpResponseReceived.bodyToString().length(), null, httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }


                    }
                } else if (DetSql.switchChexk.isSelected() && httpResponseReceived.bodyToString().length() != 0 && httpResponseReceived.bodyToString().length() < 50000) {
                    if (MyFilterRequest.fromProxySource(httpResponseReceived) && MyFilterRequest.filterOneRequest(httpResponseReceived)) {
                        String requestSm3Hash = byteToHex(cryptoUtils.generateDigest(ByteArray.byteArray(MyFilterRequest.getUnique(httpResponseReceived)), DigestAlgorithm.SM3).getBytes());
                        Thread.currentThread().setName(requestSm3Hash);
                        if (!attackMap.containsKey(requestSm3Hash)) {
                            int oneLogSize = 0;
                            lk.lock();

                            try {
                                oneLogSize = countId;
                                sourceTableModel.add(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, "run", httpResponseReceived.bodyToString().length(), HttpRequestResponse.httpRequestResponse(httpResponseReceived.initiatingRequest(), HttpResponse.httpResponse()), httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()));
                            } catch (Exception e) {
                                e.printStackTrace();
                            } finally {
                                lk.unlock();
                                attackMap.put(requestSm3Hash, new ArrayList<>());
                                countId += 1;
                            }
                            try {
                                String oneVuln = "";
                                semaphore2.acquire();
                                try {
                                    if (!Thread.currentThread().isInterrupted()) {
                                        oneVuln = processOneRequest(httpResponseReceived, requestSm3Hash);
                                    }

                                } catch (Exception e) {
                                    e.printStackTrace();
                                } finally {
                                    semaphore2.release();
                                    if (oneVuln.isBlank()) {
                                        //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                        sourceTableModel.add2(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, "", httpResponseReceived.bodyToString().length(), null, httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                                    } else {
                                        //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                        sourceTableModel.add2(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, oneVuln, httpResponseReceived.bodyToString().length(), HttpRequestResponse.httpRequestResponse(httpResponseReceived.initiatingRequest(), HttpResponse.httpResponse(httpResponseReceived.toByteArray())), httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                                    }

                                }
                            } catch (InterruptedException e) {
                                //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                sourceTableModel.add2(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, "手动停止", httpResponseReceived.bodyToString().length(), null, httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }

                    } else if (DetSql.vulnChexk.isSelected() && MyFilterRequest.fromRepeaterSource(httpResponseReceived) && MyFilterRequest.filterOneRequest(httpResponseReceived)) {
                        String requestSm3Hash = String.valueOf(System.currentTimeMillis());
                        Thread.currentThread().setName(requestSm3Hash);
                        int oneLogSize = 0;
                        lk.lock();
                        try {
                            oneLogSize = countId;
                            sourceTableModel.add(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, "run", httpResponseReceived.bodyToString().length(), HttpRequestResponse.httpRequestResponse(httpResponseReceived.initiatingRequest(), HttpResponse.httpResponse()), httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()));
                        } catch (Exception e) {
                            e.printStackTrace();
                        } finally {
                            lk.unlock();
                            attackMap.put(requestSm3Hash, new ArrayList<>());
                            countId += 1;
                        }

                        try {
                            String oneVuln = "";
                            semaphore2.acquire();
                            try {
                                if (!Thread.currentThread().isInterrupted()) {
                                    oneVuln = processOneRequest(httpResponseReceived, requestSm3Hash);
                                }

                            } catch (Exception e) {
                                e.printStackTrace();
                            } finally {
                                semaphore2.release();
                                if (oneVuln.isBlank()) {
                                    //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                    sourceTableModel.add2(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, "", httpResponseReceived.bodyToString().length(), null, httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                                } else {
                                    //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                    sourceTableModel.add2(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, oneVuln, httpResponseReceived.bodyToString().length(), HttpRequestResponse.httpRequestResponse(httpResponseReceived.initiatingRequest(), HttpResponse.httpResponse(httpResponseReceived.toByteArray())), httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                                }

                            }
                        } catch (InterruptedException e) {
                            //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                            sourceTableModel.add2(new SourceLogEntry(oneLogSize, httpResponseReceived.toolSource().toolType().toolName(), requestSm3Hash, "手动停止", httpResponseReceived.bodyToString().length(), null, httpResponseReceived.initiatingRequest().httpService().toString(), httpResponseReceived.initiatingRequest().method(), httpResponseReceived.initiatingRequest().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }


    public String processOneRequest(HttpResponseReceived httpResponseReceived, String requestSm3Hash) throws InterruptedException {
        boolean html_flag = httpResponseReceived.mimeType().description().equals("HTML");
        boolean err_flag = false;
        boolean num_flag = false;
        boolean order_flag = false;
        boolean string_flag = false;
        boolean bool_flag = false;

        boolean diy_flag = false;
        HttpRequest sourceHttpRequest = httpResponseReceived.initiatingRequest().copyToTempFile();
        String sourceBody = new String(httpResponseReceived.body().getBytes(), StandardCharsets.UTF_8);
        List<PocLogEntry> getAttackList = attackMap.get(requestSm3Hash);
        if (!httpResponseReceived.initiatingRequest().parameters(HttpParameterType.URL).isEmpty()) {
            //新参数
            List<ParsedHttpParameter> parameters = httpResponseReceived.initiatingRequest().parameters(HttpParameterType.URL);
            ArrayList<HttpParameter> newHttpParameters = new ArrayList<>();
            for (ParsedHttpParameter parameter : parameters) {
                newHttpParameters.add(HttpParameter.urlParameter(parameter.name(), parameter.value()));
            }
            //报错
            if (DetSql.errorChexk.isSelected()) {
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    for (String poc : errPocs) {
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + poc));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);

                        String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        String resBool = ErrSqlCheck(pocResponseBody);
                        if (resBool != null) {
                            PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "errsql(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                            getAttackList.add(logEntry);
                            err_flag = true;
                        }
                    }
                }
            }
            //diy
            if (DetSql.diyChexk.isSelected()&&!diyPayloads.isEmpty()&&(!DetSql.timeTextField.getText().isEmpty()||!diyRegexs.isEmpty())) {
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    for (String poc : diyPayloads) {
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + poc));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                        String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);

                        if(!diyRegexs.isEmpty()){
                            String resBool = diyRegexCheck(pocResponseBody);
                            if (resBool != null) {
                                PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "diypoc(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                diy_flag = true;
                            }
                        }
                        if(!DetSql.timeTextField.getText().isEmpty()&&pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()>intTime){
                            PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "diypoc(time)", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                            getAttackList.add(logEntry);
                            diy_flag = true;
                        }
                    }
                }
            }

            if (DetSql.stringChexk.isSelected()){
                stringloop:
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String firstPocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //单引号
                        List<HttpParameter> yinPocHttpParameters = new ArrayList<>(newHttpParameters);
                        yinPocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'"));
                        HttpRequest yinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(yinPocHttpParameters);
                        HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                        firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);

                        List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                        if (Collections.min(firstDoubleList) <= 0.9) {
                            String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "'", firstSimimarity, "stringsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue stringloop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //两个单引号
                        List<HttpParameter> dyinPocHttpParameters = new ArrayList<>(newHttpParameters);
                        dyinPocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "''"));
                        HttpRequest dyinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(dyinPocHttpParameters);
                        HttpRequestResponse dyinHttpSendRequestResponse = callMyRequest(dyinPocHttpRequest, 2);
                        String dyinPocResponseBody = new String(dyinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, dyinPocResponseBody,"","",html_flag);
                        if (Collections.min(secondDoubleList) <= 0.9) {
                            String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "''", secondSimimarity, "stringsql", String.valueOf(dyinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(dyinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (dyinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue stringloop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //"'+'"
                        List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                        poc3HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'%2B'"));
                        HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                        HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                        String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(sourceBody, poc3ResponseBody,"","'+'",html_flag);
                        if (Collections.max(oneDoubleList3) > 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                            pocLogEntries.add(new PocLogEntry(paramName, "'+'", mySimimarity, "stringsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                            getAttackList.addAll(pocLogEntries);
                            string_flag = true;
                            continue stringloop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //"'||'"
                        List<HttpParameter> poc4HttpParameters = new ArrayList<>(newHttpParameters);
                        poc4HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'||'"));
                        HttpRequest poc4HttpRequest = sourceHttpRequest.withUpdatedParameters(poc4HttpParameters);
                        HttpRequestResponse httpSendRequestResponse4 = callMyRequest(poc4HttpRequest, 2);
                        String poc4ResponseBody = new String(httpSendRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList4 = MyCompare.averageLevenshtein(sourceBody, poc4ResponseBody,"","'||'",html_flag);
                        if (Collections.max(oneDoubleList4) > 0.9) {
                            String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||'", lastSimimarity, "stringsql", String.valueOf(httpSendRequestResponse4.response().bodyToString().length()), String.valueOf(httpSendRequestResponse4.response().statusCode()), String.format("%.3f", (httpSendRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse4, requestSm3Hash));
                            getAttackList.addAll(pocLogEntries);
                            string_flag = true;
                        }
                    }
                }
            }

            //数字
            if (DetSql.numChexk.isSelected()){
                outerloop:
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    try {
                        int parseInt = Integer.parseInt(paramValue);
                    } catch (NumberFormatException e) {
                        continue;
                    }
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String pocResponseBody = "";
                    //"-0-0-0"
                    for (int j = 0; j < 1; j++) {
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "-0-0-0"));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);

                        HttpRequestResponse httpSendRequestResponse = callMyRequest(pocHttpRequest, 2);

                        pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList = MyCompare.averageLevenshtein(sourceBody, pocResponseBody,"","-0-0-0",html_flag);
                        if (Collections.max(oneDoubleList) > 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "-0-0-0", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue outerloop;
                        }
                    }
                    String poc2ResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //"-abc"
                        List<HttpParameter> poc2HttpParameters = new ArrayList<>(newHttpParameters);
                        poc2HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "-abc"));
                        HttpRequest poc2HttpRequest = sourceHttpRequest.withUpdatedParameters(poc2HttpParameters);

                        HttpRequestResponse httpSendRequestResponse2 = callMyRequest(poc2HttpRequest, 2);


                        poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList2 = MyCompare.averageLevenshtein(sourceBody, poc2ResponseBody,"","-abc",html_flag);
                        if (Collections.min(oneDoubleList2) <= 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));
                            pocLogEntries.add(new PocLogEntry(paramName, "-abc", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                        } else {
                            continue outerloop;
                        }
                    }

                    List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(pocResponseBody, poc2ResponseBody,"0-0-0","abc",html_flag);
                    if (Collections.min(oneDoubleList3) <= 0.9) {
                        getAttackList.addAll(pocLogEntries);
                        num_flag = true;
                    }


                }
            }

            //order
            if (DetSql.orderChexk.isSelected()){
                orderloop:
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    if (paramValue.isBlank()) {
                        continue;
                    }
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String pocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //",0"
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + ",0"));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse httpSendRequestResponse = callMyRequest(pocHttpRequest, 2);
                        pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList = MyCompare.averageJaccard(sourceBody, pocResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList) <= 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, ",0", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue orderloop;
                        }
                    }
                    String poc2ResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //",XXXXXX"
                        List<HttpParameter> poc2HttpParameters = new ArrayList<>(newHttpParameters);
                        poc2HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + ",XXXXXX"));
                        HttpRequest poc2HttpRequest = sourceHttpRequest.withUpdatedParameters(poc2HttpParameters);
                        HttpRequestResponse httpSendRequestResponse2 = callMyRequest(poc2HttpRequest, 2);
                        poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList2 = MyCompare.averageJaccard(sourceBody, poc2ResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList2) <= 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));
                            pocLogEntries.add(new PocLogEntry(paramName, ",XXXXXX", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                        } else {
                            continue orderloop;
                        }
                    }

                    List<Double> oneDoubleList3 = MyCompare.averageJaccard(pocResponseBody, poc2ResponseBody,"","",html_flag);
                    if (Collections.max(oneDoubleList3) > 0.9) {
                        for (int j = 0; j < 1; j++) {
                            List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                            poc3HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + ",1"));
                            HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                            HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                            String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList4 = MyCompare.averageJaccard(sourceBody, poc3ResponseBody,"","",html_flag);
                            if (Collections.max(oneDoubleList4) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, poc3ResponseBody,"","",html_flag)) <= 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                                pocLogEntries.add(new PocLogEntry(paramName, ",1", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                order_flag = true;
                                continue orderloop;
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            List<HttpParameter> poc4HttpParameters = new ArrayList<>(newHttpParameters);
                            poc4HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + ",2"));
                            HttpRequest poc4HttpRequest = sourceHttpRequest.withUpdatedParameters(poc4HttpParameters);
                            HttpRequestResponse httpSendRequestResponse4 = callMyRequest(poc4HttpRequest, 2);

                            String poc4ResponseBody = new String(httpSendRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList5 = MyCompare.averageJaccard(sourceBody, poc4ResponseBody,"","",html_flag);
                            if (Collections.max(oneDoubleList5) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, poc4ResponseBody,"","",html_flag)) <= 0.9) {
                                String mySimimarityx = MyCompare.formatPercent(Collections.max(oneDoubleList5));
                                pocLogEntries.add(new PocLogEntry(paramName, ",2", mySimimarityx, "ordersql", String.valueOf(httpSendRequestResponse4.response().bodyToString().length()), String.valueOf(httpSendRequestResponse4.response().statusCode()), String.format("%.3f", (httpSendRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse4, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                order_flag = true;
                            }
                        }
                    }


                }
            }
            //bool
            if (DetSql.boolChexk.isSelected()){
                boolLoop:
                for (int i = 0; i < newHttpParameters.size(); i++){
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String firstPocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //'||EXP(710)||'
                        List<HttpParameter> yinPocHttpParameters = new ArrayList<>(newHttpParameters);
                        yinPocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'||EXP(710)||'"));
                        HttpRequest yinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(yinPocHttpParameters);
                        HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                        firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                        if (Collections.min(firstDoubleList) <= 0.9) {
                            String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(710)||'", firstSimimarity, "boolsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue boolLoop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //'||EXP(290)||'
                        List<HttpParameter> minPocHttpParameters = new ArrayList<>(newHttpParameters);
                        minPocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'||EXP(290)||'"));
                        HttpRequest minPocHttpRequest = sourceHttpRequest.withUpdatedParameters(minPocHttpParameters);
                        HttpRequestResponse minHttpSendRequestResponse = callMyRequest(minPocHttpRequest, 2);
                        String minPocResponseBody = new String(minHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, minPocResponseBody,"","",html_flag);
                        if (Collections.min(secondDoubleList) <= 0.9) {
                            String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(290)||'", secondSimimarity, "boolsql", String.valueOf(minHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(minHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (minHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), minHttpSendRequestResponse, requestSm3Hash));
                            firstPocResponseBody=minPocResponseBody;
                        } else{
                            List<HttpParameter> addPocHttpParameters = new ArrayList<>(newHttpParameters);
                            addPocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'||1%2F0||'"));
                            HttpRequest addPocHttpRequest = sourceHttpRequest.withUpdatedParameters(addPocHttpParameters);
                            HttpRequestResponse addHttpSendRequestResponse = callMyRequest(addPocHttpRequest, 2);
                            String addPocResponseBody = new String(addHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> addDoubleList = MyCompare.averageLevenshtein(sourceBody, addPocResponseBody,"","'||1/0||'",html_flag);
                            if (Collections.max(addDoubleList) > 0.9) {
                                String addSimimarity = MyCompare.formatPercent(Collections.max(addDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||1%2F0||'", addSimimarity, "boolsql", String.valueOf(addHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(addHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (addHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), addHttpSendRequestResponse, requestSm3Hash));
                                firstPocResponseBody=minPocResponseBody;
                            }else{
                                continue boolLoop;
                            }
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //"'||1%2F1||'"
                        List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                        poc3HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'||1%2F1||'"));
                        HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                        HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                        String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(firstPocResponseBody, poc3ResponseBody,"EXP\\(290\\)","1/1",html_flag);
                        if (Collections.max(oneDoubleList3) > 0.9) {
                            String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||1%2F1||'", lastSimimarity, "boolsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                            getAttackList.addAll(pocLogEntries);
                            bool_flag = true;
                        }
                    }
                }
            }

        }
        //处理post/PUT
        if (httpResponseReceived.initiatingRequest().method().equals("POST")||httpResponseReceived.initiatingRequest().method().equals("PUT")) {
            if (!httpResponseReceived.initiatingRequest().parameters(HttpParameterType.BODY).isEmpty()) {
                //新参数
                List<ParsedHttpParameter> parameters = httpResponseReceived.initiatingRequest().parameters(HttpParameterType.BODY);
                ArrayList<HttpParameter> newHttpParameters = new ArrayList<>();
                for (ParsedHttpParameter parameter : parameters) {
                    newHttpParameters.add(HttpParameter.bodyParameter(parameter.name(), parameter.value()));
                }
                //err
                if (DetSql.errorChexk.isSelected()){
                    for (int i = 0; i < newHttpParameters.size(); i++) {
                        String paramName = newHttpParameters.get(i).name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = newHttpParameters.get(i).value();
                        for (String poc : errPocs) {
                            List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                            pocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + poc));
                            HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                            HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                            String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            String resBool = ErrSqlCheck(pocResponseBody);
                            if (resBool != null) {
                                PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "errsql(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                err_flag = true;
                            }
                        }
                    }
                }
                //diy
                if (DetSql.diyChexk.isSelected()&&!diyPayloads.isEmpty()&&(!DetSql.timeTextField.getText().isEmpty()||!diyRegexs.isEmpty())){
                    for (int i = 0; i < newHttpParameters.size(); i++) {
                        String paramName = newHttpParameters.get(i).name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = newHttpParameters.get(i).value();
                        for (String poc : diyPayloads) {
                            List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                            pocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + poc));
                            HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                            HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                            String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            if(!diyRegexs.isEmpty()){
                                String resBool = diyRegexCheck(pocResponseBody);
                                if (resBool != null) {
                                    PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "diypoc(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                    getAttackList.add(logEntry);
                                    diy_flag = true;
                                }
                            }
                            if(!DetSql.timeTextField.getText().isEmpty()&&pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()>intTime){
                                PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "diypoc(time)", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                diy_flag = true;
                            }
                        }
                    }
                }
                if (DetSql.stringChexk.isSelected()) {
                    //string
                    stringloop:
                    for (int i = 0; i < newHttpParameters.size(); i++) {
                        String paramName = newHttpParameters.get(i).name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = newHttpParameters.get(i).value();
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String firstPocResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //单引号
                            List<HttpParameter> yinPocHttpParameters = new ArrayList<>(newHttpParameters);
                            yinPocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'"));
                            HttpRequest yinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(yinPocHttpParameters);
                            HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                            firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                            if (Collections.min(firstDoubleList) <= 0.9) {
                                String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'", firstSimimarity, "stringsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue stringloop;
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            //两个单引号
                            List<HttpParameter> dyinPocHttpParameters = new ArrayList<>(newHttpParameters);
                            dyinPocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "''"));
                            HttpRequest dyinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(dyinPocHttpParameters);
                            HttpRequestResponse dyinHttpSendRequestResponse = callMyRequest(dyinPocHttpRequest, 2);
                            String dyinPocResponseBody = new String(dyinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, dyinPocResponseBody,"","",html_flag);
                            if (Collections.min(secondDoubleList) <= 0.9) {
                                String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "''", secondSimimarity, "stringsql", String.valueOf(dyinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(dyinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (dyinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue stringloop;
                            }
                        }


                        for (int j = 0; j < 1; j++) {
                            //"'+'"
                            List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                            poc3HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'+'"));
                            HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                            HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                            String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(sourceBody, poc3ResponseBody,"","'+'",html_flag);
                            if (Collections.max(oneDoubleList3) > 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                                pocLogEntries.add(new PocLogEntry(paramName, "'+'", mySimimarity, "stringsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                string_flag = true;
                                continue stringloop;
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            //"'||'"
                            List<HttpParameter> poc4HttpParameters = new ArrayList<>(newHttpParameters);
                            poc4HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'||'"));
                            HttpRequest poc4HttpRequest = sourceHttpRequest.withUpdatedParameters(poc4HttpParameters);
                            HttpRequestResponse httpSendRequestResponse4 = callMyRequest(poc4HttpRequest, 2);
                            String poc4ResponseBody = new String(httpSendRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList4 = MyCompare.averageLevenshtein(sourceBody, poc4ResponseBody,"","'||'",html_flag);
                            if (Collections.max(oneDoubleList4) > 0.9) {
                                String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||'", lastSimimarity, "stringsql", String.valueOf(httpSendRequestResponse4.response().bodyToString().length()), String.valueOf(httpSendRequestResponse4.response().statusCode()), String.format("%.3f", (httpSendRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse4, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                string_flag = true;
                            }
                        }
                    }
                }
                if (DetSql.numChexk.isSelected()){
                    //num
                    outerloop:
                    for (int i = 0; i < newHttpParameters.size(); i++) {
                        String paramName = newHttpParameters.get(i).name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = newHttpParameters.get(i).value();
                        try {
                            int parseInt = Integer.parseInt(paramValue);
                        } catch (NumberFormatException e) {
                            continue;
                        }
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String pocResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //"-0-0-0"
                            List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                            pocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "-0-0-0"));
                            HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                            HttpRequestResponse httpSendRequestResponse = callMyRequest(pocHttpRequest, 2);
                            pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);

                            List<Double> oneDoubleList = MyCompare.averageLevenshtein(sourceBody, pocResponseBody,"","-0-0-0",html_flag);
                            if (Collections.max(oneDoubleList) > 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "-0-0-0", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue outerloop;
                            }
                        }
                        String poc2ResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //"-abc"
                            List<HttpParameter> poc2HttpParameters = new ArrayList<>(newHttpParameters);
                            poc2HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "-abc"));
                            HttpRequest poc2HttpRequest = sourceHttpRequest.withUpdatedParameters(poc2HttpParameters);
                            HttpRequestResponse httpSendRequestResponse2 = callMyRequest(poc2HttpRequest, 2);

                            poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList2 = MyCompare.averageLevenshtein(sourceBody, poc2ResponseBody,"","",html_flag);
                            if (Collections.min(oneDoubleList2) <= 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));

                                pocLogEntries.add(new PocLogEntry(paramName, "-abc", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                            } else {
                                continue outerloop;
                            }
                        }

                        List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(pocResponseBody, poc2ResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList3) <= 0.9) {
                            getAttackList.addAll(pocLogEntries);
                            num_flag = true;
                        }
                    }
                }
                if (DetSql.orderChexk.isSelected()){
                    //order
                    orderloop:
                    for (int i = 0; i < newHttpParameters.size(); i++) {
                        String paramName = newHttpParameters.get(i).name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = newHttpParameters.get(i).value();
                        if (paramValue.isBlank()) {
                            continue;
                        }
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String pocResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //",0"
                            List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                            pocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + ",0"));
                            HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                            HttpRequestResponse httpSendRequestResponse = callMyRequest(pocHttpRequest, 2);
                            pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList = MyCompare.averageJaccard(sourceBody, pocResponseBody,"","",html_flag);
                            if (Collections.min(oneDoubleList) <= 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, ",0", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue orderloop;
                            }
                        }
                        String poc2ResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //",XXXXXX"
                            List<HttpParameter> poc2HttpParameters = new ArrayList<>(newHttpParameters);
                            poc2HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + ",XXXXXX"));
                            HttpRequest poc2HttpRequest = sourceHttpRequest.withUpdatedParameters(poc2HttpParameters);
                            HttpRequestResponse httpSendRequestResponse2 = callMyRequest(poc2HttpRequest, 2);
                            poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList2 = MyCompare.averageJaccard(sourceBody, poc2ResponseBody,"","",html_flag);
                            if (Collections.min(oneDoubleList2) <= 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));
                                pocLogEntries.add(new PocLogEntry(paramName, ",XXXXXX", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                            } else {
                                continue orderloop;
                            }
                        }

                        List<Double> oneDoubleList3 = MyCompare.averageJaccard(pocResponseBody, poc2ResponseBody,"","",html_flag);
                        if (Collections.max(oneDoubleList3) > 0.9) {
                            for (int j = 0; j < 1; j++) {
                                // ",1", ",2", ",TRUE"
                                List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                                poc3HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + ",1"));
                                HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                                HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);

                                String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList4 = MyCompare.averageJaccard(sourceBody, poc3ResponseBody,"",",1",html_flag);
                                if (Collections.max(oneDoubleList4) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, poc3ResponseBody,"","",html_flag)) <= 0.9) {
                                    String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                                    pocLogEntries.add(new PocLogEntry(paramName, ",1", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                    getAttackList.addAll(pocLogEntries);
                                    order_flag = true;
                                    continue orderloop;
                                }
                            }
                            for (int k = 0; k < 1; k++) {
                                List<HttpParameter> poc4HttpParameters = new ArrayList<>(newHttpParameters);
                                poc4HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + ",2"));
                                HttpRequest poc4HttpRequest = sourceHttpRequest.withUpdatedParameters(poc4HttpParameters);
                                HttpRequestResponse httpSendRequestResponse4 = callMyRequest(poc4HttpRequest, 2);

                                String poc4ResponseBody = new String(httpSendRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList5 = MyCompare.averageJaccard(sourceBody, poc4ResponseBody,"",",2",html_flag);
                                if (Collections.max(oneDoubleList5) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, poc4ResponseBody,"","",html_flag)) <= 0.9) {
                                    String mySimimarityx = MyCompare.formatPercent(Collections.max(oneDoubleList5));
                                    pocLogEntries.add(new PocLogEntry(paramName, ",2", mySimimarityx, "ordersql", String.valueOf(httpSendRequestResponse4.response().bodyToString().length()), String.valueOf(httpSendRequestResponse4.response().statusCode()), String.format("%.3f", (httpSendRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse4, requestSm3Hash));
                                    getAttackList.addAll(pocLogEntries);
                                    order_flag = true;
                                }
                            }
                        }

                    }
                }
                //bool
                if (DetSql.boolChexk.isSelected()){
                    boolLoop:
                    for (int i = 0; i < newHttpParameters.size(); i++){
                        String paramName = newHttpParameters.get(i).name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = newHttpParameters.get(i).value();
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String firstPocResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //'||EXP(710)||'
                            List<HttpParameter> yinPocHttpParameters = new ArrayList<>(newHttpParameters);
                            yinPocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'||EXP(710)||'"));
                            HttpRequest yinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(yinPocHttpParameters);
                            HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                            firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                            if (Collections.min(firstDoubleList) <= 0.9) {
                                String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(710)||'", firstSimimarity, "boolsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue boolLoop;
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            //'||EXP(290)||'
                            List<HttpParameter> minPocHttpParameters = new ArrayList<>(newHttpParameters);
                            minPocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'||EXP(290)||'"));
                            HttpRequest minPocHttpRequest = sourceHttpRequest.withUpdatedParameters(minPocHttpParameters);
                            HttpRequestResponse minHttpSendRequestResponse = callMyRequest(minPocHttpRequest, 2);
                            String minPocResponseBody = new String(minHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, minPocResponseBody,"","",html_flag);
                            if (Collections.min(secondDoubleList) <= 0.9) {
                                String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(290)||'", secondSimimarity, "boolsql", String.valueOf(minHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(minHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (minHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), minHttpSendRequestResponse, requestSm3Hash));
                                firstPocResponseBody=minPocResponseBody;
                            } else{
                                List<HttpParameter> addPocHttpParameters = new ArrayList<>(newHttpParameters);
                                addPocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'||1/0||'"));
                                HttpRequest addPocHttpRequest = sourceHttpRequest.withUpdatedParameters(addPocHttpParameters);
                                HttpRequestResponse addHttpSendRequestResponse = callMyRequest(addPocHttpRequest, 2);
                                String addPocResponseBody = new String(addHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> addDoubleList = MyCompare.averageLevenshtein(sourceBody, addPocResponseBody,"","'||1/0||'",html_flag);
                                if (Collections.max(addDoubleList) > 0.9) {
                                    String addSimimarity = MyCompare.formatPercent(Collections.max(addDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'||1/0||'", addSimimarity, "boolsql", String.valueOf(addHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(addHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (addHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), addHttpSendRequestResponse, requestSm3Hash));
                                    firstPocResponseBody=minPocResponseBody;
                                }else{
                                    continue boolLoop;
                                }
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            //"'||1%2F1||'"
                            List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                            poc3HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'||1/1||'"));
                            HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                            HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                            String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(firstPocResponseBody, poc3ResponseBody,"EXP\\(290\\)","1/1",html_flag);
                            if (Collections.max(oneDoubleList3) > 0.9) {
                                String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||1/1||'", lastSimimarity, "boolsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                bool_flag = true;
                            }
                        }
                    }
                }
            } else if (!httpResponseReceived.initiatingRequest().parameters(HttpParameterType.JSON).isEmpty()) {
                List<ParsedHttpParameter> parameters = httpResponseReceived.initiatingRequest().parameters(HttpParameterType.JSON);
                String sourceRequestIndex = new String(httpResponseReceived.initiatingRequest().toByteArray().getBytes(), StandardCharsets.UTF_8);
                int bodyStartIndex = httpResponseReceived.initiatingRequest().bodyOffset();
                if (DetSql.errorChexk.isSelected()){
                    //err
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        if (sourceRequestIndex.charAt(valueStart - 1) == '"' && sourceRequestIndex.charAt(valueEnd) == '"') {
                            String paramName = parameter.name();
                            if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                                continue;
                            }
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            for (String errPoc : errPocsj) {
                                String pocBody = prefix + errPoc + suffix;
                                HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                                HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                                String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                String resBool = ErrSqlCheck(pocResponseBody);
                                if (resBool != null) {
                                    PocLogEntry logEntry = new PocLogEntry(paramName, errPoc, null, "errsql(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                    getAttackList.add(logEntry);
                                    err_flag = true;
                                }
                            }
                        }
                    }
                }
                //diy
                if (DetSql.diyChexk.isSelected()&&!diyPayloads.isEmpty()&&(!DetSql.timeTextField.getText().isEmpty()||!diyRegexs.isEmpty())){
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        if (sourceRequestIndex.charAt(valueStart - 1) == '"' && sourceRequestIndex.charAt(valueEnd) == '"') {
                            String paramName = parameter.name();
                            if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                                continue;
                            }
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            for (String errPoc : diyPayloads) {
                                String pocBody = prefix + errPoc + suffix;
                                HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                                HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                                String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                if(!diyRegexs.isEmpty()){
                                    String resBool = diyRegexCheck(pocResponseBody);
                                    if (resBool != null) {
                                        PocLogEntry logEntry = new PocLogEntry(paramName, errPoc, null, "diypoc(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                        getAttackList.add(logEntry);
                                        diy_flag = true;
                                    }
                                }
                                if(!DetSql.timeTextField.getText().isEmpty()&&pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()>intTime){
                                    PocLogEntry logEntry = new PocLogEntry(paramName, errPoc, null, "diypoc(time)", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                    getAttackList.add(logEntry);
                                    diy_flag = true;
                                }
                            }
                        }
                    }
                }
                if (DetSql.stringChexk.isSelected()) {
                    stringloop:
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        if (sourceRequestIndex.charAt(valueStart - 1) == '"' && sourceRequestIndex.charAt(valueEnd) == '"') {
                            String paramName = parameter.name();
                            if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                                continue;
                            }
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            List<PocLogEntry> pocLogEntries = new ArrayList<>();
                            String firstPocResponseBody = "";
                            for (int i = 0; i < 1; i++) {
                                //单引号
                                String yinBody = prefix + "'" + suffix;
                                HttpRequest yinHttpRequest = sourceHttpRequest.withBody(yinBody);
                                HttpRequestResponse yinHttpRequestResponse = callMyRequest(yinHttpRequest, 2);
                                firstPocResponseBody = new String(yinHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                                if (Collections.min(firstDoubleList) <= 0.9) {
                                    String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'", firstSimimarity, "stringsql", String.valueOf(yinHttpRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpRequestResponse, requestSm3Hash));
                                } else {
                                    continue stringloop;
                                }
                            }
                            for (int i = 0; i < 1; i++) {
                                //string两个单引号
                                String dyinBody = prefix + "''" + suffix;
                                HttpRequest dyinHttpRequest = sourceHttpRequest.withBody(dyinBody);
                                HttpRequestResponse dyinHttpRequestResponse = callMyRequest(dyinHttpRequest, 2);
                                String dyinPocResponseBody = new String(dyinHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, dyinPocResponseBody,"","",html_flag);
                                if (Collections.min(secondDoubleList) <= 0.9) {
                                    String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, "''", secondSimimarity, "stringsql", String.valueOf(dyinHttpRequestResponse.response().bodyToString().length()), String.valueOf(dyinHttpRequestResponse.response().statusCode()), String.format("%.3f", (dyinHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpRequestResponse, requestSm3Hash));
                                } else {
                                    continue stringloop;
                                }
                            }

                            for (int i = 0; i < 1; i++) {
                                //"'+'"
                                String dyinBody3 = prefix + "'+'" + suffix;
                                HttpRequest dyinHttpRequest3 = sourceHttpRequest.withBody(dyinBody3);
                                HttpRequestResponse dyinHttpRequestResponse3 = callMyRequest(dyinHttpRequest3, 2);
                                String dyinPocResponseBody3 = new String(dyinHttpRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> secondDoubleList3 = MyCompare.averageLevenshtein(sourceBody, dyinPocResponseBody3,"","'+'",html_flag);
                                if (Collections.max(secondDoubleList3) > 0.9) {
                                    String secondSimimarity3 = MyCompare.formatPercent(Collections.max(secondDoubleList3));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'+'", secondSimimarity3, "stringsql", String.valueOf(dyinHttpRequestResponse3.response().bodyToString().length()), String.valueOf(dyinHttpRequestResponse3.response().statusCode()), String.format("%.3f", (dyinHttpRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpRequestResponse3, requestSm3Hash));
                                    getAttackList.addAll(pocLogEntries);
                                    string_flag = true;
                                    continue stringloop;
                                }
                            }

                            for (int i = 0; i < 1; i++) {
                                //"'||'"
                                String dyinBody4 = prefix + "'||'" + suffix;
                                HttpRequest dyinHttpRequest4 = sourceHttpRequest.withBody(dyinBody4);
                                HttpRequestResponse dyinHttpRequestResponse4 = callMyRequest(dyinHttpRequest4, 2);
                                String dyinPocResponseBody4 = new String(dyinHttpRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> secondDoubleList4 = MyCompare.averageLevenshtein(sourceBody, dyinPocResponseBody4,"","'||'",html_flag);
                                if (Collections.max(secondDoubleList4) > 0.9) {
                                    String lastSimimarity = MyCompare.formatPercent(Collections.max(secondDoubleList4));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'||'", lastSimimarity, "stringsql", String.valueOf(dyinHttpRequestResponse4.response().bodyToString().length()), String.valueOf(dyinHttpRequestResponse4.response().statusCode()), String.format("%.3f", (dyinHttpRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpRequestResponse4, requestSm3Hash));
                                    getAttackList.addAll(pocLogEntries);
                                    string_flag = true;
                                }
                            }


                        }
                    }
                }
                if (DetSql.orderChexk.isSelected()){
                    //order
                    orderloop:
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();

                        if (sourceRequestIndex.charAt(valueStart - 1) == '"' && sourceRequestIndex.charAt(valueEnd) == '"' && valueStart != valueEnd) {

                            String paramName = parameter.name();
                            if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                                continue;
                            }
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            List<PocLogEntry> pocLogEntries = new ArrayList<>();
                            String pocResponseBody = "";
                            for (int i = 0; i < 1; i++) {
                                //",0"
                                String pocBody = prefix + ",0" + suffix;
                                HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                                HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                                pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList = MyCompare.averageJaccard(sourceBody, pocResponseBody,"","",html_flag);
                                if (Collections.min(oneDoubleList) <= 0.9) {
                                    String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, ",0", mySimimarity, "ordersql", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash));
                                } else {
                                    continue orderloop;
                                }
                            }
                            String pocResponseBody1 = "";
                            for (int i = 0; i < 1; i++) {
                                //",XXXXXX"
                                String pocBody1 = prefix + ",XXXXXX" + suffix;
                                HttpRequest pocHttpRequest1 = sourceHttpRequest.withBody(pocBody1);
                                HttpRequestResponse pocHttpRequestResponse1 = callMyRequest(pocHttpRequest1, 2);
                                pocResponseBody1 = new String(pocHttpRequestResponse1.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList1 = MyCompare.averageJaccard(sourceBody, pocResponseBody1,"","",html_flag);
                                if (Collections.min(oneDoubleList1) <= 0.9) {
                                    String mySimimarity1 = MyCompare.formatPercent(Collections.min(oneDoubleList1));
                                    pocLogEntries.add(new PocLogEntry(paramName, ",XXXXXX", mySimimarity1, "ordersql", String.valueOf(pocHttpRequestResponse1.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse1.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse1.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse1, requestSm3Hash));
                                } else {
                                    continue orderloop;
                                }
                            }

                            List<Double> oneDoubleList2 = MyCompare.averageJaccard(pocResponseBody, pocResponseBody1,"","",html_flag);
                            if (Collections.max(oneDoubleList2) > 0.9) {
                                for (int i = 0; i < 1; i++) {
                                    // ",1", ",2",
                                    String pocBody2 = prefix + ",1" + suffix;
                                    HttpRequest pocHttpRequest2 = sourceHttpRequest.withBody(pocBody2);
                                    HttpRequestResponse pocHttpRequestResponse2 = callMyRequest(pocHttpRequest2, 2);
                                    String pocResponseBody2 = new String(pocHttpRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                                    List<Double> oneDoubleList3 = MyCompare.averageJaccard(sourceBody, pocResponseBody2,"",",1",html_flag);
                                    if (Collections.max(oneDoubleList3) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, pocResponseBody2,"","",html_flag)) <= 0.9) {
                                        String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                                        pocLogEntries.add(new PocLogEntry(paramName, ",1", mySimimarity, "ordersql", String.valueOf(pocHttpRequestResponse2.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse2.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse2, requestSm3Hash));
                                        getAttackList.addAll(pocLogEntries);
                                        order_flag = true;
                                        continue orderloop;
                                    }

                                }
                                for (int i = 0; i < 1; i++) {
                                    String pocBody3 = prefix + ",2" + suffix;
                                    HttpRequest pocHttpRequest3 = sourceHttpRequest.withBody(pocBody3);
                                    HttpRequestResponse pocHttpRequestResponse3 = callMyRequest(pocHttpRequest3, 2);
                                    String pocResponseBody3 = new String(pocHttpRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                                    List<Double> oneDoubleList4 = MyCompare.averageJaccard(sourceBody, pocResponseBody3,"",",2",html_flag);
                                    if (Collections.max(oneDoubleList4) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, pocResponseBody3,"","",html_flag)) <= 0.9) {
                                        String mySimimarityx = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                                        pocLogEntries.add(new PocLogEntry(paramName, ",2", mySimimarityx, "ordersql", String.valueOf(pocHttpRequestResponse3.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse3.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse3, requestSm3Hash));
                                        getAttackList.addAll(pocLogEntries);
                                        order_flag = true;
                                    }
                                }
                            }

                        }

                    }
                }
                //bool
                if (DetSql.boolChexk.isSelected()){
                    boolLoop:
                    for (ParsedHttpParameter parameter : parameters){
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        if(sourceRequestIndex.charAt(valueStart - 1) == '"' && sourceRequestIndex.charAt(valueEnd) == '"'){
                            String paramName = parameter.name();
                            if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                                continue;
                            }
                            //String paramValue = parameter.value();
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            List<PocLogEntry> pocLogEntries = new ArrayList<>();
                            String firstPocResponseBody = "";
                            for (int j = 0; j < 1; j++) {
                                //'||EXP(710)||'
                                String yinPocbody = prefix+"'||EXP(710)||'"+suffix;
                                HttpRequest yinPocHttpRequest = sourceHttpRequest.withBody(yinPocbody);
                                HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                                firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                                if (Collections.min(firstDoubleList) <= 0.9) {
                                    String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(710)||'", firstSimimarity, "boolsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                                } else {
                                    continue boolLoop;
                                }
                            }
                            for (int j = 0; j < 1; j++) {
                                //'||EXP(290)||'
                                String minPocbody = prefix+"'||EXP(290)||'"+suffix;
                                HttpRequest minPocHttpRequest = sourceHttpRequest.withBody(minPocbody);
                                HttpRequestResponse minHttpSendRequestResponse = callMyRequest(minPocHttpRequest, 2);
                                String minPocResponseBody = new String(minHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, minPocResponseBody,"","",html_flag);
                                if (Collections.min(secondDoubleList) <= 0.9) {
                                    String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(290)||'", secondSimimarity, "boolsql", String.valueOf(minHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(minHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (minHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), minHttpSendRequestResponse, requestSm3Hash));
                                    firstPocResponseBody=minPocResponseBody;
                                } else{
                                    String addPocbody=prefix+"'||1/0||'"+suffix;
                                    HttpRequest addPocHttpRequest = sourceHttpRequest.withBody(addPocbody);
                                    HttpRequestResponse addHttpSendRequestResponse = callMyRequest(addPocHttpRequest, 2);
                                    String addPocResponseBody = new String(addHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                    List<Double> addDoubleList = MyCompare.averageLevenshtein(sourceBody, addPocResponseBody,"","'||1/0||'",html_flag);
                                    if (Collections.max(addDoubleList) > 0.9) {
                                        String addSimimarity = MyCompare.formatPercent(Collections.max(addDoubleList));
                                        pocLogEntries.add(new PocLogEntry(paramName, "'||1/0||'", addSimimarity, "boolsql", String.valueOf(addHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(addHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (addHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), addHttpSendRequestResponse, requestSm3Hash));
                                        firstPocResponseBody=minPocResponseBody;
                                    }else{
                                        continue boolLoop;
                                    }
                                }
                            }
                            for (int j = 0; j < 1; j++) {
                                //"'||1%2F1||'"
                                String poc3Httpbody=prefix+"'||1/1||'"+suffix;
                                HttpRequest poc3HttpRequest = sourceHttpRequest.withBody(poc3Httpbody);
                                HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                                String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(firstPocResponseBody, poc3ResponseBody,"EXP\\(290\\)","1/1",html_flag);
                                if (Collections.max(oneDoubleList3) > 0.9) {
                                    String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'||1/1||'", lastSimimarity, "boolsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                    getAttackList.addAll(pocLogEntries);
                                    bool_flag = true;
                                }
                            }
                        }

                    }
                }


            } else if (!httpResponseReceived.initiatingRequest().parameters(HttpParameterType.XML).isEmpty()) {

                List<ParsedHttpParameter> parameters = httpResponseReceived.initiatingRequest().parameters(HttpParameterType.XML);
                String sourceRequestIndex = new String(httpResponseReceived.initiatingRequest().toByteArray().getBytes(), StandardCharsets.UTF_8);
                int bodyStartIndex = httpResponseReceived.initiatingRequest().bodyOffset();
                if (DetSql.errorChexk.isSelected()){
                    //err
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        String paramName = parameter.name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                        String suffix = sourceRequestIndex.substring(valueEnd);
                        for (String errPoc : errPocsj) {
                            String pocBody = prefix + errPoc + suffix;
                            HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                            HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                            String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            String resBool = ErrSqlCheck(pocResponseBody);
                            if (resBool != null) {
                                PocLogEntry logEntry = new PocLogEntry(paramName, errPoc, null, "errsql(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                err_flag = true;
                            }
                        }
                    }
                }
                //diy
                if (DetSql.diyChexk.isSelected()&&!diyPayloads.isEmpty()&&(!DetSql.timeTextField.getText().isEmpty()||!diyRegexs.isEmpty())){
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        String paramName = parameter.name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                        String suffix = sourceRequestIndex.substring(valueEnd);
                        for (String errPoc : diyPayloads) {
                            String pocBody = prefix + errPoc + suffix;
                            HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                            HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                            String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            if(!diyRegexs.isEmpty()){
                                String resBool = diyRegexCheck(pocResponseBody);
                                if (resBool != null) {
                                    PocLogEntry logEntry = new PocLogEntry(paramName, errPoc, null, "diypoc(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                    getAttackList.add(logEntry);
                                    diy_flag = true;
                                }
                            }
                            if(!DetSql.timeTextField.getText().isEmpty()&&pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()>intTime){
                                PocLogEntry logEntry = new PocLogEntry(paramName, errPoc, null, "diypoc(time)", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                diy_flag = true;
                            }
                        }
                    }
                }

                if (DetSql.numChexk.isSelected()) {
                    //数字
                    outerloop:
                    for (ParsedHttpParameter parameter : parameters) {
                        String paramName = parameter.name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = parameter.value();

                        try {
                            int parseInt = Integer.parseInt(paramValue);
                        } catch (NumberFormatException e) {
                            continue;
                        }
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                        String suffix = sourceRequestIndex.substring(valueEnd);
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String pocResponseBody = "";
                        //"-0-0-0"
                        for (int j = 0; j < 1; j++) {
                            String numBody = prefix + "-0-0-0" + suffix;
                            HttpRequest xmlNumHttpRequest = sourceHttpRequest.withBody(numBody);

                            HttpRequestResponse httpSendRequestResponse = callMyRequest(xmlNumHttpRequest, 2);

                            pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList = MyCompare.averageLevenshtein(sourceBody, pocResponseBody,"","-0-0-0",html_flag);
                            if (Collections.max(oneDoubleList) > 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "-0-0-0", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue outerloop;
                            }
                        }
                        String poc2ResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //"-abc"

                            String numBody2 = prefix + "-abc" + suffix;
                            HttpRequest xmlNumHttpRequest2 = sourceHttpRequest.withBody(numBody2);
                            HttpRequestResponse httpSendRequestResponse2 = callMyRequest(xmlNumHttpRequest2, 2);


                            poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList2 = MyCompare.averageLevenshtein(sourceBody, poc2ResponseBody,"","",html_flag);
                            if (Collections.min(oneDoubleList2) <= 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));
                                pocLogEntries.add(new PocLogEntry(paramName, "-abc", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                            } else {
                                continue outerloop;
                            }
                        }

                        List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(pocResponseBody, poc2ResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList3) <= 0.9) {
                            getAttackList.addAll(pocLogEntries);
                            num_flag = true;
                        }


                    }
                }
                if (DetSql.stringChexk.isSelected()){
                    //STRING
                    stringloop:
                    for (ParsedHttpParameter parameter : parameters) {

                        int valueEnd = parameter.valueOffsets().endIndexExclusive();

                        String paramName = parameter.name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                        String suffix = sourceRequestIndex.substring(valueEnd);
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String firstPocResponseBody = "";
                        for (int i = 0; i < 1; i++) {
                            //单引号
                            String yinBody = prefix + "'" + suffix;
                            HttpRequest yinHttpRequest = sourceHttpRequest.withBody(yinBody);
                            HttpRequestResponse yinHttpRequestResponse = callMyRequest(yinHttpRequest, 2);
                            firstPocResponseBody = new String(yinHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                            if (Collections.min(firstDoubleList) <= 0.9) {
                                String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'", firstSimimarity, "stringsql", String.valueOf(yinHttpRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpRequestResponse, requestSm3Hash));
                            } else {
                                continue stringloop;
                            }
                        }
                        for (int i = 0; i < 1; i++) {
                            //string两个单引号
                            String dyinBody = prefix + "''" + suffix;
                            HttpRequest dyinHttpRequest = sourceHttpRequest.withBody(dyinBody);
                            HttpRequestResponse dyinHttpRequestResponse = callMyRequest(dyinHttpRequest, 2);
                            String dyinPocResponseBody = new String(dyinHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, dyinPocResponseBody,"","",html_flag);
                            if (Collections.min(secondDoubleList) <= 0.9) {
                                String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "''", secondSimimarity, "stringsql", String.valueOf(dyinHttpRequestResponse.response().bodyToString().length()), String.valueOf(dyinHttpRequestResponse.response().statusCode()), String.format("%.3f", (dyinHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpRequestResponse, requestSm3Hash));
                            } else {
                                continue stringloop;
                            }
                        }

                        for (int i = 0; i < 1; i++) {
                            //"'+'"
                            String dyinBody3 = prefix + "'+'" + suffix;
                            HttpRequest dyinHttpRequest3 = sourceHttpRequest.withBody(dyinBody3);
                            HttpRequestResponse dyinHttpRequestResponse3 = callMyRequest(dyinHttpRequest3, 2);
                            String dyinPocResponseBody3 = new String(dyinHttpRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> secondDoubleList3 = MyCompare.averageLevenshtein(sourceBody, dyinPocResponseBody3,"","'+'",html_flag);
                            if (Collections.max(secondDoubleList3) > 0.9) {
                                String secondSimimarity3 = MyCompare.formatPercent(Collections.max(secondDoubleList3));
                                pocLogEntries.add(new PocLogEntry(paramName, "'+'", secondSimimarity3, "stringsql", String.valueOf(dyinHttpRequestResponse3.response().bodyToString().length()), String.valueOf(dyinHttpRequestResponse3.response().statusCode()), String.format("%.3f", (dyinHttpRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpRequestResponse3, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                string_flag = true;
                                continue stringloop;
                            }
                        }

                        for (int i = 0; i < 1; i++) {
                            //"'||'"
                            String dyinBody4 = prefix + "'||'" + suffix;
                            HttpRequest dyinHttpRequest4 = sourceHttpRequest.withBody(dyinBody4);
                            HttpRequestResponse dyinHttpRequestResponse4 = callMyRequest(dyinHttpRequest4, 2);
                            String dyinPocResponseBody4 = new String(dyinHttpRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> secondDoubleList4 = MyCompare.averageLevenshtein(sourceBody, dyinPocResponseBody4,"","'||'",html_flag);
                            if (Collections.max(secondDoubleList4) > 0.9) {
                                String lastSimimarity = MyCompare.formatPercent(Collections.max(secondDoubleList4));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||'", lastSimimarity, "stringsql", String.valueOf(dyinHttpRequestResponse4.response().bodyToString().length()), String.valueOf(dyinHttpRequestResponse4.response().statusCode()), String.format("%.3f", (dyinHttpRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpRequestResponse4, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                string_flag = true;
                            }
                        }


                    }
                }
                if (DetSql.orderChexk.isSelected()){
                    //order
                    orderloop:
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();

                        if (valueStart != valueEnd) {

                            String paramName = parameter.name();
                            if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                                continue;
                            }
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            List<PocLogEntry> pocLogEntries = new ArrayList<>();
                            String pocResponseBody = "";
                            for (int i = 0; i < 1; i++) {
                                //",0"
                                String pocBody = prefix + ",0" + suffix;
                                HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                                HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                                pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList = MyCompare.averageJaccard(sourceBody, pocResponseBody,"","",html_flag);
                                if (Collections.min(oneDoubleList) <= 0.9) {
                                    String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, ",0", mySimimarity, "ordersql", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash));
                                } else {
                                    continue orderloop;
                                }
                            }
                            String pocResponseBody1 = "";
                            for (int i = 0; i < 1; i++) {
                                //",XXXXXX"
                                String pocBody1 = prefix + ",XXXXXX" + suffix;
                                HttpRequest pocHttpRequest1 = sourceHttpRequest.withBody(pocBody1);
                                HttpRequestResponse pocHttpRequestResponse1 = callMyRequest(pocHttpRequest1, 2);
                                pocResponseBody1 = new String(pocHttpRequestResponse1.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList1 = MyCompare.averageJaccard(sourceBody, pocResponseBody1,"","",html_flag);
                                if (Collections.min(oneDoubleList1) <= 0.9) {
                                    String mySimimarity1 = MyCompare.formatPercent(Collections.min(oneDoubleList1));
                                    pocLogEntries.add(new PocLogEntry(paramName, ",XXXXXX", mySimimarity1, "ordersql", String.valueOf(pocHttpRequestResponse1.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse1.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse1.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse1, requestSm3Hash));
                                } else {
                                    continue orderloop;
                                }
                            }

                            List<Double> oneDoubleList2 = MyCompare.averageJaccard(pocResponseBody, pocResponseBody1,"","",html_flag);
                            if (Collections.max(oneDoubleList2) > 0.9) {
                                for (int i = 0; i < 1; i++) {
                                    // ",1", ",2",
                                    String pocBody2 = prefix + ",1" + suffix;
                                    HttpRequest pocHttpRequest2 = sourceHttpRequest.withBody(pocBody2);
                                    HttpRequestResponse pocHttpRequestResponse2 = callMyRequest(pocHttpRequest2, 2);
                                    String pocResponseBody2 = new String(pocHttpRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                                    List<Double> oneDoubleList3 = MyCompare.averageJaccard(sourceBody, pocResponseBody2,"",",1",html_flag);
                                    if (Collections.max(oneDoubleList3) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, pocResponseBody2,"","",html_flag)) <= 0.9) {
                                        String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                                        pocLogEntries.add(new PocLogEntry(paramName, ",1", mySimimarity, "ordersql", String.valueOf(pocHttpRequestResponse2.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse2.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse2, requestSm3Hash));
                                        getAttackList.addAll(pocLogEntries);
                                        order_flag = true;
                                        continue orderloop;
                                    }

                                }
                                for (int i = 0; i < 1; i++) {
                                    String pocBody3 = prefix + ",2" + suffix;
                                    HttpRequest pocHttpRequest3 = sourceHttpRequest.withBody(pocBody3);
                                    HttpRequestResponse pocHttpRequestResponse3 = callMyRequest(pocHttpRequest3, 2);
                                    String pocResponseBody3 = new String(pocHttpRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                                    List<Double> oneDoubleList4 = MyCompare.averageJaccard(sourceBody, pocResponseBody3,"",",2",html_flag);
                                    if (Collections.max(oneDoubleList4) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, pocResponseBody3,"","",html_flag)) <= 0.9) {
                                        String mySimimarityx = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                                        pocLogEntries.add(new PocLogEntry(paramName, ",2", mySimimarityx, "ordersql", String.valueOf(pocHttpRequestResponse3.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse3.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse3, requestSm3Hash));
                                        getAttackList.addAll(pocLogEntries);
                                        order_flag = true;
                                    }
                                }
                            }

                        }

                    }
                }
                //bool
                if (DetSql.boolChexk.isSelected()){
                    boolLoop:
                    for (ParsedHttpParameter parameter : parameters){
                        //int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        String paramName = parameter.name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        //String paramValue = parameter.value();
                        String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                        String suffix = sourceRequestIndex.substring(valueEnd);
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String firstPocResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //'||EXP(710)||'
                            String yinPocbody = prefix+"'||EXP(710)||'"+suffix;
                            HttpRequest yinPocHttpRequest = sourceHttpRequest.withBody(yinPocbody);
                            HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                            firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                            if (Collections.min(firstDoubleList) <= 0.9) {
                                String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(710)||'", firstSimimarity, "boolsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue boolLoop;
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            //'||EXP(290)||'
                            String minPocbody = prefix+"'||EXP(290)||'"+suffix;
                            HttpRequest minPocHttpRequest = sourceHttpRequest.withBody(minPocbody);
                            HttpRequestResponse minHttpSendRequestResponse = callMyRequest(minPocHttpRequest, 2);
                            String minPocResponseBody = new String(minHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, minPocResponseBody,"","",html_flag);
                            if (Collections.min(secondDoubleList) <= 0.9) {
                                String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(290)||'", secondSimimarity, "boolsql", String.valueOf(minHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(minHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (minHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), minHttpSendRequestResponse, requestSm3Hash));
                                firstPocResponseBody=minPocResponseBody;
                            } else{
                                String addPocbody=prefix+"'||1/0||'"+suffix;
                                HttpRequest addPocHttpRequest = sourceHttpRequest.withBody(addPocbody);
                                HttpRequestResponse addHttpSendRequestResponse = callMyRequest(addPocHttpRequest, 2);
                                String addPocResponseBody = new String(addHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> addDoubleList = MyCompare.averageLevenshtein(sourceBody, addPocResponseBody,"","'||1/0||'",html_flag);
                                if (Collections.max(addDoubleList) > 0.9) {
                                    String addSimimarity = MyCompare.formatPercent(Collections.max(addDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'||1/0||'", addSimimarity, "boolsql", String.valueOf(addHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(addHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (addHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), addHttpSendRequestResponse, requestSm3Hash));
                                    firstPocResponseBody=minPocResponseBody;
                                }else{
                                    continue boolLoop;
                                }
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            //"'||1%2F1||'"
                            String poc3Httpbody=prefix+"'||1/1||'"+suffix;
                            HttpRequest poc3HttpRequest = sourceHttpRequest.withBody(poc3Httpbody);
                            HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                            String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(firstPocResponseBody, poc3ResponseBody,"EXP\\(290\\)","1/1",html_flag);
                            if (Collections.max(oneDoubleList3) > 0.9) {
                                String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||1/1||'", lastSimimarity, "boolsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                bool_flag = true;
                            }
                        }
                    }
                }


            }
        }//POST 处理结束
        //处理cookie
        if (DetSql.cookieChexk.isSelected() && !httpResponseReceived.initiatingRequest().parameters(HttpParameterType.COOKIE).isEmpty()) {
            List<ParsedHttpParameter> parameters = httpResponseReceived.initiatingRequest().parameters(HttpParameterType.COOKIE);
            ArrayList<HttpParameter> newHttpParameters = new ArrayList<>();
            for (ParsedHttpParameter parameter : parameters) {
                newHttpParameters.add(HttpParameter.cookieParameter(parameter.name(), parameter.value()));
            }
            if (DetSql.errorChexk.isSelected()){
                //err
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    for (String poc : errPocs) {
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + poc));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                        String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        String resBool = ErrSqlCheck(pocResponseBody);
                        if (resBool != null) {
                            PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "errsql(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                            getAttackList.add(logEntry);
                            err_flag = true;
                        }
                    }
                }
            }
            //diy
            if (DetSql.diyChexk.isSelected()&&!diyPayloads.isEmpty()&&(!DetSql.timeTextField.getText().isEmpty()||!diyRegexs.isEmpty())){
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    for (String poc : diyPayloads) {
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + poc));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                        String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        if(!diyRegexs.isEmpty()){
                            String resBool = diyRegexCheck(pocResponseBody);
                            if (resBool != null) {
                                PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "diypoc(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                diy_flag = true;
                            }
                        }
                        if(!DetSql.timeTextField.getText().isEmpty()&&pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()>intTime){
                            PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "diypoc(time)", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                            getAttackList.add(logEntry);
                            diy_flag = true;
                        }
                    }
                }
            }
            if (DetSql.stringChexk.isSelected()) {
                //string
                stringloop:
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String firstPocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //单引号
                        List<HttpParameter> yinPocHttpParameters = new ArrayList<>(newHttpParameters);
                        yinPocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'"));
                        HttpRequest yinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(yinPocHttpParameters);
                        HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                        firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                        if (Collections.min(firstDoubleList) <= 0.9) {
                            String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "'", firstSimimarity, "stringsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue stringloop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //两个单引号
                        List<HttpParameter> dyinPocHttpParameters = new ArrayList<>(newHttpParameters);
                        dyinPocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "''"));
                        HttpRequest dyinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(dyinPocHttpParameters);
                        HttpRequestResponse dyinHttpSendRequestResponse = callMyRequest(dyinPocHttpRequest, 2);
                        String dyinPocResponseBody = new String(dyinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, dyinPocResponseBody,"","",html_flag);
                        if (Collections.min(secondDoubleList) <= 0.9) {
                            String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "''", secondSimimarity, "stringsql", String.valueOf(dyinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(dyinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (dyinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue stringloop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //"'+'"
                        List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                        poc3HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'+'"));
                        HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                        HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                        String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(sourceBody, poc3ResponseBody,"","'+'",html_flag);
                        if (Collections.max(oneDoubleList3) > 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                            pocLogEntries.add(new PocLogEntry(paramName, "'+'", mySimimarity, "stringsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                            getAttackList.addAll(pocLogEntries);
                            string_flag = true;
                            continue stringloop;
                        }
                    }

                    for (int j = 0; j < 1; j++) {
                        //"'||'"
                        List<HttpParameter> poc4HttpParameters = new ArrayList<>(newHttpParameters);
                        poc4HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'||'"));
                        HttpRequest poc4HttpRequest = sourceHttpRequest.withUpdatedParameters(poc4HttpParameters);
                        HttpRequestResponse httpSendRequestResponse4 = callMyRequest(poc4HttpRequest, 2);
                        String poc4ResponseBody = new String(httpSendRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList4 = MyCompare.averageLevenshtein(sourceBody, poc4ResponseBody,"","'||'",html_flag);
                        if (Collections.max(oneDoubleList4) > 0.9) {
                            String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||'", lastSimimarity, "stringsql", String.valueOf(httpSendRequestResponse4.response().bodyToString().length()), String.valueOf(httpSendRequestResponse4.response().statusCode()), String.format("%.3f", (httpSendRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse4, requestSm3Hash));
                            getAttackList.addAll(pocLogEntries);
                            string_flag = true;
                        }
                    }
                }
            }
            if (DetSql.numChexk.isSelected()){
                //数字
                outerloop:
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    try {
                        int parseInt = Integer.parseInt(paramValue);
                    } catch (NumberFormatException e) {
                        continue;
                    }
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String pocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //"-0-0-0"
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "-0-0-0"));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse httpSendRequestResponse = callMyRequest(pocHttpRequest, 2);
                        pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList = MyCompare.averageLevenshtein(sourceBody, pocResponseBody,"","-0-0-0",html_flag);
                        if (Collections.max(oneDoubleList) > 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "-0-0-0", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue outerloop;
                        }
                    }
                    String poc2ResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //"-abc"
                        List<HttpParameter> poc2HttpParameters = new ArrayList<>(newHttpParameters);
                        poc2HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "-abc"));
                        HttpRequest poc2HttpRequest = sourceHttpRequest.withUpdatedParameters(poc2HttpParameters);
                        HttpRequestResponse httpSendRequestResponse2 = callMyRequest(poc2HttpRequest, 2);
                        poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList2 = MyCompare.averageLevenshtein(sourceBody, poc2ResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList2) <= 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));
                            pocLogEntries.add(new PocLogEntry(paramName, "-abc", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                        } else {
                            continue outerloop;
                        }
                    }

                    List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(pocResponseBody, poc2ResponseBody,"","",html_flag);
                    if (Collections.min(oneDoubleList3) <= 0.9) {
                        getAttackList.addAll(pocLogEntries);
                        num_flag = true;
                    }
                }
            }
            if (DetSql.orderChexk.isSelected()){
                //order
                orderloop:
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    if (paramValue.isBlank()) {
                        continue;
                    }
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String pocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //",0"
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + ",0"));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse httpSendRequestResponse = callMyRequest(pocHttpRequest, 2);
                        pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList = MyCompare.averageJaccard(sourceBody, pocResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList) <= 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, ",0", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue orderloop;
                        }
                    }
                    String poc2ResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //",XXXXXX"
                        List<HttpParameter> poc2HttpParameters = new ArrayList<>(newHttpParameters);
                        poc2HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + ",XXXXXX"));
                        HttpRequest poc2HttpRequest = sourceHttpRequest.withUpdatedParameters(poc2HttpParameters);
                        HttpRequestResponse httpSendRequestResponse2 = callMyRequest(poc2HttpRequest, 2);
                        poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList2 = MyCompare.averageJaccard(sourceBody, poc2ResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList2) <= 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));
                            pocLogEntries.add(new PocLogEntry(paramName, ",XXXXXX", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                        } else {
                            continue orderloop;
                        }
                    }
                    List<Double> oneDoubleList3 = MyCompare.averageJaccard(pocResponseBody, poc2ResponseBody,"","",html_flag);
                    if (Collections.max(oneDoubleList3) > 0.9) {
                        for (int j = 0; j < 1; j++) {
                            // ",1", ",2",
                            List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                            poc3HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + ",1"));
                            HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                            HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                            String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList4 = MyCompare.averageJaccard(sourceBody, poc3ResponseBody,"",",1",html_flag);
                            if (Collections.max(oneDoubleList4) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, poc3ResponseBody,"","",html_flag)) <= 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                                pocLogEntries.add(new PocLogEntry(paramName, ",1", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                order_flag = true;
                                continue orderloop;
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            List<HttpParameter> poc4HttpParameters = new ArrayList<>(newHttpParameters);
                            poc4HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + ",2"));
                            HttpRequest poc4HttpRequest = sourceHttpRequest.withUpdatedParameters(poc4HttpParameters);
                            HttpRequestResponse httpSendRequestResponse4 = callMyRequest(poc4HttpRequest, 2);
                            String poc4ResponseBody = new String(httpSendRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList5 = MyCompare.averageJaccard(sourceBody, poc4ResponseBody,"",",2",html_flag);
                            if (Collections.max(oneDoubleList5) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, poc4ResponseBody,"","",html_flag)) <= 0.9) {
                                String mySimimarityx = MyCompare.formatPercent(Collections.max(oneDoubleList5));
                                pocLogEntries.add(new PocLogEntry(paramName, ",2", mySimimarityx, "ordersql", String.valueOf(httpSendRequestResponse4.response().bodyToString().length()), String.valueOf(httpSendRequestResponse4.response().statusCode()), String.format("%.3f", (httpSendRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse4, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                order_flag = true;
                            }
                        }
                    }

                }
            }
            //bool
            if (DetSql.boolChexk.isSelected()){
                boolLoop:
                for (int i = 0; i < newHttpParameters.size(); i++){
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String firstPocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //'||EXP(710)||'
                        List<HttpParameter> yinPocHttpParameters = new ArrayList<>(newHttpParameters);
                        yinPocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'||EXP(710)||'"));
                        HttpRequest yinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(yinPocHttpParameters);
                        HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                        firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                        if (Collections.min(firstDoubleList) <= 0.9) {
                            String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(710)||'", firstSimimarity, "boolsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue boolLoop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //'||EXP(290)||'
                        List<HttpParameter> minPocHttpParameters = new ArrayList<>(newHttpParameters);
                        minPocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'||EXP(290)||'"));
                        HttpRequest minPocHttpRequest = sourceHttpRequest.withUpdatedParameters(minPocHttpParameters);
                        HttpRequestResponse minHttpSendRequestResponse = callMyRequest(minPocHttpRequest, 2);
                        String minPocResponseBody = new String(minHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, minPocResponseBody,"","",html_flag);
                        if (Collections.min(secondDoubleList) <= 0.9) {
                            String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(290)||'", secondSimimarity, "boolsql", String.valueOf(minHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(minHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (minHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), minHttpSendRequestResponse, requestSm3Hash));
                            firstPocResponseBody=minPocResponseBody;
                        } else{
                            List<HttpParameter> addPocHttpParameters = new ArrayList<>(newHttpParameters);
                            addPocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'||1/0||'"));
                            HttpRequest addPocHttpRequest = sourceHttpRequest.withUpdatedParameters(addPocHttpParameters);
                            HttpRequestResponse addHttpSendRequestResponse = callMyRequest(addPocHttpRequest, 2);
                            String addPocResponseBody = new String(addHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> addDoubleList = MyCompare.averageLevenshtein(sourceBody, addPocResponseBody,"","'||1/0||'",html_flag);
                            if (Collections.max(addDoubleList) > 0.9) {
                                String addSimimarity = MyCompare.formatPercent(Collections.max(addDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||1/0||'", addSimimarity, "boolsql", String.valueOf(addHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(addHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (addHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), addHttpSendRequestResponse, requestSm3Hash));
                                firstPocResponseBody=minPocResponseBody;
                            }else{
                                continue boolLoop;
                            }
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //"'||1%2F1||'"
                        List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                        poc3HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'||1/1||'"));
                        HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                        HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                        String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(firstPocResponseBody, poc3ResponseBody,"EXP\\(290\\)","1/1",html_flag);
                        if (Collections.max(oneDoubleList3) > 0.9) {
                            String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||1/1||'", lastSimimarity, "boolsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                            getAttackList.addAll(pocLogEntries);
                            bool_flag = true;
                        }
                    }
                }
            }
        }
        StringBuilder sb = new StringBuilder();
        if (err_flag) {
            sb.append("-errsql");
        }
        if (string_flag) {
            sb.append("-stringsql");
        }
        if (num_flag) {
            sb.append("-numsql");
        }
        if (order_flag) {
            sb.append("-ordersql");
        }
        if (bool_flag) {
            sb.append("-boolsql");
        }
        if (diy_flag) {
            sb.append("-diypoc");
        }
        return sb.toString();
    }
    public String processOneRequest2(String requestSm3Hash,HttpRequestResponse httpRequestResponse) throws InterruptedException {
        boolean html_flag = httpRequestResponse.response().mimeType().description().equals("HTML");
        boolean err_flag = false;
        boolean num_flag = false;
        boolean order_flag = false;
        boolean string_flag = false;
        boolean bool_flag = false;

        boolean diy_flag = false;
        HttpRequest sourceHttpRequest = httpRequestResponse.request().copyToTempFile();
        String sourceBody = new String(httpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
        List<PocLogEntry> getAttackList = attackMap.get(requestSm3Hash);
        if (!httpRequestResponse.request().parameters(HttpParameterType.URL).isEmpty()) {
            //新参数
            List<ParsedHttpParameter> parameters = httpRequestResponse.request().parameters(HttpParameterType.URL);
            ArrayList<HttpParameter> newHttpParameters = new ArrayList<>();
            for (ParsedHttpParameter parameter : parameters) {
                newHttpParameters.add(HttpParameter.urlParameter(parameter.name(), parameter.value()));
            }
            //报错
            if (DetSql.errorChexk.isSelected()) {
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    for (String poc : errPocs) {
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + poc));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);

                        String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        String resBool = ErrSqlCheck(pocResponseBody);
                        if (resBool != null) {
                            PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "errsql(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                            getAttackList.add(logEntry);
                            err_flag = true;
                        }
                    }
                }
            }
            //diy
            if (DetSql.diyChexk.isSelected()&&!diyPayloads.isEmpty()&&(!DetSql.timeTextField.getText().isEmpty()||!diyRegexs.isEmpty())) {
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    for (String poc : diyPayloads) {
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + poc));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                        String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);

                        if(!diyRegexs.isEmpty()){
                            String resBool = diyRegexCheck(pocResponseBody);
                            if (resBool != null) {
                                PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "diypoc(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                diy_flag = true;
                            }
                        }
                        if(!DetSql.timeTextField.getText().isEmpty()&&pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()>intTime){
                            PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "diypoc(time)", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                            getAttackList.add(logEntry);
                            diy_flag = true;
                        }
                    }
                }
            }

            if (DetSql.stringChexk.isSelected()){
                stringloop:
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String firstPocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //单引号
                        List<HttpParameter> yinPocHttpParameters = new ArrayList<>(newHttpParameters);
                        yinPocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'"));
                        HttpRequest yinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(yinPocHttpParameters);
                        HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                        firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);

                        List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                        if (Collections.min(firstDoubleList) <= 0.9) {
                            String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "'", firstSimimarity, "stringsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue stringloop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //两个单引号
                        List<HttpParameter> dyinPocHttpParameters = new ArrayList<>(newHttpParameters);
                        dyinPocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "''"));
                        HttpRequest dyinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(dyinPocHttpParameters);
                        HttpRequestResponse dyinHttpSendRequestResponse = callMyRequest(dyinPocHttpRequest, 2);
                        String dyinPocResponseBody = new String(dyinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, dyinPocResponseBody,"","",html_flag);
                        if (Collections.min(secondDoubleList) <= 0.9) {
                            String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "''", secondSimimarity, "stringsql", String.valueOf(dyinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(dyinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (dyinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue stringloop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //"'+'"
                        List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                        poc3HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'%2B'"));
                        HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                        HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                        String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(sourceBody, poc3ResponseBody,"","'+'",html_flag);
                        if (Collections.max(oneDoubleList3) > 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                            pocLogEntries.add(new PocLogEntry(paramName, "'+'", mySimimarity, "stringsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                            getAttackList.addAll(pocLogEntries);
                            string_flag = true;
                            continue stringloop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //"'||'"
                        List<HttpParameter> poc4HttpParameters = new ArrayList<>(newHttpParameters);
                        poc4HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'||'"));
                        HttpRequest poc4HttpRequest = sourceHttpRequest.withUpdatedParameters(poc4HttpParameters);
                        HttpRequestResponse httpSendRequestResponse4 = callMyRequest(poc4HttpRequest, 2);
                        String poc4ResponseBody = new String(httpSendRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList4 = MyCompare.averageLevenshtein(sourceBody, poc4ResponseBody,"","'||'",html_flag);
                        if (Collections.max(oneDoubleList4) > 0.9) {
                            String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||'", lastSimimarity, "stringsql", String.valueOf(httpSendRequestResponse4.response().bodyToString().length()), String.valueOf(httpSendRequestResponse4.response().statusCode()), String.format("%.3f", (httpSendRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse4, requestSm3Hash));
                            getAttackList.addAll(pocLogEntries);
                            string_flag = true;
                        }
                    }
                }
            }

            //数字
            if (DetSql.numChexk.isSelected()){
                outerloop:
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    try {
                        int parseInt = Integer.parseInt(paramValue);
                    } catch (NumberFormatException e) {
                        continue;
                    }
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String pocResponseBody = "";
                    //"-0-0-0"
                    for (int j = 0; j < 1; j++) {
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "-0-0-0"));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);

                        HttpRequestResponse httpSendRequestResponse = callMyRequest(pocHttpRequest, 2);

                        pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList = MyCompare.averageLevenshtein(sourceBody, pocResponseBody,"","-0-0-0",html_flag);
                        if (Collections.max(oneDoubleList) > 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "-0-0-0", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue outerloop;
                        }
                    }
                    String poc2ResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //"-abc"
                        List<HttpParameter> poc2HttpParameters = new ArrayList<>(newHttpParameters);
                        poc2HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "-abc"));
                        HttpRequest poc2HttpRequest = sourceHttpRequest.withUpdatedParameters(poc2HttpParameters);

                        HttpRequestResponse httpSendRequestResponse2 = callMyRequest(poc2HttpRequest, 2);


                        poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList2 = MyCompare.averageLevenshtein(sourceBody, poc2ResponseBody,"","-abc",html_flag);
                        if (Collections.min(oneDoubleList2) <= 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));
                            pocLogEntries.add(new PocLogEntry(paramName, "-abc", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                        } else {
                            continue outerloop;
                        }
                    }

                    List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(pocResponseBody, poc2ResponseBody,"0-0-0","abc",html_flag);
                    if (Collections.min(oneDoubleList3) <= 0.9) {
                        getAttackList.addAll(pocLogEntries);
                        num_flag = true;
                    }


                }
            }

            //order
            if (DetSql.orderChexk.isSelected()){
                orderloop:
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    if (paramValue.isBlank()) {
                        continue;
                    }
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String pocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //",0"
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + ",0"));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse httpSendRequestResponse = callMyRequest(pocHttpRequest, 2);
                        pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList = MyCompare.averageJaccard(sourceBody, pocResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList) <= 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, ",0", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue orderloop;
                        }
                    }
                    String poc2ResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //",XXXXXX"
                        List<HttpParameter> poc2HttpParameters = new ArrayList<>(newHttpParameters);
                        poc2HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + ",XXXXXX"));
                        HttpRequest poc2HttpRequest = sourceHttpRequest.withUpdatedParameters(poc2HttpParameters);
                        HttpRequestResponse httpSendRequestResponse2 = callMyRequest(poc2HttpRequest, 2);
                        poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList2 = MyCompare.averageJaccard(sourceBody, poc2ResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList2) <= 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));
                            pocLogEntries.add(new PocLogEntry(paramName, ",XXXXXX", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                        } else {
                            continue orderloop;
                        }
                    }

                    List<Double> oneDoubleList3 = MyCompare.averageJaccard(pocResponseBody, poc2ResponseBody,"","",html_flag);
                    if (Collections.max(oneDoubleList3) > 0.9) {
                        for (int j = 0; j < 1; j++) {
                            List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                            poc3HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + ",1"));
                            HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                            HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                            String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList4 = MyCompare.averageJaccard(sourceBody, poc3ResponseBody,"","",html_flag);
                            if (Collections.max(oneDoubleList4) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, poc3ResponseBody,"","",html_flag)) <= 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                                pocLogEntries.add(new PocLogEntry(paramName, ",1", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                order_flag = true;
                                continue orderloop;
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            List<HttpParameter> poc4HttpParameters = new ArrayList<>(newHttpParameters);
                            poc4HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + ",2"));
                            HttpRequest poc4HttpRequest = sourceHttpRequest.withUpdatedParameters(poc4HttpParameters);
                            HttpRequestResponse httpSendRequestResponse4 = callMyRequest(poc4HttpRequest, 2);

                            String poc4ResponseBody = new String(httpSendRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList5 = MyCompare.averageJaccard(sourceBody, poc4ResponseBody,"","",html_flag);
                            if (Collections.max(oneDoubleList5) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, poc4ResponseBody,"","",html_flag)) <= 0.9) {
                                String mySimimarityx = MyCompare.formatPercent(Collections.max(oneDoubleList5));
                                pocLogEntries.add(new PocLogEntry(paramName, ",2", mySimimarityx, "ordersql", String.valueOf(httpSendRequestResponse4.response().bodyToString().length()), String.valueOf(httpSendRequestResponse4.response().statusCode()), String.format("%.3f", (httpSendRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse4, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                order_flag = true;
                            }
                        }
                    }


                }
            }
            //bool
            if (DetSql.boolChexk.isSelected()){
                boolLoop:
                for (int i = 0; i < newHttpParameters.size(); i++){
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String firstPocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //'||EXP(710)||'
                        List<HttpParameter> yinPocHttpParameters = new ArrayList<>(newHttpParameters);
                        yinPocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'||EXP(710)||'"));
                        HttpRequest yinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(yinPocHttpParameters);
                        HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                        firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                        if (Collections.min(firstDoubleList) <= 0.9) {
                            String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(710)||'", firstSimimarity, "boolsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue boolLoop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //'||EXP(290)||'
                        List<HttpParameter> minPocHttpParameters = new ArrayList<>(newHttpParameters);
                        minPocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'||EXP(290)||'"));
                        HttpRequest minPocHttpRequest = sourceHttpRequest.withUpdatedParameters(minPocHttpParameters);
                        HttpRequestResponse minHttpSendRequestResponse = callMyRequest(minPocHttpRequest, 2);
                        String minPocResponseBody = new String(minHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, minPocResponseBody,"","",html_flag);
                        if (Collections.min(secondDoubleList) <= 0.9) {
                            String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(290)||'", secondSimimarity, "boolsql", String.valueOf(minHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(minHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (minHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), minHttpSendRequestResponse, requestSm3Hash));
                            firstPocResponseBody=minPocResponseBody;
                        } else{
                            List<HttpParameter> addPocHttpParameters = new ArrayList<>(newHttpParameters);
                            addPocHttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'||1%2F0||'"));
                            HttpRequest addPocHttpRequest = sourceHttpRequest.withUpdatedParameters(addPocHttpParameters);
                            HttpRequestResponse addHttpSendRequestResponse = callMyRequest(addPocHttpRequest, 2);
                            String addPocResponseBody = new String(addHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> addDoubleList = MyCompare.averageLevenshtein(sourceBody, addPocResponseBody,"","'||1/0||'",html_flag);
                            if (Collections.max(addDoubleList) > 0.9) {
                                String addSimimarity = MyCompare.formatPercent(Collections.max(addDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||1%2F0||'", addSimimarity, "boolsql", String.valueOf(addHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(addHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (addHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), addHttpSendRequestResponse, requestSm3Hash));
                                firstPocResponseBody=minPocResponseBody;
                            }else{
                                continue boolLoop;
                            }
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //"'||1%2F1||'"
                        List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                        poc3HttpParameters.set(i, HttpParameter.urlParameter(paramName, paramValue + "'||1%2F1||'"));
                        HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                        HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                        String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(firstPocResponseBody, poc3ResponseBody,"EXP\\(290\\)","1/1",html_flag);
                        if (Collections.max(oneDoubleList3) > 0.9) {
                            String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||1%2F1||'", lastSimimarity, "boolsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                            getAttackList.addAll(pocLogEntries);
                            bool_flag = true;
                        }
                    }
                }
            }

        }
        //处理post
        if (httpRequestResponse.request().method().equals("POST")||httpRequestResponse.request().method().equals("PUT")) {
            if (!httpRequestResponse.request().parameters(HttpParameterType.BODY).isEmpty()) {
                //新参数
                List<ParsedHttpParameter> parameters = httpRequestResponse.request().parameters(HttpParameterType.BODY);
                ArrayList<HttpParameter> newHttpParameters = new ArrayList<>();
                for (ParsedHttpParameter parameter : parameters) {
                    newHttpParameters.add(HttpParameter.bodyParameter(parameter.name(), parameter.value()));
                }
                //err
                if (DetSql.errorChexk.isSelected()){
                    for (int i = 0; i < newHttpParameters.size(); i++) {
                        String paramName = newHttpParameters.get(i).name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = newHttpParameters.get(i).value();
                        for (String poc : errPocs) {
                            List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                            pocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + poc));
                            HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                            HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                            String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            String resBool = ErrSqlCheck(pocResponseBody);
                            if (resBool != null) {
                                PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "errsql(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                err_flag = true;
                            }
                        }
                    }
                }
                //diy
                if (DetSql.diyChexk.isSelected()&&!diyPayloads.isEmpty()&&(!DetSql.timeTextField.getText().isEmpty()||!diyRegexs.isEmpty())){
                    for (int i = 0; i < newHttpParameters.size(); i++) {
                        String paramName = newHttpParameters.get(i).name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = newHttpParameters.get(i).value();
                        for (String poc : diyPayloads) {
                            List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                            pocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + poc));
                            HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                            HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                            String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            if(!diyRegexs.isEmpty()){
                                String resBool = diyRegexCheck(pocResponseBody);
                                if (resBool != null) {
                                    PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "diypoc(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                    getAttackList.add(logEntry);
                                    diy_flag = true;
                                }
                            }
                            if(!DetSql.timeTextField.getText().isEmpty()&&pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()>intTime){
                                PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "diypoc(time)", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                diy_flag = true;
                            }
                        }
                    }
                }
                if (DetSql.stringChexk.isSelected()) {
                    //string
                    stringloop:
                    for (int i = 0; i < newHttpParameters.size(); i++) {
                        String paramName = newHttpParameters.get(i).name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = newHttpParameters.get(i).value();
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String firstPocResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //单引号
                            List<HttpParameter> yinPocHttpParameters = new ArrayList<>(newHttpParameters);
                            yinPocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'"));
                            HttpRequest yinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(yinPocHttpParameters);
                            HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                            firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                            if (Collections.min(firstDoubleList) <= 0.9) {
                                String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'", firstSimimarity, "stringsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue stringloop;
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            //两个单引号
                            List<HttpParameter> dyinPocHttpParameters = new ArrayList<>(newHttpParameters);
                            dyinPocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "''"));
                            HttpRequest dyinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(dyinPocHttpParameters);
                            HttpRequestResponse dyinHttpSendRequestResponse = callMyRequest(dyinPocHttpRequest, 2);
                            String dyinPocResponseBody = new String(dyinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, dyinPocResponseBody,"","",html_flag);
                            if (Collections.min(secondDoubleList) <= 0.9) {
                                String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "''", secondSimimarity, "stringsql", String.valueOf(dyinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(dyinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (dyinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue stringloop;
                            }
                        }


                        for (int j = 0; j < 1; j++) {
                            //"'+'"
                            List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                            poc3HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'+'"));
                            HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                            HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                            String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(sourceBody, poc3ResponseBody,"","'+'",html_flag);
                            if (Collections.max(oneDoubleList3) > 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                                pocLogEntries.add(new PocLogEntry(paramName, "'+'", mySimimarity, "stringsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                string_flag = true;
                                continue stringloop;
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            //"'||'"
                            List<HttpParameter> poc4HttpParameters = new ArrayList<>(newHttpParameters);
                            poc4HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'||'"));
                            HttpRequest poc4HttpRequest = sourceHttpRequest.withUpdatedParameters(poc4HttpParameters);
                            HttpRequestResponse httpSendRequestResponse4 = callMyRequest(poc4HttpRequest, 2);
                            String poc4ResponseBody = new String(httpSendRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList4 = MyCompare.averageLevenshtein(sourceBody, poc4ResponseBody,"","'||'",html_flag);
                            if (Collections.max(oneDoubleList4) > 0.9) {
                                String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||'", lastSimimarity, "stringsql", String.valueOf(httpSendRequestResponse4.response().bodyToString().length()), String.valueOf(httpSendRequestResponse4.response().statusCode()), String.format("%.3f", (httpSendRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse4, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                string_flag = true;
                            }
                        }
                    }
                }
                if (DetSql.numChexk.isSelected()){
                    //num
                    outerloop:
                    for (int i = 0; i < newHttpParameters.size(); i++) {
                        String paramName = newHttpParameters.get(i).name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = newHttpParameters.get(i).value();
                        try {
                            int parseInt = Integer.parseInt(paramValue);
                        } catch (NumberFormatException e) {
                            continue;
                        }
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String pocResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //"-0-0-0"
                            List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                            pocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "-0-0-0"));
                            HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                            HttpRequestResponse httpSendRequestResponse = callMyRequest(pocHttpRequest, 2);
                            pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);

                            List<Double> oneDoubleList = MyCompare.averageLevenshtein(sourceBody, pocResponseBody,"","-0-0-0",html_flag);
                            if (Collections.max(oneDoubleList) > 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "-0-0-0", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue outerloop;
                            }
                        }
                        String poc2ResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //"-abc"
                            List<HttpParameter> poc2HttpParameters = new ArrayList<>(newHttpParameters);
                            poc2HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "-abc"));
                            HttpRequest poc2HttpRequest = sourceHttpRequest.withUpdatedParameters(poc2HttpParameters);
                            HttpRequestResponse httpSendRequestResponse2 = callMyRequest(poc2HttpRequest, 2);

                            poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList2 = MyCompare.averageLevenshtein(sourceBody, poc2ResponseBody,"","",html_flag);
                            if (Collections.min(oneDoubleList2) <= 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));

                                pocLogEntries.add(new PocLogEntry(paramName, "-abc", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                            } else {
                                continue outerloop;
                            }
                        }

                        List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(pocResponseBody, poc2ResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList3) <= 0.9) {
                            getAttackList.addAll(pocLogEntries);
                            num_flag = true;
                        }
                    }
                }
                if (DetSql.orderChexk.isSelected()){
                    //order
                    orderloop:
                    for (int i = 0; i < newHttpParameters.size(); i++) {
                        String paramName = newHttpParameters.get(i).name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = newHttpParameters.get(i).value();
                        if (paramValue.isBlank()) {
                            continue;
                        }
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String pocResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //",0"
                            List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                            pocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + ",0"));
                            HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                            HttpRequestResponse httpSendRequestResponse = callMyRequest(pocHttpRequest, 2);
                            pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList = MyCompare.averageJaccard(sourceBody, pocResponseBody,"","",html_flag);
                            if (Collections.min(oneDoubleList) <= 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, ",0", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue orderloop;
                            }
                        }
                        String poc2ResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //",XXXXXX"
                            List<HttpParameter> poc2HttpParameters = new ArrayList<>(newHttpParameters);
                            poc2HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + ",XXXXXX"));
                            HttpRequest poc2HttpRequest = sourceHttpRequest.withUpdatedParameters(poc2HttpParameters);
                            HttpRequestResponse httpSendRequestResponse2 = callMyRequest(poc2HttpRequest, 2);
                            poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList2 = MyCompare.averageJaccard(sourceBody, poc2ResponseBody,"","",html_flag);
                            if (Collections.min(oneDoubleList2) <= 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));
                                pocLogEntries.add(new PocLogEntry(paramName, ",XXXXXX", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                            } else {
                                continue orderloop;
                            }
                        }

                        List<Double> oneDoubleList3 = MyCompare.averageJaccard(pocResponseBody, poc2ResponseBody,"","",html_flag);
                        if (Collections.max(oneDoubleList3) > 0.9) {
                            for (int j = 0; j < 1; j++) {
                                // ",1", ",2", ",TRUE"
                                List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                                poc3HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + ",1"));
                                HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                                HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);

                                String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList4 = MyCompare.averageJaccard(sourceBody, poc3ResponseBody,"",",1",html_flag);
                                if (Collections.max(oneDoubleList4) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, poc3ResponseBody,"","",html_flag)) <= 0.9) {
                                    String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                                    pocLogEntries.add(new PocLogEntry(paramName, ",1", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                    getAttackList.addAll(pocLogEntries);
                                    order_flag = true;
                                    continue orderloop;
                                }
                            }
                            for (int k = 0; k < 1; k++) {
                                List<HttpParameter> poc4HttpParameters = new ArrayList<>(newHttpParameters);
                                poc4HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + ",2"));
                                HttpRequest poc4HttpRequest = sourceHttpRequest.withUpdatedParameters(poc4HttpParameters);
                                HttpRequestResponse httpSendRequestResponse4 = callMyRequest(poc4HttpRequest, 2);

                                String poc4ResponseBody = new String(httpSendRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList5 = MyCompare.averageJaccard(sourceBody, poc4ResponseBody,"",",2",html_flag);
                                if (Collections.max(oneDoubleList5) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, poc4ResponseBody,"","",html_flag)) <= 0.9) {
                                    String mySimimarityx = MyCompare.formatPercent(Collections.max(oneDoubleList5));
                                    pocLogEntries.add(new PocLogEntry(paramName, ",2", mySimimarityx, "ordersql", String.valueOf(httpSendRequestResponse4.response().bodyToString().length()), String.valueOf(httpSendRequestResponse4.response().statusCode()), String.format("%.3f", (httpSendRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse4, requestSm3Hash));
                                    getAttackList.addAll(pocLogEntries);
                                    order_flag = true;
                                }
                            }
                        }

                    }
                }
                //bool
                if (DetSql.boolChexk.isSelected()){
                    boolLoop:
                    for (int i = 0; i < newHttpParameters.size(); i++){
                        String paramName = newHttpParameters.get(i).name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = newHttpParameters.get(i).value();
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String firstPocResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //'||EXP(710)||'
                            List<HttpParameter> yinPocHttpParameters = new ArrayList<>(newHttpParameters);
                            yinPocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'||EXP(710)||'"));
                            HttpRequest yinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(yinPocHttpParameters);
                            HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                            firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                            if (Collections.min(firstDoubleList) <= 0.9) {
                                String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(710)||'", firstSimimarity, "boolsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue boolLoop;
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            //'||EXP(290)||'
                            List<HttpParameter> minPocHttpParameters = new ArrayList<>(newHttpParameters);
                            minPocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'||EXP(290)||'"));
                            HttpRequest minPocHttpRequest = sourceHttpRequest.withUpdatedParameters(minPocHttpParameters);
                            HttpRequestResponse minHttpSendRequestResponse = callMyRequest(minPocHttpRequest, 2);
                            String minPocResponseBody = new String(minHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, minPocResponseBody,"","",html_flag);
                            if (Collections.min(secondDoubleList) <= 0.9) {
                                String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(290)||'", secondSimimarity, "boolsql", String.valueOf(minHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(minHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (minHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), minHttpSendRequestResponse, requestSm3Hash));
                                firstPocResponseBody=minPocResponseBody;
                            } else{
                                List<HttpParameter> addPocHttpParameters = new ArrayList<>(newHttpParameters);
                                addPocHttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'||1/0||'"));
                                HttpRequest addPocHttpRequest = sourceHttpRequest.withUpdatedParameters(addPocHttpParameters);
                                HttpRequestResponse addHttpSendRequestResponse = callMyRequest(addPocHttpRequest, 2);
                                String addPocResponseBody = new String(addHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> addDoubleList = MyCompare.averageLevenshtein(sourceBody, addPocResponseBody,"","'||1/0||'",html_flag);
                                if (Collections.max(addDoubleList) > 0.9) {
                                    String addSimimarity = MyCompare.formatPercent(Collections.max(addDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'||1/0||'", addSimimarity, "boolsql", String.valueOf(addHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(addHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (addHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), addHttpSendRequestResponse, requestSm3Hash));
                                    firstPocResponseBody=minPocResponseBody;
                                }else{
                                    continue boolLoop;
                                }
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            //"'||1%2F1||'"
                            List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                            poc3HttpParameters.set(i, HttpParameter.bodyParameter(paramName, paramValue + "'||1/1||'"));
                            HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                            HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                            String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(firstPocResponseBody, poc3ResponseBody,"EXP\\(290\\)","1/1",html_flag);
                            if (Collections.max(oneDoubleList3) > 0.9) {
                                String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||1/1||'", lastSimimarity, "boolsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                bool_flag = true;
                            }
                        }
                    }
                }
            } else if (!httpRequestResponse.request().parameters(HttpParameterType.JSON).isEmpty()) {
                List<ParsedHttpParameter> parameters = httpRequestResponse.request().parameters(HttpParameterType.JSON);
                String sourceRequestIndex = new String(httpRequestResponse.request().toByteArray().getBytes(), StandardCharsets.UTF_8);
                int bodyStartIndex = httpRequestResponse.request().bodyOffset();
                if (DetSql.errorChexk.isSelected()){
                    //err
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        if (sourceRequestIndex.charAt(valueStart - 1) == '"' && sourceRequestIndex.charAt(valueEnd) == '"') {
                            String paramName = parameter.name();
                            if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                                continue;
                            }
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            for (String errPoc : errPocsj) {
                                String pocBody = prefix + errPoc + suffix;
                                HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                                HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                                String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                String resBool = ErrSqlCheck(pocResponseBody);
                                if (resBool != null) {
                                    PocLogEntry logEntry = new PocLogEntry(paramName, errPoc, null, "errsql(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                    getAttackList.add(logEntry);
                                    err_flag = true;
                                }
                            }
                        }
                    }
                }
                //diy
                if (DetSql.diyChexk.isSelected()&&!diyPayloads.isEmpty()&&(!DetSql.timeTextField.getText().isEmpty()||!diyRegexs.isEmpty())){
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        if (sourceRequestIndex.charAt(valueStart - 1) == '"' && sourceRequestIndex.charAt(valueEnd) == '"') {
                            String paramName = parameter.name();
                            if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                                continue;
                            }
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            for (String errPoc : diyPayloads) {
                                String pocBody = prefix + errPoc + suffix;
                                HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                                HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                                String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                if(!diyRegexs.isEmpty()){
                                    String resBool = diyRegexCheck(pocResponseBody);
                                    if (resBool != null) {
                                        PocLogEntry logEntry = new PocLogEntry(paramName, errPoc, null, "diypoc(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                        getAttackList.add(logEntry);
                                        diy_flag = true;
                                    }
                                }
                                if(!DetSql.timeTextField.getText().isEmpty()&&pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()>intTime){
                                    PocLogEntry logEntry = new PocLogEntry(paramName, errPoc, null, "diypoc(time)", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                    getAttackList.add(logEntry);
                                    diy_flag = true;
                                }
                            }
                        }
                    }
                }
                if (DetSql.stringChexk.isSelected()) {
                    stringloop:
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        if (sourceRequestIndex.charAt(valueStart - 1) == '"' && sourceRequestIndex.charAt(valueEnd) == '"') {
                            String paramName = parameter.name();
                            if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                                continue;
                            }
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            List<PocLogEntry> pocLogEntries = new ArrayList<>();
                            String firstPocResponseBody = "";
                            for (int i = 0; i < 1; i++) {
                                //单引号
                                String yinBody = prefix + "'" + suffix;
                                HttpRequest yinHttpRequest = sourceHttpRequest.withBody(yinBody);
                                HttpRequestResponse yinHttpRequestResponse = callMyRequest(yinHttpRequest, 2);
                                firstPocResponseBody = new String(yinHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                                if (Collections.min(firstDoubleList) <= 0.9) {
                                    String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'", firstSimimarity, "stringsql", String.valueOf(yinHttpRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpRequestResponse, requestSm3Hash));
                                } else {
                                    continue stringloop;
                                }
                            }
                            for (int i = 0; i < 1; i++) {
                                //string两个单引号
                                String dyinBody = prefix + "''" + suffix;
                                HttpRequest dyinHttpRequest = sourceHttpRequest.withBody(dyinBody);
                                HttpRequestResponse dyinHttpRequestResponse = callMyRequest(dyinHttpRequest, 2);
                                String dyinPocResponseBody = new String(dyinHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, dyinPocResponseBody,"","",html_flag);
                                if (Collections.min(secondDoubleList) <= 0.9) {
                                    String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, "''", secondSimimarity, "stringsql", String.valueOf(dyinHttpRequestResponse.response().bodyToString().length()), String.valueOf(dyinHttpRequestResponse.response().statusCode()), String.format("%.3f", (dyinHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpRequestResponse, requestSm3Hash));
                                } else {
                                    continue stringloop;
                                }
                            }

                            for (int i = 0; i < 1; i++) {
                                //"'+'"
                                String dyinBody3 = prefix + "'+'" + suffix;
                                HttpRequest dyinHttpRequest3 = sourceHttpRequest.withBody(dyinBody3);
                                HttpRequestResponse dyinHttpRequestResponse3 = callMyRequest(dyinHttpRequest3, 2);
                                String dyinPocResponseBody3 = new String(dyinHttpRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> secondDoubleList3 = MyCompare.averageLevenshtein(sourceBody, dyinPocResponseBody3,"","'+'",html_flag);
                                if (Collections.max(secondDoubleList3) > 0.9) {
                                    String secondSimimarity3 = MyCompare.formatPercent(Collections.max(secondDoubleList3));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'+'", secondSimimarity3, "stringsql", String.valueOf(dyinHttpRequestResponse3.response().bodyToString().length()), String.valueOf(dyinHttpRequestResponse3.response().statusCode()), String.format("%.3f", (dyinHttpRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpRequestResponse3, requestSm3Hash));
                                    getAttackList.addAll(pocLogEntries);
                                    string_flag = true;
                                    continue stringloop;
                                }
                            }

                            for (int i = 0; i < 1; i++) {
                                //"'||'"
                                String dyinBody4 = prefix + "'||'" + suffix;
                                HttpRequest dyinHttpRequest4 = sourceHttpRequest.withBody(dyinBody4);
                                HttpRequestResponse dyinHttpRequestResponse4 = callMyRequest(dyinHttpRequest4, 2);
                                String dyinPocResponseBody4 = new String(dyinHttpRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> secondDoubleList4 = MyCompare.averageLevenshtein(sourceBody, dyinPocResponseBody4,"","'||'",html_flag);
                                if (Collections.max(secondDoubleList4) > 0.9) {
                                    String lastSimimarity = MyCompare.formatPercent(Collections.max(secondDoubleList4));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'||'", lastSimimarity, "stringsql", String.valueOf(dyinHttpRequestResponse4.response().bodyToString().length()), String.valueOf(dyinHttpRequestResponse4.response().statusCode()), String.format("%.3f", (dyinHttpRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpRequestResponse4, requestSm3Hash));
                                    getAttackList.addAll(pocLogEntries);
                                    string_flag = true;
                                }
                            }


                        }
                    }
                }
                if (DetSql.orderChexk.isSelected()){
                    //order
                    orderloop:
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();

                        if (sourceRequestIndex.charAt(valueStart - 1) == '"' && sourceRequestIndex.charAt(valueEnd) == '"' && valueStart != valueEnd) {

                            String paramName = parameter.name();
                            if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                                continue;
                            }
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            List<PocLogEntry> pocLogEntries = new ArrayList<>();
                            String pocResponseBody = "";
                            for (int i = 0; i < 1; i++) {
                                //",0"
                                String pocBody = prefix + ",0" + suffix;
                                HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                                HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                                pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList = MyCompare.averageJaccard(sourceBody, pocResponseBody,"","",html_flag);
                                if (Collections.min(oneDoubleList) <= 0.9) {
                                    String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, ",0", mySimimarity, "ordersql", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash));
                                } else {
                                    continue orderloop;
                                }
                            }
                            String pocResponseBody1 = "";
                            for (int i = 0; i < 1; i++) {
                                //",XXXXXX"
                                String pocBody1 = prefix + ",XXXXXX" + suffix;
                                HttpRequest pocHttpRequest1 = sourceHttpRequest.withBody(pocBody1);
                                HttpRequestResponse pocHttpRequestResponse1 = callMyRequest(pocHttpRequest1, 2);
                                pocResponseBody1 = new String(pocHttpRequestResponse1.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList1 = MyCompare.averageJaccard(sourceBody, pocResponseBody1,"","",html_flag);
                                if (Collections.min(oneDoubleList1) <= 0.9) {
                                    String mySimimarity1 = MyCompare.formatPercent(Collections.min(oneDoubleList1));
                                    pocLogEntries.add(new PocLogEntry(paramName, ",XXXXXX", mySimimarity1, "ordersql", String.valueOf(pocHttpRequestResponse1.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse1.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse1.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse1, requestSm3Hash));
                                } else {
                                    continue orderloop;
                                }
                            }

                            List<Double> oneDoubleList2 = MyCompare.averageJaccard(pocResponseBody, pocResponseBody1,"","",html_flag);
                            if (Collections.max(oneDoubleList2) > 0.9) {
                                for (int i = 0; i < 1; i++) {
                                    // ",1", ",2",
                                    String pocBody2 = prefix + ",1" + suffix;
                                    HttpRequest pocHttpRequest2 = sourceHttpRequest.withBody(pocBody2);
                                    HttpRequestResponse pocHttpRequestResponse2 = callMyRequest(pocHttpRequest2, 2);
                                    String pocResponseBody2 = new String(pocHttpRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                                    List<Double> oneDoubleList3 = MyCompare.averageJaccard(sourceBody, pocResponseBody2,"",",1",html_flag);
                                    if (Collections.max(oneDoubleList3) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, pocResponseBody2,"","",html_flag)) <= 0.9) {
                                        String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                                        pocLogEntries.add(new PocLogEntry(paramName, ",1", mySimimarity, "ordersql", String.valueOf(pocHttpRequestResponse2.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse2.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse2, requestSm3Hash));
                                        getAttackList.addAll(pocLogEntries);
                                        order_flag = true;
                                        continue orderloop;
                                    }

                                }
                                for (int i = 0; i < 1; i++) {
                                    String pocBody3 = prefix + ",2" + suffix;
                                    HttpRequest pocHttpRequest3 = sourceHttpRequest.withBody(pocBody3);
                                    HttpRequestResponse pocHttpRequestResponse3 = callMyRequest(pocHttpRequest3, 2);
                                    String pocResponseBody3 = new String(pocHttpRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                                    List<Double> oneDoubleList4 = MyCompare.averageJaccard(sourceBody, pocResponseBody3,"",",2",html_flag);
                                    if (Collections.max(oneDoubleList4) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, pocResponseBody3,"","",html_flag)) <= 0.9) {
                                        String mySimimarityx = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                                        pocLogEntries.add(new PocLogEntry(paramName, ",2", mySimimarityx, "ordersql", String.valueOf(pocHttpRequestResponse3.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse3.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse3, requestSm3Hash));
                                        getAttackList.addAll(pocLogEntries);
                                        order_flag = true;
                                    }
                                }
                            }

                        }

                    }
                }
                //bool
                if (DetSql.boolChexk.isSelected()){
                    boolLoop:
                    for (ParsedHttpParameter parameter : parameters){
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        if(sourceRequestIndex.charAt(valueStart - 1) == '"' && sourceRequestIndex.charAt(valueEnd) == '"'){
                            String paramName = parameter.name();
                            if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                                continue;
                            }
                            //String paramValue = parameter.value();
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            List<PocLogEntry> pocLogEntries = new ArrayList<>();
                            String firstPocResponseBody = "";
                            for (int j = 0; j < 1; j++) {
                                //'||EXP(710)||'
                                String yinPocbody = prefix+"'||EXP(710)||'"+suffix;
                                HttpRequest yinPocHttpRequest = sourceHttpRequest.withBody(yinPocbody);
                                HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                                firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                                if (Collections.min(firstDoubleList) <= 0.9) {
                                    String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(710)||'", firstSimimarity, "boolsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                                } else {
                                    continue boolLoop;
                                }
                            }
                            for (int j = 0; j < 1; j++) {
                                //'||EXP(290)||'
                                String minPocbody = prefix+"'||EXP(290)||'"+suffix;
                                HttpRequest minPocHttpRequest = sourceHttpRequest.withBody(minPocbody);
                                HttpRequestResponse minHttpSendRequestResponse = callMyRequest(minPocHttpRequest, 2);
                                String minPocResponseBody = new String(minHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, minPocResponseBody,"","",html_flag);
                                if (Collections.min(secondDoubleList) <= 0.9) {
                                    String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(290)||'", secondSimimarity, "boolsql", String.valueOf(minHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(minHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (minHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), minHttpSendRequestResponse, requestSm3Hash));
                                    firstPocResponseBody=minPocResponseBody;
                                } else{
                                    String addPocbody=prefix+"'||1/0||'"+suffix;
                                    HttpRequest addPocHttpRequest = sourceHttpRequest.withBody(addPocbody);
                                    HttpRequestResponse addHttpSendRequestResponse = callMyRequest(addPocHttpRequest, 2);
                                    String addPocResponseBody = new String(addHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                    List<Double> addDoubleList = MyCompare.averageLevenshtein(sourceBody, addPocResponseBody,"","'||1/0||'",html_flag);
                                    if (Collections.max(addDoubleList) > 0.9) {
                                        String addSimimarity = MyCompare.formatPercent(Collections.max(addDoubleList));
                                        pocLogEntries.add(new PocLogEntry(paramName, "'||1/0||'", addSimimarity, "boolsql", String.valueOf(addHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(addHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (addHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), addHttpSendRequestResponse, requestSm3Hash));
                                        firstPocResponseBody=minPocResponseBody;
                                    }else{
                                        continue boolLoop;
                                    }
                                }
                            }
                            for (int j = 0; j < 1; j++) {
                                //"'||1%2F1||'"
                                String poc3Httpbody=prefix+"'||1/1||'"+suffix;
                                HttpRequest poc3HttpRequest = sourceHttpRequest.withBody(poc3Httpbody);
                                HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                                String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(firstPocResponseBody, poc3ResponseBody,"EXP\\(290\\)","1/1",html_flag);
                                if (Collections.max(oneDoubleList3) > 0.9) {
                                    String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'||1/1||'", lastSimimarity, "boolsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                    getAttackList.addAll(pocLogEntries);
                                    bool_flag = true;
                                }
                            }
                        }

                    }
                }


            } else if (!httpRequestResponse.request().parameters(HttpParameterType.XML).isEmpty()) {

                List<ParsedHttpParameter> parameters = httpRequestResponse.request().parameters(HttpParameterType.XML);
                String sourceRequestIndex = new String(httpRequestResponse.request().toByteArray().getBytes(), StandardCharsets.UTF_8);
                int bodyStartIndex = httpRequestResponse.request().bodyOffset();
                if (DetSql.errorChexk.isSelected()){
                    //err
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        String paramName = parameter.name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                        String suffix = sourceRequestIndex.substring(valueEnd);
                        for (String errPoc : errPocsj) {
                            String pocBody = prefix + errPoc + suffix;
                            HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                            HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                            String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            String resBool = ErrSqlCheck(pocResponseBody);
                            if (resBool != null) {
                                PocLogEntry logEntry = new PocLogEntry(paramName, errPoc, null, "errsql(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                err_flag = true;
                            }
                        }
                    }
                }
                //diy
                if (DetSql.diyChexk.isSelected()&&!diyPayloads.isEmpty()&&(!DetSql.timeTextField.getText().isEmpty()||!diyRegexs.isEmpty())){
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        String paramName = parameter.name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                        String suffix = sourceRequestIndex.substring(valueEnd);
                        for (String errPoc : diyPayloads) {
                            String pocBody = prefix + errPoc + suffix;
                            HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                            HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                            String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            if(!diyRegexs.isEmpty()){
                                String resBool = diyRegexCheck(pocResponseBody);
                                if (resBool != null) {
                                    PocLogEntry logEntry = new PocLogEntry(paramName, errPoc, null, "diypoc(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                    getAttackList.add(logEntry);
                                    diy_flag = true;
                                }
                            }
                            if(!DetSql.timeTextField.getText().isEmpty()&&pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()>intTime){
                                PocLogEntry logEntry = new PocLogEntry(paramName, errPoc, null, "diypoc(time)", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                diy_flag = true;
                            }
                        }
                    }
                }

                if (DetSql.numChexk.isSelected()) {
                    //数字
                    outerloop:
                    for (ParsedHttpParameter parameter : parameters) {
                        String paramName = parameter.name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String paramValue = parameter.value();

                        try {
                            int parseInt = Integer.parseInt(paramValue);
                        } catch (NumberFormatException e) {
                            continue;
                        }
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                        String suffix = sourceRequestIndex.substring(valueEnd);
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String pocResponseBody = "";
                        //"-0-0-0"
                        for (int j = 0; j < 1; j++) {
                            String numBody = prefix + "-0-0-0" + suffix;
                            HttpRequest xmlNumHttpRequest = sourceHttpRequest.withBody(numBody);

                            HttpRequestResponse httpSendRequestResponse = callMyRequest(xmlNumHttpRequest, 2);

                            pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList = MyCompare.averageLevenshtein(sourceBody, pocResponseBody,"","-0-0-0",html_flag);
                            if (Collections.max(oneDoubleList) > 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "-0-0-0", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue outerloop;
                            }
                        }
                        String poc2ResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //"-abc"

                            String numBody2 = prefix + "-abc" + suffix;
                            HttpRequest xmlNumHttpRequest2 = sourceHttpRequest.withBody(numBody2);
                            HttpRequestResponse httpSendRequestResponse2 = callMyRequest(xmlNumHttpRequest2, 2);


                            poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList2 = MyCompare.averageLevenshtein(sourceBody, poc2ResponseBody,"","",html_flag);
                            if (Collections.min(oneDoubleList2) <= 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));
                                pocLogEntries.add(new PocLogEntry(paramName, "-abc", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                            } else {
                                continue outerloop;
                            }
                        }

                        List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(pocResponseBody, poc2ResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList3) <= 0.9) {
                            getAttackList.addAll(pocLogEntries);
                            num_flag = true;
                        }


                    }
                }
                if (DetSql.stringChexk.isSelected()){
                    //STRING
                    stringloop:
                    for (ParsedHttpParameter parameter : parameters) {

                        int valueEnd = parameter.valueOffsets().endIndexExclusive();

                        String paramName = parameter.name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                        String suffix = sourceRequestIndex.substring(valueEnd);
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String firstPocResponseBody = "";
                        for (int i = 0; i < 1; i++) {
                            //单引号
                            String yinBody = prefix + "'" + suffix;
                            HttpRequest yinHttpRequest = sourceHttpRequest.withBody(yinBody);
                            HttpRequestResponse yinHttpRequestResponse = callMyRequest(yinHttpRequest, 2);
                            firstPocResponseBody = new String(yinHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                            if (Collections.min(firstDoubleList) <= 0.9) {
                                String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'", firstSimimarity, "stringsql", String.valueOf(yinHttpRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpRequestResponse, requestSm3Hash));
                            } else {
                                continue stringloop;
                            }
                        }
                        for (int i = 0; i < 1; i++) {
                            //string两个单引号
                            String dyinBody = prefix + "''" + suffix;
                            HttpRequest dyinHttpRequest = sourceHttpRequest.withBody(dyinBody);
                            HttpRequestResponse dyinHttpRequestResponse = callMyRequest(dyinHttpRequest, 2);
                            String dyinPocResponseBody = new String(dyinHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, dyinPocResponseBody,"","",html_flag);
                            if (Collections.min(secondDoubleList) <= 0.9) {
                                String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "''", secondSimimarity, "stringsql", String.valueOf(dyinHttpRequestResponse.response().bodyToString().length()), String.valueOf(dyinHttpRequestResponse.response().statusCode()), String.format("%.3f", (dyinHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpRequestResponse, requestSm3Hash));
                            } else {
                                continue stringloop;
                            }
                        }

                        for (int i = 0; i < 1; i++) {
                            //"'+'"
                            String dyinBody3 = prefix + "'+'" + suffix;
                            HttpRequest dyinHttpRequest3 = sourceHttpRequest.withBody(dyinBody3);
                            HttpRequestResponse dyinHttpRequestResponse3 = callMyRequest(dyinHttpRequest3, 2);
                            String dyinPocResponseBody3 = new String(dyinHttpRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> secondDoubleList3 = MyCompare.averageLevenshtein(sourceBody, dyinPocResponseBody3,"","'+'",html_flag);
                            if (Collections.max(secondDoubleList3) > 0.9) {
                                String secondSimimarity3 = MyCompare.formatPercent(Collections.max(secondDoubleList3));
                                pocLogEntries.add(new PocLogEntry(paramName, "'+'", secondSimimarity3, "stringsql", String.valueOf(dyinHttpRequestResponse3.response().bodyToString().length()), String.valueOf(dyinHttpRequestResponse3.response().statusCode()), String.format("%.3f", (dyinHttpRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpRequestResponse3, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                string_flag = true;
                                continue stringloop;
                            }
                        }

                        for (int i = 0; i < 1; i++) {
                            //"'||'"
                            String dyinBody4 = prefix + "'||'" + suffix;
                            HttpRequest dyinHttpRequest4 = sourceHttpRequest.withBody(dyinBody4);
                            HttpRequestResponse dyinHttpRequestResponse4 = callMyRequest(dyinHttpRequest4, 2);
                            String dyinPocResponseBody4 = new String(dyinHttpRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> secondDoubleList4 = MyCompare.averageLevenshtein(sourceBody, dyinPocResponseBody4,"","'||'",html_flag);
                            if (Collections.max(secondDoubleList4) > 0.9) {
                                String lastSimimarity = MyCompare.formatPercent(Collections.max(secondDoubleList4));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||'", lastSimimarity, "stringsql", String.valueOf(dyinHttpRequestResponse4.response().bodyToString().length()), String.valueOf(dyinHttpRequestResponse4.response().statusCode()), String.format("%.3f", (dyinHttpRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpRequestResponse4, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                string_flag = true;
                            }
                        }


                    }
                }
                if (DetSql.orderChexk.isSelected()){
                    //order
                    orderloop:
                    for (ParsedHttpParameter parameter : parameters) {
                        int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();

                        if (valueStart != valueEnd) {

                            String paramName = parameter.name();
                            if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                                continue;
                            }
                            String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                            String suffix = sourceRequestIndex.substring(valueEnd);
                            List<PocLogEntry> pocLogEntries = new ArrayList<>();
                            String pocResponseBody = "";
                            for (int i = 0; i < 1; i++) {
                                //",0"
                                String pocBody = prefix + ",0" + suffix;
                                HttpRequest pocHttpRequest = sourceHttpRequest.withBody(pocBody);
                                HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                                pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList = MyCompare.averageJaccard(sourceBody, pocResponseBody,"","",html_flag);
                                if (Collections.min(oneDoubleList) <= 0.9) {
                                    String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, ",0", mySimimarity, "ordersql", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash));
                                } else {
                                    continue orderloop;
                                }
                            }
                            String pocResponseBody1 = "";
                            for (int i = 0; i < 1; i++) {
                                //",XXXXXX"
                                String pocBody1 = prefix + ",XXXXXX" + suffix;
                                HttpRequest pocHttpRequest1 = sourceHttpRequest.withBody(pocBody1);
                                HttpRequestResponse pocHttpRequestResponse1 = callMyRequest(pocHttpRequest1, 2);
                                pocResponseBody1 = new String(pocHttpRequestResponse1.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> oneDoubleList1 = MyCompare.averageJaccard(sourceBody, pocResponseBody1,"","",html_flag);
                                if (Collections.min(oneDoubleList1) <= 0.9) {
                                    String mySimimarity1 = MyCompare.formatPercent(Collections.min(oneDoubleList1));
                                    pocLogEntries.add(new PocLogEntry(paramName, ",XXXXXX", mySimimarity1, "ordersql", String.valueOf(pocHttpRequestResponse1.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse1.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse1.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse1, requestSm3Hash));
                                } else {
                                    continue orderloop;
                                }
                            }

                            List<Double> oneDoubleList2 = MyCompare.averageJaccard(pocResponseBody, pocResponseBody1,"","",html_flag);
                            if (Collections.max(oneDoubleList2) > 0.9) {
                                for (int i = 0; i < 1; i++) {
                                    // ",1", ",2",
                                    String pocBody2 = prefix + ",1" + suffix;
                                    HttpRequest pocHttpRequest2 = sourceHttpRequest.withBody(pocBody2);
                                    HttpRequestResponse pocHttpRequestResponse2 = callMyRequest(pocHttpRequest2, 2);
                                    String pocResponseBody2 = new String(pocHttpRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                                    List<Double> oneDoubleList3 = MyCompare.averageJaccard(sourceBody, pocResponseBody2,"",",1",html_flag);
                                    if (Collections.max(oneDoubleList3) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, pocResponseBody2,"","",html_flag)) <= 0.9) {
                                        String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                                        pocLogEntries.add(new PocLogEntry(paramName, ",1", mySimimarity, "ordersql", String.valueOf(pocHttpRequestResponse2.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse2.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse2, requestSm3Hash));
                                        getAttackList.addAll(pocLogEntries);
                                        order_flag = true;
                                        continue orderloop;
                                    }

                                }
                                for (int i = 0; i < 1; i++) {
                                    String pocBody3 = prefix + ",2" + suffix;
                                    HttpRequest pocHttpRequest3 = sourceHttpRequest.withBody(pocBody3);
                                    HttpRequestResponse pocHttpRequestResponse3 = callMyRequest(pocHttpRequest3, 2);
                                    String pocResponseBody3 = new String(pocHttpRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                                    List<Double> oneDoubleList4 = MyCompare.averageJaccard(sourceBody, pocResponseBody3,"",",2",html_flag);
                                    if (Collections.max(oneDoubleList4) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, pocResponseBody3,"","",html_flag)) <= 0.9) {
                                        String mySimimarityx = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                                        pocLogEntries.add(new PocLogEntry(paramName, ",2", mySimimarityx, "ordersql", String.valueOf(pocHttpRequestResponse3.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse3.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse3, requestSm3Hash));
                                        getAttackList.addAll(pocLogEntries);
                                        order_flag = true;
                                    }
                                }
                            }

                        }

                    }
                }
                //bool
                if (DetSql.boolChexk.isSelected()){
                    boolLoop:
                    for (ParsedHttpParameter parameter : parameters){
                        //int valueStart = parameter.valueOffsets().startIndexInclusive();
                        int valueEnd = parameter.valueOffsets().endIndexExclusive();
                        String paramName = parameter.name();
                        if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                            continue;
                        }
                        //String paramValue = parameter.value();
                        String prefix = sourceRequestIndex.substring(bodyStartIndex, valueEnd);
                        String suffix = sourceRequestIndex.substring(valueEnd);
                        List<PocLogEntry> pocLogEntries = new ArrayList<>();
                        String firstPocResponseBody = "";
                        for (int j = 0; j < 1; j++) {
                            //'||EXP(710)||'
                            String yinPocbody = prefix+"'||EXP(710)||'"+suffix;
                            HttpRequest yinPocHttpRequest = sourceHttpRequest.withBody(yinPocbody);
                            HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                            firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                            if (Collections.min(firstDoubleList) <= 0.9) {
                                String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(710)||'", firstSimimarity, "boolsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                            } else {
                                continue boolLoop;
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            //'||EXP(290)||'
                            String minPocbody = prefix+"'||EXP(290)||'"+suffix;
                            HttpRequest minPocHttpRequest = sourceHttpRequest.withBody(minPocbody);
                            HttpRequestResponse minHttpSendRequestResponse = callMyRequest(minPocHttpRequest, 2);
                            String minPocResponseBody = new String(minHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, minPocResponseBody,"","",html_flag);
                            if (Collections.min(secondDoubleList) <= 0.9) {
                                String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(290)||'", secondSimimarity, "boolsql", String.valueOf(minHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(minHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (minHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), minHttpSendRequestResponse, requestSm3Hash));
                                firstPocResponseBody=minPocResponseBody;
                            } else{
                                String addPocbody=prefix+"'||1/0||'"+suffix;
                                HttpRequest addPocHttpRequest = sourceHttpRequest.withBody(addPocbody);
                                HttpRequestResponse addHttpSendRequestResponse = callMyRequest(addPocHttpRequest, 2);
                                String addPocResponseBody = new String(addHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                                List<Double> addDoubleList = MyCompare.averageLevenshtein(sourceBody, addPocResponseBody,"","'||1/0||'",html_flag);
                                if (Collections.max(addDoubleList) > 0.9) {
                                    String addSimimarity = MyCompare.formatPercent(Collections.max(addDoubleList));
                                    pocLogEntries.add(new PocLogEntry(paramName, "'||1/0||'", addSimimarity, "boolsql", String.valueOf(addHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(addHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (addHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), addHttpSendRequestResponse, requestSm3Hash));
                                    firstPocResponseBody=minPocResponseBody;
                                }else{
                                    continue boolLoop;
                                }
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            //"'||1%2F1||'"
                            String poc3Httpbody=prefix+"'||1/1||'"+suffix;
                            HttpRequest poc3HttpRequest = sourceHttpRequest.withBody(poc3Httpbody);
                            HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                            String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(firstPocResponseBody, poc3ResponseBody,"EXP\\(290\\)","1/1",html_flag);
                            if (Collections.max(oneDoubleList3) > 0.9) {
                                String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||1/1||'", lastSimimarity, "boolsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                bool_flag = true;
                            }
                        }
                    }
                }


            }
        }//POST 处理结束
        //处理cookie
        if (DetSql.cookieChexk.isSelected() && !httpRequestResponse.request().parameters(HttpParameterType.COOKIE).isEmpty()) {
            List<ParsedHttpParameter> parameters = httpRequestResponse.request().parameters(HttpParameterType.COOKIE);
            ArrayList<HttpParameter> newHttpParameters = new ArrayList<>();
            for (ParsedHttpParameter parameter : parameters) {
                newHttpParameters.add(HttpParameter.cookieParameter(parameter.name(), parameter.value()));
            }
            if (DetSql.errorChexk.isSelected()){
                //err
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    for (String poc : errPocs) {
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + poc));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                        String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        String resBool = ErrSqlCheck(pocResponseBody);
                        if (resBool != null) {
                            PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "errsql(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                            getAttackList.add(logEntry);
                            err_flag = true;
                        }
                    }
                }
            }
            //diy
            if (DetSql.diyChexk.isSelected()&&!diyPayloads.isEmpty()&&(!DetSql.timeTextField.getText().isEmpty()||!diyRegexs.isEmpty())){
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    for (String poc : diyPayloads) {
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + poc));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse pocHttpRequestResponse = callMyRequest(pocHttpRequest, 2);
                        String pocResponseBody = new String(pocHttpRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        if(!diyRegexs.isEmpty()){
                            String resBool = diyRegexCheck(pocResponseBody);
                            if (resBool != null) {
                                PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "diypoc(" + resBool + ")", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                                getAttackList.add(logEntry);
                                diy_flag = true;
                            }
                        }
                        if(!DetSql.timeTextField.getText().isEmpty()&&pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()>intTime){
                            PocLogEntry logEntry = new PocLogEntry(paramName, poc, null, "diypoc(time)", String.valueOf(pocHttpRequestResponse.response().bodyToString().length()), String.valueOf(pocHttpRequestResponse.response().statusCode()), String.format("%.3f", (pocHttpRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), pocHttpRequestResponse, requestSm3Hash);
                            getAttackList.add(logEntry);
                            diy_flag = true;
                        }
                    }
                }
            }
            if (DetSql.stringChexk.isSelected()) {
                //string
                stringloop:
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String firstPocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //单引号
                        List<HttpParameter> yinPocHttpParameters = new ArrayList<>(newHttpParameters);
                        yinPocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'"));
                        HttpRequest yinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(yinPocHttpParameters);
                        HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                        firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                        if (Collections.min(firstDoubleList) <= 0.9) {
                            String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "'", firstSimimarity, "stringsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue stringloop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //两个单引号
                        List<HttpParameter> dyinPocHttpParameters = new ArrayList<>(newHttpParameters);
                        dyinPocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "''"));
                        HttpRequest dyinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(dyinPocHttpParameters);
                        HttpRequestResponse dyinHttpSendRequestResponse = callMyRequest(dyinPocHttpRequest, 2);
                        String dyinPocResponseBody = new String(dyinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, dyinPocResponseBody,"","",html_flag);
                        if (Collections.min(secondDoubleList) <= 0.9) {
                            String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "''", secondSimimarity, "stringsql", String.valueOf(dyinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(dyinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (dyinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), dyinHttpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue stringloop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //"'+'"
                        List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                        poc3HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'+'"));
                        HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                        HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                        String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(sourceBody, poc3ResponseBody,"","'+'",html_flag);
                        if (Collections.max(oneDoubleList3) > 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                            pocLogEntries.add(new PocLogEntry(paramName, "'+'", mySimimarity, "stringsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                            getAttackList.addAll(pocLogEntries);
                            string_flag = true;
                            continue stringloop;
                        }
                    }

                    for (int j = 0; j < 1; j++) {
                        //"'||'"
                        List<HttpParameter> poc4HttpParameters = new ArrayList<>(newHttpParameters);
                        poc4HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'||'"));
                        HttpRequest poc4HttpRequest = sourceHttpRequest.withUpdatedParameters(poc4HttpParameters);
                        HttpRequestResponse httpSendRequestResponse4 = callMyRequest(poc4HttpRequest, 2);
                        String poc4ResponseBody = new String(httpSendRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList4 = MyCompare.averageLevenshtein(sourceBody, poc4ResponseBody,"","'||'",html_flag);
                        if (Collections.max(oneDoubleList4) > 0.9) {
                            String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||'", lastSimimarity, "stringsql", String.valueOf(httpSendRequestResponse4.response().bodyToString().length()), String.valueOf(httpSendRequestResponse4.response().statusCode()), String.format("%.3f", (httpSendRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse4, requestSm3Hash));
                            getAttackList.addAll(pocLogEntries);
                            string_flag = true;
                        }
                    }
                }
            }
            if (DetSql.numChexk.isSelected()){
                //数字
                outerloop:
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    try {
                        int parseInt = Integer.parseInt(paramValue);
                    } catch (NumberFormatException e) {
                        continue;
                    }
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String pocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //"-0-0-0"
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "-0-0-0"));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse httpSendRequestResponse = callMyRequest(pocHttpRequest, 2);
                        pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList = MyCompare.averageLevenshtein(sourceBody, pocResponseBody,"","-0-0-0",html_flag);
                        if (Collections.max(oneDoubleList) > 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "-0-0-0", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue outerloop;
                        }
                    }
                    String poc2ResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //"-abc"
                        List<HttpParameter> poc2HttpParameters = new ArrayList<>(newHttpParameters);
                        poc2HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "-abc"));
                        HttpRequest poc2HttpRequest = sourceHttpRequest.withUpdatedParameters(poc2HttpParameters);
                        HttpRequestResponse httpSendRequestResponse2 = callMyRequest(poc2HttpRequest, 2);
                        poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList2 = MyCompare.averageLevenshtein(sourceBody, poc2ResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList2) <= 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));
                            pocLogEntries.add(new PocLogEntry(paramName, "-abc", mySimimarity, "numsql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                        } else {
                            continue outerloop;
                        }
                    }

                    List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(pocResponseBody, poc2ResponseBody,"","",html_flag);
                    if (Collections.min(oneDoubleList3) <= 0.9) {
                        getAttackList.addAll(pocLogEntries);
                        num_flag = true;
                    }
                }
            }
            if (DetSql.orderChexk.isSelected()){
                //order
                orderloop:
                for (int i = 0; i < newHttpParameters.size(); i++) {
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    if (paramValue.isBlank()) {
                        continue;
                    }
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String pocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //",0"
                        List<HttpParameter> pocHttpParameters = new ArrayList<>(newHttpParameters);
                        pocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + ",0"));
                        HttpRequest pocHttpRequest = sourceHttpRequest.withUpdatedParameters(pocHttpParameters);
                        HttpRequestResponse httpSendRequestResponse = callMyRequest(pocHttpRequest, 2);
                        pocResponseBody = new String(httpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList = MyCompare.averageJaccard(sourceBody, pocResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList) <= 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, ",0", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse.response().bodyToString().length()), String.valueOf(httpSendRequestResponse.response().statusCode()), String.format("%.3f", (httpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue orderloop;
                        }
                    }
                    String poc2ResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //",XXXXXX"
                        List<HttpParameter> poc2HttpParameters = new ArrayList<>(newHttpParameters);
                        poc2HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + ",XXXXXX"));
                        HttpRequest poc2HttpRequest = sourceHttpRequest.withUpdatedParameters(poc2HttpParameters);
                        HttpRequestResponse httpSendRequestResponse2 = callMyRequest(poc2HttpRequest, 2);
                        poc2ResponseBody = new String(httpSendRequestResponse2.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList2 = MyCompare.averageJaccard(sourceBody, poc2ResponseBody,"","",html_flag);
                        if (Collections.min(oneDoubleList2) <= 0.9) {
                            String mySimimarity = MyCompare.formatPercent(Collections.min(oneDoubleList2));
                            pocLogEntries.add(new PocLogEntry(paramName, ",XXXXXX", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse2.response().bodyToString().length()), String.valueOf(httpSendRequestResponse2.response().statusCode()), String.format("%.3f", (httpSendRequestResponse2.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse2, requestSm3Hash));
                        } else {
                            continue orderloop;
                        }
                    }
                    List<Double> oneDoubleList3 = MyCompare.averageJaccard(pocResponseBody, poc2ResponseBody,"","",html_flag);
                    if (Collections.max(oneDoubleList3) > 0.9) {
                        for (int j = 0; j < 1; j++) {
                            // ",1", ",2",
                            List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                            poc3HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + ",1"));
                            HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                            HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                            String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList4 = MyCompare.averageJaccard(sourceBody, poc3ResponseBody,"",",1",html_flag);
                            if (Collections.max(oneDoubleList4) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, poc3ResponseBody,"","",html_flag)) <= 0.9) {
                                String mySimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList4));
                                pocLogEntries.add(new PocLogEntry(paramName, ",1", mySimimarity, "ordersql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                order_flag = true;
                                continue orderloop;
                            }
                        }
                        for (int j = 0; j < 1; j++) {
                            List<HttpParameter> poc4HttpParameters = new ArrayList<>(newHttpParameters);
                            poc4HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + ",2"));
                            HttpRequest poc4HttpRequest = sourceHttpRequest.withUpdatedParameters(poc4HttpParameters);
                            HttpRequestResponse httpSendRequestResponse4 = callMyRequest(poc4HttpRequest, 2);
                            String poc4ResponseBody = new String(httpSendRequestResponse4.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> oneDoubleList5 = MyCompare.averageJaccard(sourceBody, poc4ResponseBody,"",",2",html_flag);
                            if (Collections.max(oneDoubleList5) > 0.9 && Collections.min(MyCompare.averageJaccard(pocResponseBody, poc4ResponseBody,"","",html_flag)) <= 0.9) {
                                String mySimimarityx = MyCompare.formatPercent(Collections.max(oneDoubleList5));
                                pocLogEntries.add(new PocLogEntry(paramName, ",2", mySimimarityx, "ordersql", String.valueOf(httpSendRequestResponse4.response().bodyToString().length()), String.valueOf(httpSendRequestResponse4.response().statusCode()), String.format("%.3f", (httpSendRequestResponse4.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse4, requestSm3Hash));
                                getAttackList.addAll(pocLogEntries);
                                order_flag = true;
                            }
                        }
                    }

                }
            }
            //bool
            if (DetSql.boolChexk.isSelected()){
                boolLoop:
                for (int i = 0; i < newHttpParameters.size(); i++){
                    String paramName = newHttpParameters.get(i).name();
                    if(!blackParamsSet.isEmpty()&&blackParamsSet.contains(paramName)){
                        continue;
                    }
                    String paramValue = newHttpParameters.get(i).value();
                    List<PocLogEntry> pocLogEntries = new ArrayList<>();
                    String firstPocResponseBody = "";
                    for (int j = 0; j < 1; j++) {
                        //'||EXP(710)||'
                        List<HttpParameter> yinPocHttpParameters = new ArrayList<>(newHttpParameters);
                        yinPocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'||EXP(710)||'"));
                        HttpRequest yinPocHttpRequest = sourceHttpRequest.withUpdatedParameters(yinPocHttpParameters);
                        HttpRequestResponse yinHttpSendRequestResponse = callMyRequest(yinPocHttpRequest, 2);
                        firstPocResponseBody = new String(yinHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> firstDoubleList = MyCompare.averageLevenshtein(sourceBody, firstPocResponseBody,"","",html_flag);
                        if (Collections.min(firstDoubleList) <= 0.9) {
                            String firstSimimarity = MyCompare.formatPercent(Collections.min(firstDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(710)||'", firstSimimarity, "boolsql", String.valueOf(yinHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(yinHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (yinHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), yinHttpSendRequestResponse, requestSm3Hash));
                        } else {
                            continue boolLoop;
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //'||EXP(290)||'
                        List<HttpParameter> minPocHttpParameters = new ArrayList<>(newHttpParameters);
                        minPocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'||EXP(290)||'"));
                        HttpRequest minPocHttpRequest = sourceHttpRequest.withUpdatedParameters(minPocHttpParameters);
                        HttpRequestResponse minHttpSendRequestResponse = callMyRequest(minPocHttpRequest, 2);
                        String minPocResponseBody = new String(minHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> secondDoubleList = MyCompare.averageLevenshtein(firstPocResponseBody, minPocResponseBody,"","",html_flag);
                        if (Collections.min(secondDoubleList) <= 0.9) {
                            String secondSimimarity = MyCompare.formatPercent(Collections.min(secondDoubleList));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||EXP(290)||'", secondSimimarity, "boolsql", String.valueOf(minHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(minHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (minHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), minHttpSendRequestResponse, requestSm3Hash));
                            firstPocResponseBody=minPocResponseBody;
                        } else{
                            List<HttpParameter> addPocHttpParameters = new ArrayList<>(newHttpParameters);
                            addPocHttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'||1/0||'"));
                            HttpRequest addPocHttpRequest = sourceHttpRequest.withUpdatedParameters(addPocHttpParameters);
                            HttpRequestResponse addHttpSendRequestResponse = callMyRequest(addPocHttpRequest, 2);
                            String addPocResponseBody = new String(addHttpSendRequestResponse.response().body().getBytes(), StandardCharsets.UTF_8);
                            List<Double> addDoubleList = MyCompare.averageLevenshtein(sourceBody, addPocResponseBody,"","'||1/0||'",html_flag);
                            if (Collections.max(addDoubleList) > 0.9) {
                                String addSimimarity = MyCompare.formatPercent(Collections.max(addDoubleList));
                                pocLogEntries.add(new PocLogEntry(paramName, "'||1/0||'", addSimimarity, "boolsql", String.valueOf(addHttpSendRequestResponse.response().bodyToString().length()), String.valueOf(addHttpSendRequestResponse.response().statusCode()), String.format("%.3f", (addHttpSendRequestResponse.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), addHttpSendRequestResponse, requestSm3Hash));
                                firstPocResponseBody=minPocResponseBody;
                            }else{
                                continue boolLoop;
                            }
                        }
                    }
                    for (int j = 0; j < 1; j++) {
                        //"'||1%2F1||'"
                        List<HttpParameter> poc3HttpParameters = new ArrayList<>(newHttpParameters);
                        poc3HttpParameters.set(i, HttpParameter.cookieParameter(paramName, paramValue + "'||1/1||'"));
                        HttpRequest poc3HttpRequest = sourceHttpRequest.withUpdatedParameters(poc3HttpParameters);
                        HttpRequestResponse httpSendRequestResponse3 = callMyRequest(poc3HttpRequest, 2);
                        String poc3ResponseBody = new String(httpSendRequestResponse3.response().body().getBytes(), StandardCharsets.UTF_8);
                        List<Double> oneDoubleList3 = MyCompare.averageLevenshtein(firstPocResponseBody, poc3ResponseBody,"EXP\\(290\\)","1/1",html_flag);
                        if (Collections.max(oneDoubleList3) > 0.9) {
                            String lastSimimarity = MyCompare.formatPercent(Collections.max(oneDoubleList3));
                            pocLogEntries.add(new PocLogEntry(paramName, "'||1/1||'", lastSimimarity, "boolsql", String.valueOf(httpSendRequestResponse3.response().bodyToString().length()), String.valueOf(httpSendRequestResponse3.response().statusCode()), String.format("%.3f", (httpSendRequestResponse3.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis()) / 1000.0), httpSendRequestResponse3, requestSm3Hash));
                            getAttackList.addAll(pocLogEntries);
                            bool_flag = true;
                        }
                    }
                }
            }
        }
        StringBuilder sb = new StringBuilder();
        if (err_flag) {
            sb.append("-errsql");
        }
        if (string_flag) {
            sb.append("-stringsql");
        }
        if (num_flag) {
            sb.append("-numsql");
        }
        if (order_flag) {
            sb.append("-ordersql");
        }
        if (bool_flag) {
            sb.append("-boolsql");
        }
        if (diy_flag) {
            sb.append("-diypoc");
        }
        return sb.toString();
    }

    public static String ErrSqlCheck(String text) {
        String cleanedText = text.replaceAll("\\n|\\r|\\r\\n", "");
        for (String rule : rules) {
            Pattern pattern = Pattern.compile(rule, Pattern.CASE_INSENSITIVE);
            if (pattern.matcher(cleanedText).find()) {
                return rule;
            }
        }
        return null;
    }
    public static String diyRegexCheck(String text) {
        String cleanedText = text.replaceAll("\\n|\\r|\\r\\n", "");
        for (String rule : diyRegexs) {
            Pattern pattern = Pattern.compile(rule, Pattern.CASE_INSENSITIVE);
            if (pattern.matcher(cleanedText).find()) {
                return rule;
            }
        }
        return null;
    }
    public static String byteToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public HttpRequestResponse callMyRequest(HttpRequest pocHttpRequest, int retryCount) throws InterruptedException {
        HttpRequestResponse resHttpRequestResponse;
        try {
            resHttpRequestResponse = api.http().sendRequest(pocHttpRequest).copyToTempFile();
            Thread.sleep(Math.max(staticTime, 100));
            if (resHttpRequestResponse.response().body() != null && resHttpRequestResponse.response().body().length() >= 0) {
                return resHttpRequestResponse;
            }
        } catch (InterruptedException e) {
            throw new InterruptedException();
        } catch (Exception e) {
            HttpResponse aHttpResponse = HttpResponse.httpResponse();
            HttpResponse emptyHttpResponse = aHttpResponse.withBody("");
            resHttpRequestResponse = HttpRequestResponse.httpRequestResponse(pocHttpRequest, emptyHttpResponse);
        }
        if (retryCount <= 0) {
            return resHttpRequestResponse;
        }
        Thread.sleep(ThreadLocalRandom.current().nextInt(startTime, endTime + 1));
        return callMyRequest(pocHttpRequest, retryCount - 1);
    }

    public void createProcessThread(HttpRequestResponse httpRequestResponse) {
        new Thread() {
            @Override
            public void run() {
                try {
                    if (httpRequestResponse.response().bodyToString().length() != 0 && httpRequestResponse.response().bodyToString().length() < 10000) {
                        String requestSm3Hash = String.valueOf(System.currentTimeMillis());
                        Thread.currentThread().setName(requestSm3Hash);
                        int oneLogSize = 0;
                        lk.lock();
                        try {
                            oneLogSize = countId;
                            sourceTableModel.add(new SourceLogEntry(oneLogSize, "Send", requestSm3Hash, "run", httpRequestResponse.response().bodyToString().length(), HttpRequestResponse.httpRequestResponse(httpRequestResponse.request(), HttpResponse.httpResponse()), httpRequestResponse.request().httpService().toString(), httpRequestResponse.request().method(), httpRequestResponse.request().pathWithoutQuery()));
                        } catch (Exception e) {
                            e.printStackTrace();
                        } finally {
                            lk.unlock();
                            attackMap.put(requestSm3Hash, new ArrayList<>());
                            countId += 1;
                        }
                        try {
                            String oneVuln = "";
                            semaphore.acquire();
                            try {
                                if (!Thread.currentThread().isInterrupted()) {
                                    oneVuln = processOneRequest2(requestSm3Hash, httpRequestResponse);
                                }

                            } catch (Exception e) {
                                e.printStackTrace();
                            } finally {
                                semaphore.release();
                                if (oneVuln.isBlank()) {
                                    //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                    sourceTableModel.add2(new SourceLogEntry(oneLogSize, "Send", requestSm3Hash, "", httpRequestResponse.response().bodyToString().length(), null, httpRequestResponse.request().httpService().toString(), httpRequestResponse.request().method(), httpRequestResponse.request().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                                } else {
                                    //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                    sourceTableModel.add2(new SourceLogEntry(oneLogSize, "Send", requestSm3Hash, oneVuln, httpRequestResponse.response().bodyToString().length(), httpRequestResponse, httpRequestResponse.request().httpService().toString(), httpRequestResponse.request().method(), httpRequestResponse.request().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                                }

                            }
                        } catch (InterruptedException e) {
                            //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                            sourceTableModel.add2(new SourceLogEntry(oneLogSize, "Send", requestSm3Hash, "手动停止", httpRequestResponse.response().bodyToString().length(), null, httpRequestResponse.request().httpService().toString(), httpRequestResponse.request().method(), httpRequestResponse.request().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else if (httpRequestResponse.response().bodyToString().length() != 0 && httpRequestResponse.response().bodyToString().length() < 80000) {
                        String requestSm3Hash = String.valueOf(System.currentTimeMillis());
                        Thread.currentThread().setName(requestSm3Hash);
                        int oneLogSize = 0;
                        lk.lock();
                        try {
                            oneLogSize = countId;
                            sourceTableModel.add(new SourceLogEntry(oneLogSize, "Send", requestSm3Hash, "run", httpRequestResponse.response().bodyToString().length(), HttpRequestResponse.httpRequestResponse(httpRequestResponse.request(), HttpResponse.httpResponse()), httpRequestResponse.request().httpService().toString(), httpRequestResponse.request().method(), httpRequestResponse.request().pathWithoutQuery()));
                        } catch (Exception e) {
                            e.printStackTrace();
                        } finally {
                            lk.unlock();
                            attackMap.put(requestSm3Hash, new ArrayList<>());
                            countId += 1;
                        }

                        try {
                            String oneVuln = "";
                            semaphore2.acquire();
                            try {
                                if (!Thread.currentThread().isInterrupted()) {
                                    oneVuln = processOneRequest2(requestSm3Hash, httpRequestResponse);
                                }

                            } catch (Exception e) {
                                e.printStackTrace();
                            } finally {
                                semaphore2.release();
                                if (oneVuln.isBlank()) {
                                    //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                    sourceTableModel.add2(new SourceLogEntry(oneLogSize, "Send", requestSm3Hash, "", httpRequestResponse.response().bodyToString().length(), null, httpRequestResponse.request().httpService().toString(), httpRequestResponse.request().method(), httpRequestResponse.request().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                                } else {
                                    //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                                    sourceTableModel.add2(new SourceLogEntry(oneLogSize, "Send", requestSm3Hash, oneVuln, httpRequestResponse.response().bodyToString().length(), httpRequestResponse, httpRequestResponse.request().httpService().toString(), httpRequestResponse.request().method(), httpRequestResponse.request().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                                }

                            }
                        } catch (InterruptedException e) {
                            //api.logging().logToOutput("oneLogSize:"+oneLogSize+";viewindex:"+DetSql.table1.convertRowIndexToView(oneLogSize)+";modelindex:"+DetSql.table1.convertRowIndexToModel(oneLogSize)+";logindex:"+sourceTableModel.getValueAt(oneLogSize,0));
                            sourceTableModel.add2(new SourceLogEntry(oneLogSize, "Send", requestSm3Hash, "手动停止", httpRequestResponse.response().bodyToString().length(), null, httpRequestResponse.request().httpService().toString(), httpRequestResponse.request().method(), httpRequestResponse.request().pathWithoutQuery()), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)), sourceTableModel.log.indexOf(new SourceLogEntry(oneLogSize, null, null, null, 0, null, null, null, null)));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }.start();
    }
}
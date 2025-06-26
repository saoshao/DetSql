/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class MyFilterRequest {
    public static Set<String> whiteListSet = new HashSet<>();

    public static Set<String> blackListSet = new HashSet<>();
    public static Set<String> blackPathSet=new HashSet<>();

    public static Set<String> unLegalExtensionSet = new HashSet<>(Arrays.asList("wma", "csv", "mov", "doc", "3g2", "mp4", "7z", "3gp", "xbm", "jar", "avi", "ogv", "mpv2", "tiff", "pnm", "jpg", "xpm", "xul", "epub", "au", "aac", "midi", "weba", "tar", "js", "rtf", "bin", "woff", "wmv", "tif", "css", "gif", "flv", "ttf", "html", "eot", "ods", "odt", "webm", "mpg", "mjs", "bz", "ics", "ras", "aifc", "mpa", "ppt", "mpeg", "pptx", "oga", "ra", "aiff", "asf", "woff2", "snd", "xwd", "csh", "webp", "xlsx", "mpkg", "vsd", "mid", "wav", "svg", "mp3", "bz2", "ico", "jpe", "pbm", "gz", "pdf", "log", "jpeg", "rmi", "txt", "arc", "rm", "ppm", "cod", "jfif", "ram", "docx", "mpe", "odp", "otf", "pgm", "cmx", "m3u", "mp2", "cab", "rar", "bmp", "rgb", "png", "azw", "ogx", "aif", "zip", "ief", "htm", "xls", "mpp", "swf", "rmvb", "abw"));


    //过滤一，来源为Proxy,Repeater
    public static boolean fromProxySource(HttpResponseReceived httpResponseReceived) {

        return httpResponseReceived.toolSource().isFromTool(ToolType.PROXY);
    }

    public static boolean fromRepeaterSource(HttpResponseReceived httpResponseReceived) {

        return httpResponseReceived.toolSource().isFromTool(ToolType.REPEATER);
    }

    //过滤二，保留白名单域名
    public static boolean useWhiteList(HttpResponseReceived httpResponseReceived) {
        if (whiteListSet.isEmpty()) {
            return true;
        }
        String host = httpResponseReceived.initiatingRequest().httpService().host();
        for (String s : whiteListSet) {
            if (host.toLowerCase().endsWith(s.trim())) {
                return true;
            }
        }
        return false;
    }


    //过滤三，删除黑名单域名
    public static boolean useBlackList(HttpResponseReceived httpResponseReceived) {
        if (blackListSet.isEmpty()) {
            return true;
        }
        String host = httpResponseReceived.initiatingRequest().httpService().host();
        for (String s : blackListSet) {
            if (host.toLowerCase().endsWith(s.trim())) {
                return false;
            }
        }
        return true;
    }

    //过滤四，保留GET,POST请求+PUT请求
    public static boolean isGetPost(HttpResponseReceived httpResponseReceived) {
        return httpResponseReceived.initiatingRequest().method().equals("GET") || httpResponseReceived.initiatingRequest().method().equals("POST")||httpResponseReceived.initiatingRequest().method().equals("PUT");
    }


    //过滤五，去除非法后缀
    public static boolean useUnLegalExtension(HttpResponseReceived httpResponseReceived) {
        if (unLegalExtensionSet.isEmpty()) {
            return true;
        }
        String fileExtension = httpResponseReceived.initiatingRequest().fileExtension().toLowerCase();
        return !unLegalExtensionSet.contains(fileExtension);
    }

    //过滤六，GET或POST参数不能为空+PUT

    public static boolean paramNotEmpty(HttpResponseReceived httpResponseReceived) {
        if (httpResponseReceived.initiatingRequest().method().equals("GET")) {
            return !httpResponseReceived.initiatingRequest().parameters(HttpParameterType.URL).isEmpty();
        }
        if (httpResponseReceived.initiatingRequest().method().equals("POST")||httpResponseReceived.initiatingRequest().method().equals("PUT")) {
            return (!httpResponseReceived.initiatingRequest().parameters(HttpParameterType.BODY).isEmpty()) || (!httpResponseReceived.initiatingRequest().parameters(HttpParameterType.JSON).isEmpty()) || (!httpResponseReceived.initiatingRequest().parameters(HttpParameterType.XML).isEmpty());
        }

        return false;
    }
    //过滤七，路径黑名单
    public static boolean pathBlackList(HttpResponseReceived httpResponseReceived) {
        if(blackPathSet.isEmpty()){return true;}
        String path = httpResponseReceived.initiatingRequest().pathWithoutQuery();

        String cleanedText = path.replaceAll("\\n|\\r|\\r\\n", "");

        for (String rule : blackPathSet) {
            Pattern pattern = Pattern.compile(rule, Pattern.CASE_INSENSITIVE);
            if (pattern.matcher(cleanedText).find()) {
                return false;

            }
        }
        return true;
    }

    //包含5个过滤方法的方法
    public static boolean filterOneRequest(HttpResponseReceived httpResponseReceived) {
        //DetSql.api.logging().logToOutput(""+useWhiteList(httpResponseReceived) + useBlackList(httpResponseReceived) + isGetPost(httpResponseReceived) + useUnLegalExtension(httpResponseReceived) + paramNotEmpty(httpResponseReceived)+pathBlackList(httpResponseReceived));
        return useWhiteList(httpResponseReceived) && useBlackList(httpResponseReceived) && isGetPost(httpResponseReceived) && useUnLegalExtension(httpResponseReceived) && paramNotEmpty(httpResponseReceived)&&pathBlackList(httpResponseReceived);
    }


    public static String getUnique(HttpResponseReceived httpResponseReceived) {
        String method = httpResponseReceived.initiatingRequest().method();
        String httpServices = httpResponseReceived.initiatingRequest().httpService().toString();
        String littlePath = httpResponseReceived.initiatingRequest().pathWithoutQuery();
        StringBuilder sb = new StringBuilder();
        if (method.equals("GET")) {
            List<ParsedHttpParameter> urlParameters = httpResponseReceived.initiatingRequest().parameters(HttpParameterType.URL);
            for (ParsedHttpParameter urlParameter : urlParameters) {
                sb.append(urlParameter.name());
            }
        } else if (method.equals("POST")||method.equals("PUT")) {
            List<ParsedHttpParameter> normalParameters = httpResponseReceived.initiatingRequest().parameters(HttpParameterType.BODY);
            List<ParsedHttpParameter> jsonParameters = httpResponseReceived.initiatingRequest().parameters(HttpParameterType.JSON);
            List<ParsedHttpParameter> xmlParameters = httpResponseReceived.initiatingRequest().parameters(HttpParameterType.XML);

            if (!normalParameters.isEmpty()) {
                for (ParsedHttpParameter normalParameter : normalParameters) {
                    sb.append(normalParameter.name());
                }
            } else if (!jsonParameters.isEmpty()) {
                for (ParsedHttpParameter jsonParameter : jsonParameters) {
                    sb.append(jsonParameter.name());
                }
            } else if (!xmlParameters.isEmpty()) {
                for (ParsedHttpParameter xmlParameter : xmlParameters) {
                    sb.append(xmlParameter.name());
                }
            }
        }
        String paramString = sb.toString();

        return method + httpServices + littlePath + paramString;
    }

    public static String getUnique(HttpRequestResponse selectHttpRequestRespons) {
        String method = selectHttpRequestRespons.request().method();
        String httpServices = selectHttpRequestRespons.request().httpService().toString();
        String littlePath = selectHttpRequestRespons.request().pathWithoutQuery();
        StringBuilder sb = new StringBuilder();
        if (method.equals("GET")) {
            List<ParsedHttpParameter> urlParameters = selectHttpRequestRespons.request().parameters(HttpParameterType.URL);
            for (ParsedHttpParameter urlParameter : urlParameters) {
                sb.append(urlParameter.name());
            }
        } else if (method.equals("POST")||method.equals("PUT")) {
            List<ParsedHttpParameter> normalParameters = selectHttpRequestRespons.request().parameters(HttpParameterType.BODY);
            List<ParsedHttpParameter> jsonParameters = selectHttpRequestRespons.request().parameters(HttpParameterType.JSON);
            List<ParsedHttpParameter> xmlParameters = selectHttpRequestRespons.request().parameters(HttpParameterType.XML);
            if (!normalParameters.isEmpty()) {
                for (ParsedHttpParameter normalParameter : normalParameters) {
                    sb.append(normalParameter.name());
                }
            } else if (!jsonParameters.isEmpty()) {
                for (ParsedHttpParameter jsonParameter : jsonParameters) {
                    sb.append(jsonParameter.name());
                }
            } else if (!xmlParameters.isEmpty()) {
                for (ParsedHttpParameter xmlParameter : xmlParameters) {
                    sb.append(xmlParameter.name());
                }
            }
        }
        String paramString = sb.toString();
        return method + httpServices + littlePath + paramString;
    }

}
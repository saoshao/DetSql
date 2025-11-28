package DetSql;

import DetSql.ui.MyFilterRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.HashSet;
import java.util.Arrays;
import java.util.Collections;

public class PathBlacklistTest {

    @BeforeEach
    public void setUp() {
        MyFilterRequest.whiteListSet = new HashSet<>();
        MyFilterRequest.blackListSet = new HashSet<>();
        MyFilterRequest.blackPathSet = new HashSet<>();
        MyFilterRequest.blackParamsSet = new HashSet<>();
        MyFilterRequest.unLegalExtensionSet = new HashSet<>();
    }

    @Test
    public void testPathBlacklistBlocksRequestWithoutParams() {
        // Setup blacklist
        MyFilterRequest.blackPathSet.add("/admin");

        // Mock request
        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        HttpRequest request = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);

        when(requestResponse.request()).thenReturn(request);
        when(request.httpService()).thenReturn(service);
        when(service.host()).thenReturn("example.com");
        when(request.method()).thenReturn("GET");
        when(request.fileExtension()).thenReturn("");
        when(request.pathWithoutQuery()).thenReturn("/admin");

        // Mock parameters (empty)
        when(request.parameters()).thenReturn(Collections.emptyList());
        when(request.bodyToString()).thenReturn("");

        // Test
        boolean result = MyFilterRequest.filterOneRequest(requestResponse);
        assertFalse(result, "Request to /admin should be blocked (return false) even without parameters");
    }

    @Test
    public void testPathBlacklistBlocksRequestWithParams() {
        // Setup blacklist
        MyFilterRequest.blackPathSet.add("/admin");

        // Mock request
        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        HttpRequest request = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        ParsedHttpParameter param = mock(ParsedHttpParameter.class);

        when(requestResponse.request()).thenReturn(request);
        when(request.httpService()).thenReturn(service);
        when(service.host()).thenReturn("example.com");
        when(request.method()).thenReturn("GET");
        when(request.fileExtension()).thenReturn("");
        when(request.pathWithoutQuery()).thenReturn("/admin");

        // Mock parameters (some params)
        when(request.parameters()).thenReturn(Arrays.asList(param));
        when(request.parameters(HttpParameterType.URL)).thenReturn(Arrays.asList(param));
        when(param.name()).thenReturn("id");
        when(request.bodyToString()).thenReturn("id=1");

        // Test
        boolean result = MyFilterRequest.filterOneRequest(requestResponse);
        assertFalse(result, "Request to /admin should be blocked (return false) with parameters");
    }

    @Test
    public void testNormalPathAllowed() {
        // Setup blacklist
        MyFilterRequest.blackPathSet.add("/admin");

        // Mock request
        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        HttpRequest request = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        ParsedHttpParameter param = mock(ParsedHttpParameter.class);

        when(requestResponse.request()).thenReturn(request);
        when(request.httpService()).thenReturn(service);
        when(service.host()).thenReturn("example.com");
        when(request.method()).thenReturn("GET");
        when(request.fileExtension()).thenReturn("");
        when(request.pathWithoutQuery()).thenReturn("/normal");

        // Mock parameters (some params)
        when(request.parameters()).thenReturn(Arrays.asList(param));
        when(request.parameters(HttpParameterType.URL)).thenReturn(Arrays.asList(param));
        when(param.name()).thenReturn("id");
        when(request.bodyToString()).thenReturn("id=1");

        // Test
        boolean result = MyFilterRequest.filterOneRequest(requestResponse);
        assertTrue(result, "Request to /normal should be allowed (return true)");
    }
}

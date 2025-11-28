package DetSql;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.Arrays;
import DetSql.config.DefaultConfig;

public class DefaultConfigJsonErrPocsTest {

    @Test
    void testDefaultJsonErrPocsContainsEscapedDoubleQuote() {
        assertTrue(Arrays.asList(DefaultConfig.DEFAULT_ERR_POCS_JSON).contains("\\\""),
            "Expected escaped double quote in DEFAULT_ERR_POCS_JSON");
    }

    @Test
    void testDefaultJsonErrPocsContainsUnicodeQuotes() {
        var list = Arrays.asList(DefaultConfig.DEFAULT_ERR_POCS_JSON);
        assertTrue(list.contains("\\u0022"), "Expected Unicode double quote \\u0022");
        assertTrue(list.contains("\\u0027"), "Expected Unicode single quote \\u0027");
    }

    @Test
    void testDefaultJsonErrPocsContainsBacktick() {
        assertTrue(Arrays.asList(DefaultConfig.DEFAULT_ERR_POCS_JSON).contains("`"),
            "Expected backtick payload present");
    }
}

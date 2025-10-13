package DetSql;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class MyHttpHandlerErrSqlCheckTest {

    @Test
    void testErrSqlCheckMatchesMySqlSyntaxError() {
        String text = "Random prefix... You have an error in your SQL syntax; check the manual ... suffix";
        String matched = MyHttpHandler.ErrSqlCheck(text);
        assertNotNull(matched, "Expected MySQL syntax error pattern to match");
        assertTrue(matched.toLowerCase().contains("mysql") || matched.toLowerCase().contains("syntax"));
    }

    @Test
    void testErrSqlCheckNoMatch() {
        String text = "Everything is fine. Status OK.";
        String matched = MyHttpHandler.ErrSqlCheck(text);
        assertNull(matched, "Expected no SQL error pattern to match");
    }
}

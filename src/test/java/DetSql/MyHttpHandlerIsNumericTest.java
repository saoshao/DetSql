package DetSql;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class MyHttpHandlerIsNumericTest {

    @Test
    void testNullAndEmpty() {
        assertFalse(MyHttpHandler.isNumericExposed(null));
        assertFalse(MyHttpHandler.isNumericExposed(""));
    }

    @Test
    void testValidNumbers() {
        assertTrue(MyHttpHandler.isNumericExposed("0"));
        assertTrue(MyHttpHandler.isNumericExposed("123"));
        assertTrue(MyHttpHandler.isNumericExposed("-5"));
        assertTrue(MyHttpHandler.isNumericExposed("0012")); // leading zeros allowed by Long.parseLong
    }

    @Test
    void testInvalidNumbers() {
        assertFalse(MyHttpHandler.isNumericExposed("12a"));
        assertFalse(MyHttpHandler.isNumericExposed("a12"));
        assertFalse(MyHttpHandler.isNumericExposed(" 1")); // whitespace not trimmed
        // overflow beyond Long
        assertFalse(MyHttpHandler.isNumericExposed("9223372036854775808"));
    }
}

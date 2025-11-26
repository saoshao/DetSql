package DetSql.util;

import org.junit.jupiter.api.Test;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

public class StringUtilsTest {

    @Test
    public void testParseDelimitedString() {
        // Test pipe delimiter (existing behavior)
        Set<String> result1 = StringUtils.parseDelimitedString("a.com|b.com");
        assertTrue(result1.contains("a.com"));
        assertTrue(result1.contains("b.com"));
        assertEquals(2, result1.size());

        // Test comma delimiter (new requirement)
        Set<String> result2 = StringUtils.parseDelimitedString("a.com,b.com");
        assertTrue(result2.contains("a.com"));
        assertTrue(result2.contains("b.com"));
        assertEquals(2, result2.size());

        // Test mixed delimiters
        Set<String> result3 = StringUtils.parseDelimitedString("a.com|b.com,c.com;d.com\ne.com");
        assertTrue(result3.contains("a.com"));
        assertTrue(result3.contains("b.com"));
        assertTrue(result3.contains("c.com"));
        assertTrue(result3.contains("d.com"));
        assertTrue(result3.contains("e.com"));
        assertEquals(5, result3.size());

        // Test empty and null
        assertTrue(StringUtils.parseDelimitedString(null).isEmpty());
        assertTrue(StringUtils.parseDelimitedString("").isEmpty());
        assertTrue(StringUtils.parseDelimitedString("   ").isEmpty());

        // Test trimming
        Set<String> result4 = StringUtils.parseDelimitedString("  a.com  ,  b.com  ");
        assertTrue(result4.contains("a.com"));
        assertTrue(result4.contains("b.com"));
        assertEquals(2, result4.size());
    }
}

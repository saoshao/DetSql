package DetSql;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;
import DetSql.ui.DetSqlUI;

public class DetSqlDeriveJsonErrPocsTest {

    @Test
    void testDeriveJsonErrPocsVariantsAndDedup() throws Exception {
        Method m = DetSqlUI.class.getDeclaredMethod("deriveJsonErrPocs", String[].class);
        m.setAccessible(true);
        String[] base = new String[] {"\"", "'"};
        String[] derived = (String[]) m.invoke(null, new Object[]{ base });

        var set = new HashSet<>(Arrays.asList(derived));
        // should contain original
        assertTrue(set.contains("\""));
        assertTrue(set.contains("'"));
        // should contain escaped and unicode variants
        assertTrue(set.contains("\\\""));
        assertTrue(set.contains("\\u0022"));
        assertTrue(set.contains("\\u0027"));
        // dedup: size equals distinct count
        assertEquals(set.size(), derived.length);
    }
}

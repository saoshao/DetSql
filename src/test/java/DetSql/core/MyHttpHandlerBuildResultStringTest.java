package DetSql.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import DetSql.core.MyHttpHandler;

public class MyHttpHandlerBuildResultStringTest {

    @Test
    void testAllFalseProducesEmpty() {
        String res = MyHttpHandler.buildResultStringExposed(false,false,false,false,false,false);
        assertEquals("", res);
    }

    @Test
    void testSingleFlags() {
        assertEquals("-errsql", MyHttpHandler.buildResultStringExposed(true,false,false,false,false,false));
        assertEquals("-stringsql", MyHttpHandler.buildResultStringExposed(false,true,false,false,false,false));
        assertEquals("-numsql", MyHttpHandler.buildResultStringExposed(false,false,true,false,false,false));
        assertEquals("-ordersql", MyHttpHandler.buildResultStringExposed(false,false,false,true,false,false));
        assertEquals("-boolsql", MyHttpHandler.buildResultStringExposed(false,false,false,false,true,false));
        assertEquals("-diypoc", MyHttpHandler.buildResultStringExposed(false,false,false,false,false,true));
    }

    @Test
    void testMultipleFlagsOrder() {
        String res = MyHttpHandler.buildResultStringExposed(true,true,true,true,true,true);
        assertEquals("-errsql-stringsql-numsql-ordersql-boolsql-diypoc", res);
    }
}

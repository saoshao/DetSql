package DetSql;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class MyHttpHandlerByteToHexTest {

    @Test
    void testByteToHexLowerValues() {
        byte[] bytes = new byte[] {0x00, 0x0F, 0x10, (byte)0xFF};
        String hex = MyHttpHandler.byteToHex(bytes);
        assertEquals("000F10FF", hex);
    }

    @Test
    void testByteToHexEmpty() {
        byte[] bytes = new byte[] {};
        String hex = MyHttpHandler.byteToHex(bytes);
        assertEquals("", hex);
    }
}

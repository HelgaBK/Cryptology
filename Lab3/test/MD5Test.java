import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class MD5Test {

    @Test
    void computeMD5() {
        String stringToTest = "test";
        byte[] res = MD5.computeMD5(stringToTest.getBytes());
        assertEquals(9, res[0]);
        assertEquals(-113, res[1]);
        assertEquals(-51, res[3]);
    }

    @Test
    void toHexString() {
        String stringToTest = "a";
        byte[] res = MD5.computeMD5(stringToTest.getBytes());
        assertEquals("0CC175B9C0F1B6A831C399E269772661", MD5.toHexString(res));
    }
}
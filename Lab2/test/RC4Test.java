import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RC4Test {

    @Test
    void RPGA() {
        try {
            String key = "strongKey";
            String stringToEncrypt = "test string";

            RC4 rc4 = new RC4(key);
            char[] result = rc4.RPGA(stringToEncrypt.toCharArray());

            assertEquals("»Ad.b+Oa' f", new String(result));
            assertEquals("test string", new String(rc4.RPGA(result)));
        } catch (InvalidKeyException e) {
            System.err.println(e.getMessage());
        }
    }
}
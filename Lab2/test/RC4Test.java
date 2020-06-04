import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class RC4Test {

    @Test
    public void rc4Test(){
        String key = "olha";
        String plainText = "karpyshyn";
        RC4 rc4 = new RC4(key.getBytes());
        byte[] encoded = rc4.encrypt(plainText.getBytes());

        rc4 = new RC4(key.getBytes());
        byte[] decrypted = rc4.decrypt(encoded);
        String result = new String(decrypted);
        assertEquals(plainText,result);
    }
}
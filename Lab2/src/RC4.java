public class RC4 {
    private final byte[] S = new byte[256];
    private final byte[] T = new byte[256];

    public RC4(final byte[] key){
        for(int i = 0; i < 256; i++){
            S[i] = (byte) i;
            T[i] = key[i % key.length];
        }

        byte temp;
        for(int i = 0, j = 0; i < 256; i++){
            j = (j + S[i] + T[i]) & 0xFF;
            temp = S[j];
            S[j] = S[i];
            S[i] = temp;
        }
    }

    public byte[] encrypt(final byte[] plainText){
        final byte[] encrypted = new byte[plainText.length];
        int i = 0, j = 0, x;

        byte temp;
        for(int counter = 0; counter < plainText.length; counter++){
            i = (i+1) & 0xFF;
            j = j + S[i] & 0xFF;
            temp = S[i];
            S[i] = S[j];
            S[j] = temp;
            x = S[(S[i] + S[j]) & 0xFF];
            encrypted[counter] = (byte) (plainText[counter] ^ x);
        }
        return encrypted;
    }

    public byte[] decrypt(final byte[] encrypted){
        return encrypt(encrypted);
    }
}

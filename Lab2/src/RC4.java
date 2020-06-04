import java.util.Scanner;

public class RC4 {
    private char[] key;

    public RC4(String key) throws InvalidKeyException {
        if (key.length() < 1 || key.length() > 256)
            throw new InvalidKeyException("The key length has to be between 1 and 256.");
        if (key.length() < 5 || key.length() > 16)
            System.out.println("It is recommended to pick the key length between 5 and 16.");
        this.key = key.toCharArray();
    }

    /*
    For as many iterations as are needed, the pseudorandom generation algorithm (PRGA) modifies the state and outputs a
    byte of the keystream. In each iteration, the PRGA
    - increments i;
    - looks up the ith element of S, S[i], and adds that to j;
    - exchanges the values of S[i] and S[j] then uses the sum S[i] + S[j] (modulo 256) as an index to fetch a third
    element of S (the keystream value K below);
    - then bitwise exclusive ORed (XORed) with the next byte of the message to produce the next byte of either
    ciphertext or plaintext.
    Each element of S is swapped with another element at least once every 256 iterations.
    */
    public char[] RPGA(final char[] m) {
        int[] S = KSA(key);
        char[] K = new char[m.length];

        int i = 0;
        int j = 0;
        for (int n = 0; n < m.length; n++) {
            i = (i + 1) % S.length;
            j = (j + S[i]) % S.length;
            swap(i, j, S);

            int pseudoRandom = S[(S[i] + S[j]) % S.length];
            K[n] = (char) (pseudoRandom ^ (int) m[n]);
        }
        return K;
    }

    /*
    The key-scheduling algorithm (KSA) is used to initialize the permutation in the array "S". "key.length" is defined
    as the number of bytes in the key and can be in the range 1 <= key.length <= 256, typically between 5 and 16,
    corresponding to a key length between 40 and 128 bits. First, the array "S" is initialized to { 0, 1, 2, ..., 255 }.
    "S" is then processed for 256 iterations, but also mixes in bytes of the key at the same time.
    */
    private int[] KSA(char[] key) {
        int[] S = new int[256];
        int j = 0;

        for (int i = 0; i < S.length; i++)
            S[i] = i;

        for (int i = 0; i < S.length; i++) {
            j = (j + S[i] + key[i % key.length]) % S.length;
            swap(i, j, S);
        }
        return S;
    }

    // Swaps to values within array
    private void swap(int i, int j, int[] array) {
        int temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }

    /*
    16. Implement the RC4 algorithm.
    RC4 generates a pseudorandom stream of bits (a keystream). As with any stream cipher, these can be used for
    encryption by combining it with the plaintext using bit-wise exclusive-or; decryption is performed the same way
    (since exclusive-or with given data is an involution).
    */
    public static void main(String[] args) {
        try {
            Scanner scan = new Scanner(System.in);

            System.out.print("Input the key: ");
            RC4 rc4 = new RC4(scan.nextLine());

            System.out.print("Input the message to be encrypted: ");
            char[] result = rc4.RPGA(scan.nextLine().toCharArray());

            System.out.println("Encrypted message: " + new String(result));
            System.out.println("Decrypted message: " + new String(rc4.RPGA(result)));
        } catch (InvalidKeyException e) {
            System.err.println(e.getMessage());
        }
    }
}
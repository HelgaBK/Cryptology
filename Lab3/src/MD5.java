import java.util.Scanner;

public class MD5 {
    /*
    Initialize variables. A four 32 bits words buffer (A, B, C, D) is used to compute the message digest. Here each of
    A, B, C and D is a 32-bit register. These registers are initialized to the following values in hexadecimal,
    low-order bytes first
    */
    private static final int INIT_A = 0x67452301;
    private static final int INIT_B = (int) 0xEFCDAB89L;
    private static final int INIT_C = (int) 0x98BADCFEL;
    private static final int INIT_D = 0x10325476;

    // specifies the per-round shift amounts
    private static final int[] SHIFT_AMTS = {
            7, 12, 17, 22,
            5, 9, 14, 20,
            4, 11, 16, 23,
            6, 10, 15, 21
    };

    // Auxiliary table which is filled in the static block below
    private static final int[] TABLE_T = new int[64];

    /*
    Let T[i] denote the i-th element of the table, which is equal to the integer part of 4_294_967_296 times (2 ^ 32)
    abs(sin(i + 1)), where i is in radians
    In other words, these are the pseudo-random numbers that depend on sin(i):
    */
    static {
        for (int i = 0; i < 64; i++)
            TABLE_T[i] = (int) (long) ((1L << 32) * Math.abs(Math.sin(i + 1)));
    }

    /* MD5 processes a variable-length message into a fixed-length output of 128 bits. */
    public static byte[] computeMD5(byte[] message) {
        // message length
        int messageLenBytes = message.length;

        /* The unsigned right shift operator ">>>" shifts a zero into the leftmost position. In the other words it
        divides the number by 2^6 = 64.
        The byte array could be converted to a sequence of zeros and ones. The byte numbers, written in binary number
        system, can be written as a sequence of zeros and ones. If we do this, we get a sequence of zeros and ones from
        the original string.
        Let q be the length of the resulting sequence (exactly 64 bits, possibly with insignificant zeros). So if
        divided by 64, we can count number of 64-bits blocks.
        For example, 1 for "HELLO".
        */
        int numBlocks = ((messageLenBytes + 8) >>> 6) + 1;

        /*
        The signed left shift operator "<<" shifts a bit pattern to the left. In other words it multiplies the number by
        2^6 = 64. So we can calculate number of bytes in numbBlocks number of block.
        */
        int totalLen = numBlocks << 6;  // For example, 64 for "HELLO"

        /*
        The input message will be broken up into chunks of 512-bit blocks (sixteen 32-bit words); so the message is
        padded so that its length in bits is divisible by 512.
        The message is "padded" (extended) so that its length (in bits) is congruent to 448, modulo 512
        (length mod 512 = 448). That is, the message is extended so that it is just 64 bits shy of being a multiple of
        512 bits long. Padding is always performed, even if the length of the message is already congruent to 448,
        modulo 512. Padding is performed as follows: a single "1" bit is appended to the message, and then "0" bits are
        appended so that the length in bits of the padded message becomes congruent to 448, modulo 512. In all, at least
        one bit and at most 512 bits are appended.
        */
        byte[] paddingBytes = new byte[totalLen - messageLenBytes]; // 64 - 5 = 59 - number of bytes need to be padded

        // Pre-processing: adding a single 1 bit
        paddingBytes[0] = (byte) 0x80;

        // length of message in bytes multiplies by 2 ^ 3 = 8, calculate the length in bits
        long messageLenBits = (long) messageLenBytes << 3;
        for (int i = 0; i < 8; i++) {
            paddingBytes[paddingBytes.length - 8 + i] = (byte) messageLenBits;  // 40, 0, 0, ...
            messageLenBits >>>= 8;  // 0, 0, ...
        }

        // Initialize hash value for this chunk:
        int a = INIT_A;
        int b = INIT_B;
        int c = INIT_C;
        int d = INIT_D;

        // buffer for 512-bits (16 int) chunk
        int[] buffer = new int[16];

        // Main loop processes the message in successive 512-bit chunks:
        for (int i = 0; i < numBlocks; i++) {
            // index the first element of the current chunk (in bytes)
            int index = i << 6;

            // Copy next 512-bit (64 bytes, 16 ints) chunk to buffer
            for (int j = 0; j < 64; j++, index++)
                /*
                The low 4 bytes (32 bits) of the message are added to the buffer, and then the high bytes (bits), and
                then the padding.
                */
                buffer[j >>> 2] = ((int) ((index < messageLenBytes) ? message[index] : paddingBytes[index - messageLenBytes]) << 24) | (buffer[j >>> 2] >>> 8);

            int originalA = a;
            int originalB = b;
            int originalC = c;
            int originalD = d;

            /*
            The processing of a message block consists of 4 similar stages, termed rounds; each round is composed of 16
            similar operations based on a non-linear function f, modular addition, and left rotation. There are 4
            possible functions; a different one is used in each round.
            */
            for (int j = 0; j < 64; j++) {
                // Defines number of round (from 1 to 4)
                int div16 = j >>> 4;

                int f = 0;
                int bufferIndex = j;

                /*
                Uses 4 auxiliary functions (depends on round) that each take as input three 32-bit words and produce as
                output one 32-bit word.
                */
                switch (div16) {
                    case 0:
                        f = (b & c) | (~b & d);
                        break;

                    case 1:
                        f = (b & d) | (c & ~d);
                        bufferIndex = (bufferIndex * 5 + 1) & 0x0F;
                        break;

                    case 2:
                        f = b ^ c ^ d;
                        bufferIndex = (bufferIndex * 3 + 5) & 0x0F;
                        break;

                    case 3:
                        f = c ^ (b | ~d);
                        bufferIndex = (bufferIndex * 7) & 0x0F;
                        break;
                }

                /* a, b, c, d transformations for rounds 1, 2, 3, and 4. */
                int temp = b + Integer.rotateLeft(a + f + buffer[bufferIndex] + TABLE_T[j], SHIFT_AMTS[(div16 << 2) | (j & 3)]);
                a = d;
                d = c;
                c = b;
                b = temp;
            }

            /*
            Then perform the following additions. (That is increment each of the 4 registers by the value it had before
            this block was started.)
            */
            a += originalA;
            b += originalB;
            c += originalC;
            d += originalD;
        }

        /*
        The message digest produced as output is A, B, C, D. That begins with the low-order byte of A, and ends with the
        high-order byte of D.
        */
        byte[] md5 = new byte[16];
        int count = 0;
        for (int i = 0; i < 4; i++) {
            int n = (i == 0) ? a : ((i == 1) ? b : ((i == 2) ? c : d));
            for (int j = 0; j < 4; j++) {
                md5[count++] = (byte) n;
                n >>>= 8;
            }
        }
        return md5;
    }

    // Convert to byte word
    public static String toHexString(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte value : b)
            sb.append(String.format("%02X", value & 0xFF));
        return sb.toString();
    }

    // Run the algorithm
    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);
        System.out.print("Input: ");

        /*
        For MD5 processing, it gets some string. This string is converted to a sequence of bytes (numbers from 0 to
        127). For example,
        "HELLO" = [72, 69, 76, 76, 79].
        After executing this algorithm, the length of result will be 128 bits. We will see the result of MD5 as a
        sequence of 32 characters 0..f, as it's displayed in hexadecimal.
        */
        System.out.print("MD5: " + toHexString(computeMD5(scan.nextLine().getBytes())));
    }
}
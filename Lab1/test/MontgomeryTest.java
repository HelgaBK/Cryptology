import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;


import static org.junit.jupiter.api.Assertions.*;

class MontgomeryTest {

    @Test
    void multiply() {
        BigInteger x = new BigInteger("25");
        BigInteger y = new BigInteger("25");
        BigInteger N = new BigInteger("7");
        BigInteger R = new BigInteger("2");

        BigInteger R1 = R;
        int pow = -1;
        while (R1.compareTo(BigInteger.ZERO) > 0) {
            R1 = R1.divide(BigInteger.TWO);
            pow++;
        }

        BigInteger res;

        res = Montgomery.multiply(x, y, R, N, pow);

        assertEquals(0, res.compareTo(new BigInteger("2")));
    }

    @Test
    void pow() {
        BigInteger x = new BigInteger("25");
        BigInteger y = new BigInteger("25");
        BigInteger N = new BigInteger("7");
        BigInteger R = new BigInteger("2");

        BigInteger R1 = R;
        int pow = -1;
        while (R1.compareTo(BigInteger.ZERO) > 0) {
            R1 = R1.divide(BigInteger.TWO);
            pow++;
        }

        BigInteger res;

        res = Montgomery.pow(x, y, R, N, pow);

        assertEquals(0, res.compareTo(new BigInteger("4")));
    }
}
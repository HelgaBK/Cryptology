import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Scanner;

public class KarazubaMult {
    public static BigInteger karazubaMult(BigInteger x, BigInteger y) {
        // cutoff to brute force
        int N = Math.max(x.bitLength(), y.bitLength());

        // Karazuba is not efficient
        if (N <= 2000)
            return x.multiply(y);

        // number of bits divided by 2, rounded up
        N = (N / 2) + (N % 2);

        // x = X1 * 2^N + X2, y = Y1 * 2^N + Y2
        BigInteger x1 = x.shiftRight(N);
        BigInteger x2 = x.subtract(x1.shiftLeft(N));
        BigInteger y1 = y.shiftRight(N);
        BigInteger y2 = y.subtract(y1.shiftLeft(N));

        // compute sub-expressions
        BigInteger x1y1 = karazubaMult(x1, y1);
        BigInteger x2y2 = karazubaMult(x2, y2);
        BigInteger x1x2y1y2 = karazubaMult(x2.add(x1), y2.add(y1)); // (x1+x2) * (y1+y2)

        // x1y1 * 10^2n + (x1y2 + x2y1) * 10^n + x2y2
        // (x1+x2)(y1+y2) - x1y1 - x2y2 = x1y2 + xy1
        // x1y1 * 10^2n + ((x1+x2)(y1+y2) - x1y1 - x2y2) * 10^n + x2y2
        return x2y2.add(x1x2y1y2.subtract(x2y2).subtract(x1y1).shiftLeft(N)).add(x1y1.shiftLeft(2 * N));
    }

    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);

        System.out.print("Input first number: ");
        BigInteger a = new BigDecimal(scan.nextLine()).toBigInteger();

        System.out.print("Input second number: ");
        BigInteger b = new BigDecimal(scan.nextLine()).toBigInteger();

        BigInteger c = karazubaMult(a, b);
        System.out.println("Multiplication result: " + c);

        BigInteger d = a.multiply(b);
        System.out.println("Check result: " + c.equals(d));
    }
}
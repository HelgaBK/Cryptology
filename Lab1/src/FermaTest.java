import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Random;

public class FermaTest {
    private final static Random rand = new Random();

    // Get random number suitable for Fermat Test
    private static BigInteger getRandomFermatBase(BigInteger n) {
        // Rejection method: ask for a random integer but reject it if it isn't in the acceptable set
        while (true) {
            final BigInteger a = new BigInteger(n.bitLength(), rand);

            // require 1 <= a < n
            if (BigInteger.ONE.compareTo(a) <= 0 && a.compareTo(n) < 0)
                return a;
        }
    }

    // Check if n may be a prime number
    public static boolean checkPrime(BigInteger n, int maxIterations) {
        if (n.equals(BigInteger.ONE))
            return false;

        // Run Fermat Test for some numbers
        for (int i = 0; i < maxIterations; i++) {
            BigInteger a = getRandomFermatBase(n);
            a = a.modPow(n.subtract(BigInteger.ONE), n);    // a^(n - 1) mod n

            // If (a^(n - 1) mod n) != 1 then n is definitely not prime
            if (!a.equals(BigInteger.ONE))
                return false;
        }

        // n may be prime
        return true;
    }

    public static void main(String[] args) {
        System.out.printf("Is 2 a prime number? %b%n", checkPrime(BigInteger.valueOf(2L), 20));
        System.out.printf("Is 5 a prime number? %b%n", checkPrime(BigInteger.valueOf(5L), 20));
        System.out.printf("Is 7 a prime number? %b%n", checkPrime(BigInteger.valueOf(7L), 20));
        System.out.printf("Is 9 a prime number? %b%n", checkPrime(BigInteger.valueOf(9L), 20));
        System.out.printf("Is 1.34078e161 a prime number? %b%n", checkPrime(new BigDecimal("1.34078e161").toBigInteger(), 20));
    }
}
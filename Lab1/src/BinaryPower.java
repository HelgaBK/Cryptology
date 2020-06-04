import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Scanner;

// 3 Реализовать операцию возведения по модулю в степень методом двоичного потенцирования
public class BinaryPower {
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    // Рекурсивна функція, що повертає a^n
    public static BigInteger binpow(BigInteger a, BigInteger n) {
        // a^0 == 1
        if (n.equals(ZERO)) {
            return BigInteger.ONE;
        }

        // a^1 == a
        if (n.equals(ONE)) {
            return a;
        }

        // n непарне
        if (n.mod(TWO).equals(ONE)) {
            return a.multiply(binpow(a, n.subtract(ONE)));
        }

        // n парне
        else {
            BigInteger b = binpow(a, n.divide(TWO));
            return b.multiply(b);
        }
    }

    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);

        System.out.print("Input number: ");
        BigInteger numb = new BigDecimal(scan.nextLine()).toBigInteger();

        System.out.print("Input degree: ");
        BigInteger deg = new BigDecimal(scan.nextLine()).toBigInteger();

        System.out.println(binpow(numb, deg));
    }
}
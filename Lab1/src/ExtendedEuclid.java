import java.math.*;

/*
This function will perform the Extended Euclidean algorithm to find the
d = GCD(a, b).
We assume here that a and b are non-negative (and non-zero). This function also returns numbers X and Y such that
d = X * a + Y * b
where d is the GCD of a and b.
*/
public class ExtendedEuclid {
    public static BigInteger[] extendedAlgorithm(BigInteger a, BigInteger b) {
        BigInteger[] ans = new BigInteger[3];   // { gcd, x, y }

        if (b.intValue() == 0) {  /*  If b = 0, then GCD is a  */
            ans[0] = a;
            ans[1] = BigInteger.valueOf(1);
            ans[2] = BigInteger.valueOf(0);
        } else {
            /*  Otherwise, make a recursive function call  */
            BigInteger q = a.divide(b);                             // a / b
            ans = extendedAlgorithm(b, a.remainder(b));             // gcd(b, a % b)

            BigInteger temp = ans[1].subtract(ans[2].multiply(q));  // temp = y1 - x1 * (b / a) = y1 - x1 * q
            ans[1] = ans[2];                                        // y = x1
            ans[2] = temp;                                          // x = temp
        }
        return ans;
    }

    private static void Diofant(BigInteger a, BigInteger b, BigInteger c, BigInteger[] extEuclid) {
        // a * x + b * y = c, a = b = 0 is impossible here
        // if c % gcd(a, b) == 0, then ax + by = c has a solution, otherwise it has none

        // gcd = extEuclid[0]
        // X = extEuclid[1]
        // Y = extEuclid[2]
        if (!c.remainder(extEuclid[0]).equals(BigInteger.valueOf(0))) {
            System.out.println("None");
            return;
        }

        BigInteger x0 = extEuclid[1].multiply(c).divide(extEuclid[0]); // x0 = X * (c / gcd)
        BigInteger y0 = extEuclid[2].multiply(c).divide(extEuclid[0]); // y0 = Y * (c / gcd)
        System.out.println(c.toString() + " = " + x0.toString() + "*" + a.toString() + " + " + y0.toString() + "*" + b.toString());

        // x = x0 + k * b, y = y0 – k * a, k є Z
        // Розв'язки становлять нескінченну множину, наприклад 5 з них(к від 2 до 6)
        for (BigInteger k = BigInteger.valueOf(2); k.intValue() < 7; k = k.add(BigInteger.valueOf(1)))
            System.out.println(c.toString() + " = " + x0.add(b.multiply(k)).toString() + "*" + a.toString() + " + " + y0.subtract(a.multiply(k)).toString() + "*" + b.toString());
    }

    public static void main(String[] args) {
        // a * x + b * y = c 7x mod19=1 7*x-k*19=1
        BigInteger a = new BigDecimal("7").toBigInteger();
        BigInteger b = new BigDecimal("-19").toBigInteger();
        BigInteger c = new BigInteger("1");

        BigInteger[] res = extendedAlgorithm(a, b);
        System.out.println("GCD(" + a.toString() + ", " + b.toString() + ") = " + res[0].toString());

        System.out.println("Bezout's Identity: " + res[0].toString() + " = " + res[1].toString() + "*" + a.toString() + " + " + res[2].toString() + "*" + b.toString() + "\nSolutions to Diofant equation: ");
        Diofant(a, b, c, res);
    }
}
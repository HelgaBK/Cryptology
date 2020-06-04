import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class ExtendedEuclidTest {

    @Test
    void extendedAlgorithm() {
        BigInteger[] res = ExtendedEuclid.extendedAlgorithm(new BigInteger("10"), new BigInteger("15"));
        assertEquals(0, res[0].compareTo(new BigInteger("5")));
        assertEquals(0, res[1].compareTo(new BigInteger("-1")));
        assertEquals(0, res[2].compareTo(new BigInteger("1")));
    }

}
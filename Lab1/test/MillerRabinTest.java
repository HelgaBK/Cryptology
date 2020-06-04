import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class MillerRabinTest {

    @Test
    void isProbablePrime() {
        assertTrue(MillerRabin.isProbablePrime(new BigInteger("7"), 20));
        assertFalse(MillerRabin.isProbablePrime(new BigDecimal("1.34078e161").toBigInteger(), 20));
    }
}
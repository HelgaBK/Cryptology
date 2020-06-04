import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class BinaryPowerTest {

    @Test
    void binpow() {
        assertEquals(0, BinaryPower.binpow(new BigInteger("2"), new BigInteger("10")).compareTo(new BigInteger("1024")));
        assertEquals(0, BinaryPower.binpow(new BigInteger("3"), new BigInteger("4")).compareTo(new BigInteger("81")));
    }
}
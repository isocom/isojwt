package eu.isocom.jwt.crypto;

import eu.isocom.jwt.crypto.AESGCM.Tuple;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

/**
 * @author Bart Prokop
 */
public class AESGCMTest {

    final byte[] key = new byte[256 / 8];

    @Before
    public void before() {
        Tools.SECURE_RANDOM.nextBytes(key);
    }

    @Test
    public void testEncrypt() {
        AESGCM.Tuple tuple = AESGCM.encrypt(key, "Hello world".getBytes(), "Bart".getBytes());
        assertEquals(12, tuple.iv.length);
        assertEquals("Hello world".length(), tuple.cipherText.length);
        assertEquals(128 / 8, tuple.authTag.length);
        byte[] plain = AESGCM.decrypt(key, tuple, "Bart".getBytes());
        assertEquals("Hello world", new String(plain));
    }

    @Test
    public void testToString() {
        String s = AESGCM.encrypt(key, "Hello".getBytes(), "Bart".getBytes()).toString();
        byte[] decrypted = AESGCM.decrypt(key, Tuple.parse(s), "Bart".getBytes());
        assertEquals("Hello", new String(decrypted));
    }

}

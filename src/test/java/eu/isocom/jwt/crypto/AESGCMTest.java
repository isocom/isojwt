package eu.isocom.jwt.crypto;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Bart Prokop
 */
public class AESGCMTest {
    
    @Test
    public void testEncrypt() {
        final byte[] key = new byte[256/8];
        Tools.SECURE_RANDOM.nextBytes(key);
        
        AESGCM.Tuple tuple = AESGCM.encrypt(key, "Hello world".getBytes(), "Bart".getBytes());
        assertEquals(12, tuple.iv.length);
        assertEquals("Hello world".length(), tuple.cipherText.length);
        assertEquals(128/8, tuple.authTag.length);
        byte[] plain = AESGCM.decrypt(key, tuple, "Bart".getBytes());
        assertEquals("Hello world", new String(plain));
    }

}

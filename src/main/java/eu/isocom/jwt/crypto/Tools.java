package eu.isocom.jwt.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author Bart Prokop
 */
public class Tools {
    
    static final SecureRandom SECURE_RANDOM = getSecureRandom();
    
    private static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException nsae) {
            throw new InternalError(nsae);
        }
    }
}

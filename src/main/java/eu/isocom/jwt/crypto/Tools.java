package eu.isocom.jwt.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * @author Bart Prokop
 */
public final class Tools {
    
    static final SecureRandom SECURE_RANDOM = getSecureRandom();
    static final Base64.Encoder BASE64URL = Base64.getEncoder().withoutPadding();
    static final Base64.Decoder BASE64DEC = Base64.getDecoder();
    
    private static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException nsae) {
            throw new InternalError(nsae);
        }
    }
}

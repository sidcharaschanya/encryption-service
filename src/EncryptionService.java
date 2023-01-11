import java.security.GeneralSecurityException;

public interface EncryptionService {
    byte[] encrypt(byte[] plainBytes, byte[] key) throws GeneralSecurityException;

    byte[] decrypt(byte[] cipherBytes, byte[] key) throws GeneralSecurityException;
}

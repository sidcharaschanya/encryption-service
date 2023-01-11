import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class AesGcmEncryptionService implements EncryptionService {
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    private Cipher getCipher(int mode, byte[] key, GCMParameterSpec gcmParameterSpec) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), gcmParameterSpec);
        return cipher;
    }

    public byte[] encrypt(byte[] plainBytes, byte[] key) throws GeneralSecurityException {
        byte[] iv = new byte[GCM_IV_BYTES];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        byte[] cipherBytes = cipher.doFinal(plainBytes);
        return ByteBuffer.allocate(GCM_IV_BYTES + cipherBytes.length).put(iv).put(cipherBytes).array();
    }

    public byte[] decrypt(byte[] cipherBytes, byte[] key) throws GeneralSecurityException {
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_BITS, cipherBytes, 0, GCM_IV_BYTES);
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        return cipher.doFinal(cipherBytes, GCM_IV_BYTES, cipherBytes.length - GCM_IV_BYTES);
    }
}

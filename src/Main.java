import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Main {
    private final EncryptionService encryptionService = new AesGcmEncryptionService();
    private String plainString;
    private byte[] key;

    private void setUpEncryptionServiceTests() throws NoSuchAlgorithmException {
        byte[] plainBytes = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(plainBytes);
        plainString = new String(plainBytes, StandardCharsets.UTF_8);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        key = keyGenerator.generateKey().getEncoded();
    }

    private void printTestResult(boolean testResult) {
        System.out.println((testResult ? "Test passed!" : "Test failed!") + "\n");
    }

    private void testEncryptionAndDecryption() throws GeneralSecurityException {
        byte[] encryptedBytes = encryptionService.encrypt(plainString.getBytes(StandardCharsets.UTF_8), key);
        byte[] decryptedBytes = encryptionService.decrypt(encryptedBytes, key);
        String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);
        System.out.println("Test Encryption and Decryption:");
        System.out.println("plainString = " + plainString);
        System.out.println("decryptedString = " + decryptedString);
        printTestResult(decryptedString.equals(plainString));
    }

    private void testEncryptingTwice() throws GeneralSecurityException {
        byte[] encryptedBytes1 = encryptionService.encrypt(plainString.getBytes(StandardCharsets.UTF_8), key);
        byte[] encryptedBytes2 = encryptionService.encrypt(plainString.getBytes(StandardCharsets.UTF_8), key);
        System.out.println("Test Encrypting Twice:");
        System.out.println("encryptedBytes1 = " + Arrays.toString(encryptedBytes1));
        System.out.println("encryptedBytes2 = " + Arrays.toString(encryptedBytes2));
        printTestResult(!Arrays.equals(encryptedBytes1, encryptedBytes2));
    }

    public void runEncryptionServiceTests() {
        try {
            setUpEncryptionServiceTests();
            testEncryptionAndDecryption();
            testEncryptingTwice();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Main().runEncryptionServiceTests();
    }
}

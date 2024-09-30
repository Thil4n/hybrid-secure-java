import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AES {
    // Method to encrypt a string using AES
    public static String encrypt(String plainText, String secretKey) throws Exception {
        // Create AES cipher instance
        Cipher cipher = Cipher.getInstance("AES");

        // Create secret key spec
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "AES");

        // Initialize the cipher for encryption
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        // Encrypt the plain text
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        // Encode the result to Base64 to make it human-readable
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Method to decrypt a string using AES
    public static String decrypt(String encryptedText, String secretKey) throws Exception {
        // Create AES cipher instance
        Cipher cipher = Cipher.getInstance("AES");

        // Create secret key spec
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "AES");

        // Initialize the cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        // Decode the encrypted text from Base64
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);

        // Decrypt the bytes and return the result
        return new String(cipher.doFinal(decodedBytes));
    }

    public static void main(String[] args) {
        try {
            // Example secret key (16 bytes for AES-128)
            String secretKey = "1234567890123456";

            // Text to encrypt
            String plainText = "Hello, World!";

            // Encrypt the text
            String encryptedText = encrypt(plainText, secretKey);
            System.out.println("Encrypted Text: " + encryptedText);

            // Decrypt the text
            String decryptedText = decrypt(encryptedText, secretKey);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
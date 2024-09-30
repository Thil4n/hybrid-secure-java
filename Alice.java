import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Alice {

    public static void main(String[] args) throws Exception {
        // Load Bob's public key from file
        PublicKey bobPublicKey = loadPublicKey("bob_pub.der");

        // Generate random AES key (symmetric key)
        SecretKey aesKey = generateAESKey();

        // Data to encrypt
        String dataToEncrypt = "Sensitive Data from Alice";

        // Encrypt the data using AES
        byte[] encryptedData = encryptDataWithAES(dataToEncrypt, aesKey);

        // Encrypt the AES key using Bob's public key (RSA)
        byte[] encryptedAESKey = encryptAESKeyWithRSA(aesKey.getEncoded(), bobPublicKey);

        // Output the results (this would be sent to the recipient)
        System.out.println("Encrypted Data: " + Base64.getEncoder().encodeToString(encryptedData));
        System.out.println("Encrypted AES Key: " + Base64.getEncoder().encodeToString(encryptedAESKey));
    }

    // Generate a random AES key (128-bit)
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128-bit AES
        return keyGen.generateKey();
    }

    // Encrypt data using AES
    public static byte[] encryptDataWithAES(String data, SecretKey aesKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return aesCipher.doFinal(data.getBytes());
    }

    // Encrypt AES key using RSA (public key)
    public static byte[] encryptAESKeyWithRSA(byte[] aesKey, PublicKey publicKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return rsaCipher.doFinal(aesKey);
    }

    // Load public key from file (Bob's public key)
    public static PublicKey loadPublicKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
}
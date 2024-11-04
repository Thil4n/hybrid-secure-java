import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Bob {

    public static void main(String[] args) throws Exception {
        // Encrypted data received from Alice (Base64 encoded)
        String encryptedDataBase64 = "e8U/qD0uW5YzMh9vErg4MAQyjRjNe0/DF5GN+GJxvOc=";
        String encryptedAESKeyBase64 = "GypGvLme1/qzWWCQRRmCQ+QjKC+CGf6OJMaVmnSF8WCYWiVbxy/PqAfqnt79on86rqF6tKZJeiwceMZdoBbrf7ZaQY6KThUGpQXrZgqTIO+luTKk1dD1LfEu5m8sp6OF6cKEuGMo/lNfotIDGi2Qphk/OolrLzNpqYTYjxWkhjva7Gk/sePK3DX+vLgOI7+zs/BvVCVrDV/xLrayX9ArJS42DqlCkZZV8HiF+2eNy/j7sf6U6vBaQBWU9OAGkBkNHB7oGjBLEyVwD38qFtX3e9ymgZRGqkPXNzD7650e0/jnVBfftaE0itamBp4QhPMQ3A76mDOG2wwk08Iuw/2GAg==";

        // Decode the Base64 encoded encrypted data and AES key
        byte[] encryptedData = Base64.getDecoder().decode(encryptedDataBase64);
        byte[] encryptedAESKey = Base64.getDecoder().decode(encryptedAESKeyBase64);

        // Load Bob's private key to decrypt the AES key
        PrivateKey bobPrivateKey = loadPrivateKey("bob_priv.der");

        // Decrypt the AES key using Bob's private key (RSA)
        byte[] decryptedAESKey = decryptAESKeyWithRSA(encryptedAESKey, bobPrivateKey);

        // Decrypt the data using the decrypted AES key
        String decryptedData = decryptDataWithAES(encryptedData, decryptedAESKey);
        System.out.println("Decrypted Data: " + decryptedData);
    }

    // Decrypt AES key using RSA (private key)
    public static byte[] decryptAESKeyWithRSA(byte[] encryptedAESKey, PrivateKey privateKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return rsaCipher.doFinal(encryptedAESKey);
    }

    // Decrypt data using AES
    public static String decryptDataWithAES(byte[] encryptedData, byte[] aesKey) throws Exception {
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec);
        byte[] decryptedData = aesCipher.doFinal(encryptedData);
        return new String(decryptedData);
    }

    // Load private key from file (Bob's private key)
    public static PrivateKey loadPrivateKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

}
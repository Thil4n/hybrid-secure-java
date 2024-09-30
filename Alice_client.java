import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;

public class Alice_client {

    final static int PORT = 4444;
    final static String HOST = "localhost";

    public static void main(String[] args) {

        try {
            // Load Bob's public key from file
            PublicKey bobPublicKey = loadPublicKey("bob_pub.der");

            // Encrypt the message using Bob's public key
            String message = "Hello from Alice!";
            byte[] encryptedMessage = encryptMessage(message, bobPublicKey);

            // Send the encrypted message to Bob
            Socket s = new Socket(HOST, PORT);
            OutputStream os = s.getOutputStream();
            os.write(encryptedMessage);
            os.flush();

            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
            String resp = in.readLine();
            System.out.println("Response from Bob: " + resp);

            s.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Method to load Bob's public key from a file
    public static PublicKey loadPublicKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    // Method to encrypt a message using a public key
    public static byte[] encryptMessage(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }
}
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;

public class Bob_server {

    final static int PORT = 4444;

    public static void main(String[] args) throws Exception {
        System.out.println("Server is listening on port " + PORT + "!");

        // Load Bob's private key from file
        PrivateKey bobPrivateKey = loadPrivateKey("bob_pvt_pkcs8.key");

        ServerSocket ss = new ServerSocket(PORT);

        while (true) {
            Socket s = ss.accept();
            System.out.println("A client connected!");

            // Read the encrypted message from Alice
            InputStream is = s.getInputStream();
            byte[] encryptedMessage = new byte[256];
            is.read(encryptedMessage);

            // Decrypt the message using Bob's private key
            String decryptedMessage = decryptMessage(encryptedMessage, bobPrivateKey);
            System.out.println("Decrypted message from Alice: " + decryptedMessage);

            // Respond to Alice
            PrintWriter out = new PrintWriter(s.getOutputStream(), true);
            out.println("Hello from Bob!");

            s.close();
        }
    }

    // Method to load Bob's private key from a file (PKCS#8 format, DER encoded)
    public static PrivateKey loadPrivateKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    // Method to decrypt a message using a private key
    public static String decryptMessage(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }
}
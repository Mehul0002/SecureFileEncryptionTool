import java.security.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.security.cert.*;

public class KeyGenerator {

    public static void generateAESKey(String filename) throws Exception {
        javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        saveKey(secretKey, filename);
        System.out.println("AES key generated and saved to " + filename);
    }

    public static void generateRSAKeyPair(String privateKeyFile, String publicKeyFile) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        saveKey(pair.getPrivate(), privateKeyFile);
        saveKey(pair.getPublic(), publicKeyFile);
        System.out.println("RSA key pair generated and saved to " + privateKeyFile + " and " + publicKeyFile);
    }

    private static void saveKey(Key key, String filename) throws Exception {
        byte[] keyBytes = key.getEncoded();
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(keyBytes);
        fos.close();
    }

    public static SecretKey loadAESKey(String filename) throws Exception {
        byte[] keyBytes = loadKeyBytes(filename);
        SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
        return spec;
    }

    public static PrivateKey loadRSAPrivateKey(String filename) throws Exception {
        byte[] keyBytes = loadKeyBytes(filename);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return keyFactory.generatePrivate(keySpec);
    }

    public static PublicKey loadRSAPublicKey(String filename) throws Exception {
        byte[] keyBytes = loadKeyBytes(filename);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(keySpec);
    }

    private static byte[] loadKeyBytes(String filename) throws Exception {
        File file = new File(filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] keyBytes = new byte[(int) file.length()];
        fis.read(keyBytes);
        fis.close();
        return keyBytes;
    }
}

import java.security.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Decryptor {

    public static void decryptFileAES(String inputFile, String outputFile, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        processFile(cipher, inputFile, outputFile);
        System.out.println("File decrypted successfully: " + outputFile);
    }

    public static void decryptFileRSA(String inputFile, String outputFile, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        processFile(cipher, inputFile, outputFile);
        System.out.println("File decrypted successfully: " + outputFile);
    }

    private static void processFile(Cipher cipher, String inputFile, String outputFile) throws Exception {
        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(outputFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                fos.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            fos.write(outputBytes);
        }
        fis.close();
        fos.close();
    }

    public static void validateFilePath(String filePath) throws Exception {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException("File not found: " + filePath);
        }
    }
}

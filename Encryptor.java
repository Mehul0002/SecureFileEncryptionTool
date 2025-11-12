import java.security.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Encryptor {

    public static void encryptFileAES(String inputFile, String outputFile, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        processFile(cipher, inputFile, outputFile);
        System.out.println("File encrypted successfully: " + outputFile);
    }

    public static void encryptFileRSA(String inputFile, String outputFile, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        processFile(cipher, inputFile, outputFile);
        System.out.println("File encrypted successfully: " + outputFile);
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

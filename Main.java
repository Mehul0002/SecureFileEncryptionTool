import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Secure File Encryption Tool (Java)");
        System.out.println("Choose action: 1. Generate Keys 2. Encrypt 3. Decrypt");
        int action = scanner.nextInt();
        scanner.nextLine(); // consume newline

        System.out.println("Choose algorithm: 1. AES 2. RSA");
        int algo = scanner.nextInt();
        scanner.nextLine();

        try {
            if (action == 1) {
                if (algo == 1) {
                    System.out.println("Enter AES key filename:");
                    String keyFile = scanner.nextLine();
                    KeyGenerator.generateAESKey(keyFile);
                } else if (algo == 2) {
                    System.out.println("Enter RSA private key filename:");
                    String privFile = scanner.nextLine();
                    System.out.println("Enter RSA public key filename:");
                    String pubFile = scanner.nextLine();
                    KeyGenerator.generateRSAKeyPair(privFile, pubFile);
                }
            } else if (action == 2) {
                System.out.println("Enter input file:");
                String input = scanner.nextLine();
                System.out.println("Enter output file:");
                String output = scanner.nextLine();
                Encryptor.validateFilePath(input);
                if (algo == 1) {
                    System.out.println("Enter AES key file:");
                    String keyFile = scanner.nextLine();
                    var key = KeyGenerator.loadAESKey(keyFile);
                    Encryptor.encryptFileAES(input, output, key);
                } else if (algo == 2) {
                    System.out.println("Enter RSA public key file:");
                    String keyFile = scanner.nextLine();
                    var key = KeyGenerator.loadRSAPublicKey(keyFile);
                    Encryptor.encryptFileRSA(input, output, key);
                }
            } else if (action == 3) {
                System.out.println("Enter input file:");
                String input = scanner.nextLine();
                System.out.println("Enter output file:");
                String output = scanner.nextLine();
                Decryptor.validateFilePath(input);
                if (algo == 1) {
                    System.out.println("Enter AES key file:");
                    String keyFile = scanner.nextLine();
                    var key = KeyGenerator.loadAESKey(keyFile);
                    Decryptor.decryptFileAES(input, output, key);
                } else if (algo == 2) {
                    System.out.println("Enter RSA private key file:");
                    String keyFile = scanner.nextLine();
                    var key = KeyGenerator.loadRSAPrivateKey(keyFile);
                    Decryptor.decryptFileRSA(input, output, key);
                }
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
        scanner.close();
    }
}

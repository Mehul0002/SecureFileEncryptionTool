import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;

public class EncryptionGUI extends JFrame {
    private JTextField fileField;
    private JComboBox<String> algoBox;
    private JButton browseButton, generateButton, encryptButton, decryptButton;
    private JLabel statusLabel;

    public EncryptionGUI() {
        setTitle("Secure File Encryption Tool");
        setSize(400, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new FlowLayout());

        // File selection
        add(new JLabel("Select File:"));
        fileField = new JTextField(20);
        add(fileField);
        browseButton = new JButton("Browse");
        browseButton.addActionListener(e -> browseFile());
        add(browseButton);

        // Algorithm selection
        add(new JLabel("Algorithm:"));
        algoBox = new JComboBox<>(new String[]{"AES", "RSA"});
        add(algoBox);

        // Buttons
        generateButton = new JButton("Generate Key");
        generateButton.addActionListener(e -> generateKey());
        add(generateButton);

        encryptButton = new JButton("Encrypt");
        encryptButton.addActionListener(e -> encryptFile());
        add(encryptButton);

        decryptButton = new JButton("Decrypt");
        decryptButton.addActionListener(e -> decryptFile());
        add(decryptButton);

        // Status
        statusLabel = new JLabel("");
        add(statusLabel);

        setVisible(true);
    }

    private void browseFile() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            fileField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void generateKey() {
        String algo = (String) algoBox.getSelectedItem();
        try {
            if ("AES".equals(algo)) {
                KeyGenerator.generateAESKey("aes_key.key");
                statusLabel.setText("AES key generated.");
            } else if ("RSA".equals(algo)) {
                KeyGenerator.generateRSAKeyPair("rsa_private.pem", "rsa_public.pem");
                statusLabel.setText("RSA key pair generated.");
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error: " + e.getMessage());
        }
    }

    private void encryptFile() {
        String inputFile = fileField.getText();
        String algo = (String) algoBox.getSelectedItem();
        try {
            Encryptor.validateFilePath(inputFile);
            if ("AES".equals(algo)) {
                var key = KeyGenerator.loadAESKey("aes_key.key");
                String outputFile = inputFile + ".aes";
                Encryptor.encryptFileAES(inputFile, outputFile, key);
                statusLabel.setText("File encrypted: " + outputFile);
            } else if ("RSA".equals(algo)) {
                var key = KeyGenerator.loadRSAPublicKey("rsa_public.pem");
                String outputFile = inputFile + ".rsa";
                Encryptor.encryptFileRSA(inputFile, outputFile, key);
                statusLabel.setText("File encrypted: " + outputFile);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error: " + e.getMessage());
        }
    }

    private void decryptFile() {
        String inputFile = fileField.getText();
        String algo = (String) algoBox.getSelectedItem();
        try {
            Decryptor.validateFilePath(inputFile);
            if ("AES".equals(algo)) {
                var key = KeyGenerator.loadAESKey("aes_key.key");
                String outputFile = inputFile.replace(".aes", "_decrypted.txt");
                Decryptor.decryptFileAES(inputFile, outputFile, key);
                statusLabel.setText("File decrypted: " + outputFile);
            } else if ("RSA".equals(algo)) {
                var key = KeyGenerator.loadRSAPrivateKey("rsa_private.pem");
                String outputFile = inputFile.replace(".rsa", "_decrypted.txt");
                Decryptor.decryptFileRSA(inputFile, outputFile, key);
                statusLabel.setText("File decrypted: " + outputFile);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(EncryptionGUI::new);
    }
}

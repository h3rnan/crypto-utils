package cl.utils.crypto.impl;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

public class FileEncryptionTest extends TestCase {

    protected static String FOLDER_PATH = "/home/haja/pruebas/";

    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public FileEncryptionTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(FileEncryptionTest.class);
    }

    public void testEncryptLargeFile() throws Exception {

        // Generate public and private keys
        RSAKeyManager keyMan = new RSAKeyManager();
        keyMan.generateKeyPair();
        RSAPublicKey publicKey = keyMan.getPublicKey();
        RSAPrivateKey privateKey = keyMan.getPrivateKey();
        String modulus = keyMan.getModulusAsHex();
        String exponent = keyMan.getPrivateExponentAsHex();

        // Store module and exponent in a secured file. Pass modulus to the client

        // AES to encrypt the log file

        long startTime = System.currentTimeMillis();
        String logFile = readLogFile(FOLDER_PATH + "sample.txt");
        AESUtils aesUtils = new AESUtils();
        byte[] secretKey = aesUtils.generateSecretKey();

        String hexSecretKey = aesUtils.getSecretyKey();
        String encryptedHexContent = new String(Hex.encodeHex(aesUtils.encrypt(logFile)));
        System.out.println("Encrypted content in hex: " + encryptedHexContent);
        long endTime = System.currentTimeMillis();
        System.out.println("Encryption time: " + (endTime - startTime) / 1000);

        // Should save the hexSecretyKey and encrypted hex content in text file
        RSAEncryptor encryptor = new RSAEncryptor(modulus);
        String encryptedHexSecretKey = encryptor.encryptString(hexSecretKey);

        // Store encryptedHexSecretKey and encryptedHexSecretKey in files

        // On our side

        startTime = System.currentTimeMillis();
        // Decrypt the RSA encrypted secrety key using our Private Key
        RSADecryptor decryptor = new RSADecryptor(modulus, exponent);
        hexSecretKey = decryptor.decryptText(encryptedHexSecretKey);
        // Un-hex the hex secrety key
        secretKey = Hex.decodeHex(hexSecretKey.toCharArray());

        // Now we have the original secret key, decode the content

        // Un-hex the content
        byte[] encryptedContent = Hex.decodeHex(encryptedHexContent.toCharArray());
        aesUtils.setSecretKey(secretKey);
        byte[] originalContent = aesUtils.decrypt(encryptedContent);
        System.out.println("Original content: " + new String(originalContent));
        endTime = System.currentTimeMillis();
        System.out.println("Decryption time: " + (endTime - startTime) / 1000);
    }

    public void testAES() throws Exception {
        String message = readLogFile(FOLDER_PATH + "sample.txt");

        // Get the KeyGenerator
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128); // 192 and 256 bits may not be available

        // Generate the secret key specs.
        SecretKey skey = kgen.generateKey();
        byte[] raw = skey.getEncoded();

        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");

        // Instantiate the cipher
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

        long startTime = System.currentTimeMillis();
        byte[] encrypted = cipher.doFinal(message.getBytes());
        System.out.println("encrypted string: " + asHex(encrypted));
        long endTime = System.currentTimeMillis();
        System.out.println("Encryption time: " + (endTime - startTime) / 1000);


        startTime = System.currentTimeMillis();
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] original = cipher.doFinal(encrypted);
        String originalString = new String(original);
        System.out.println("Original string: " +
                originalString + " " + asHex(original));
        endTime = System.currentTimeMillis();
        System.out.println("Decryption time: " + (endTime - startTime) / 1000);
    }

    /**
     * Turns array of bytes into string
     *
     * @param buf Array of bytes to convert to hex string
     * @return Generated hex string
     */
    public String asHex(byte buf[]) {
        return new String(Hex.encodeHex(buf));
    }

    public void testRSA() throws Exception {
        Map<String, String> privateKeys;
        String cleartext = "Session Key";
        int keySize = 1024;
        privateKeys = new HashMap<String, String>();

        String modulus = generateKeys(privateKeys, keySize);
        System.out.println("Generated a key pair with a modulus of " + modulus);

        // the client will use the modulus to encrypt their password
        String encryptedText = encrypt(modulus, cleartext);
        System.out.println("Encrypted the text : " + encryptedText);

        // the server will receive the encrypted text and modulus to perform its decryption
        String decryptedText = decrypt(modulus, encryptedText, privateKeys);
        System.out.println("Decrypted as " + decryptedText);
    }

    private String decrypt(String modulus, String encryptedText, Map<String, String> privateKeys) throws RSAException {
        String exponent = privateKeys.get(modulus);
        RSADecryptor server = new RSADecryptor(modulus, exponent);
        return server.decryptText(encryptedText);
    }

    private String encrypt(String modulus, String clearText) throws RSAException {
        RSAEncryptor client = new RSAEncryptor(modulus);
        return client.encryptString(clearText);
    }

    private String generateKeys(Map<String, String> privateKeys, int keySize) throws RSAException {
        RSAKeyManager keyMan = new RSAKeyManager(keySize);
        keyMan.generateKeyPair();
        String modulus = keyMan.getModulusAsHex();
        String exponent = keyMan.getPrivateExponentAsHex();

        // You will need to store the private key somewhere in order to
        // re-use it for the decryption.  A resident memory cache is a great
        // option, if possible, to ensure that the private exponent is kept secret

        // (as opposed to a database)
        privateKeys.put(modulus, exponent);

        return modulus;
    }

    private String readLogFile(String filePath) throws Exception {
        File aFile = new File(filePath);

        //...checks on aFile are elided
        StringBuffer contents = new StringBuffer();

        //declared here only to make visible to finally clause
        BufferedReader input = null;
        try {
            input = new BufferedReader(new FileReader(aFile));
            String line = null; //not declared within while loop
            /*
            * readLine is a bit quirky :
            * it returns the content of a line MINUS the newline.
            * it returns null only for the END of the stream.
            * it returns an empty String if two newlines appear in a row.
            */
            while ((line = input.readLine()) != null) {
                contents.append(line);
                contents.append(System.getProperty("line.separator"));
            }
        }
        catch (FileNotFoundException ex) {
            ex.printStackTrace();
        }
        catch (IOException ex) {
            ex.printStackTrace();
        }
        finally {
            try {
                if (input != null) {
                    //flush and close both "input" and its underlying FileReader
                    input.close();
                }
            }
            catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        return contents.toString();
    }
}


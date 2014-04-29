package cl.utils.crypto.impl;


import java.util.HashMap;
import java.util.Map;

/**
 * Example code for a RSA keygen, encrypt, decrypt process
 *
 */
public class RSAExample {

	private Map<String,String> privateKeys;

	private String cleartext;
	private int keySize;

	public RSAExample(String text, int size) {
		privateKeys = new HashMap<String,String>();
		cleartext = text;
		keySize = size;
	}

	public static void main (String[] args) {

		try {

			int keySize = 1024;
			String cleartext = "Hello.  This is my lame password!";

			if (args.length > 0) {
				cleartext = args[0];
			}
			if (args.length == 2) {
				keySize = (new Integer(args[1])).intValue();
			}
			RSAExample example = new RSAExample(cleartext, keySize);

			// in the first pass to the server, we need to generate the key pairs
			// and send the public key (just the modulus is necessary) back to the client
			String modulus = example.generateKeys();
			System.out.println("Generated a key pair with a modulus of " + modulus);

			// the client will use the modulus to encrypt their password
			String encryptedText = example.simulateClientEncryption(modulus);
			System.out.println("Encrypted the text : " + encryptedText);

			// the server will receive the encrypted text and modulus to perform its decryption
			String decryptedText = example.simulateServerDecryption(modulus, encryptedText);
			System.out.println("Decrypted as " + decryptedText);

		} catch (RSAException e) {
			e.printStackTrace();
		}

	}

	private String simulateServerDecryption(String modulus, String encryptedText) throws RSAException {

		String exponent = privateKeys.get(modulus);

		RSADecryptor server = new RSADecryptor(modulus, exponent);
		String decryptedText = server.decryptText(encryptedText);

		return decryptedText;
	}

	private String simulateClientEncryption(String modulus) throws RSAException {

		RSAEncryptor client = new RSAEncryptor(modulus);
		String encrypted = client.encryptString(cleartext);

		return encrypted;
	}

	private String generateKeys() throws RSAException {

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

}

package cl.utils.crypto.impl;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * RSA Decryptor
 */
public class RSADecryptor extends BaseCrypto {

	public static String DEFAULT_DECRYPTION_ALGORITHM = "RSA";

	private RSAPrivateKey privateKey;

	public RSADecryptor(RSAPrivateKey key) {
		privateKey = key;
	}

	public RSADecryptor(String modulus, String exponent) throws RSAException {
		BigInteger modulusBI = KeyMath.hexToBigInt(modulus);
		BigInteger privateExponentBI = KeyMath.hexToBigInt(exponent);

		privateKey = RSAKeyManager.reconstructPrivateKey(modulusBI, privateExponentBI);
	}

	/**
	 *
	 *  Decrypts the text using the given algorithm (depending on the client
	 *  implementation, there may be padding involved)
	 *
	 * @param encryptedText
	 * @param decryptionAlgorithm
	 * @return
	 * @throws RSAException
	 */
	public String decryptText(String encryptedText, String decryptionAlgorithm) throws RSAException {
		String cleartext = null;
		byte[] encryptedTextBytes = KeyMath.hexToBytes(encryptedText);

		try {
			Cipher serverCipher = Cipher.getInstance(decryptionAlgorithm);
			serverCipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] clearTextBytes = serverCipher.doFinal(encryptedTextBytes);
			cleartext = new String(clearTextBytes);
		} catch (InvalidKeyException e) {
			throw new RSAException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new RSAException(e);
		} catch (NoSuchPaddingException e) {
			throw new RSAException(e);
		} catch (IllegalBlockSizeException e) {
			throw new RSAException(e);
		} catch (BadPaddingException e) {
			throw new RSAException(e);
		}

		return cleartext;
	}

	/**
	 *
	 *   Decrypts the text using the default algorithm (RSA)
	 *
	 * @param encryptedText (hexadecimal string value of a Big Integer)
	 * @return
	 * @throws RSAException RSA Util exception
	 */
	public String decryptText(String encryptedText) throws RSAException {

		return decryptText(encryptedText,DEFAULT_DECRYPTION_ALGORITHM);
	}

}

package cl.utils.crypto.impl;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import cl.utils.log.LogRegister;


import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

/**
 * DES encrypt and decrypt functions
 */
public class AESUtils extends BaseCrypto {

	private static Logger log = LogManager.getLogger(BaseCrypto.class.getName());

	private static final String ENCRYPTION_ALGORITHM = "AES";
	private static final int KEY_SIZE = 128;
	private static final String ENCRYPTION_TYPE = "AES/CBC/PKCS5Padding";

	private byte[] secretKey;


    private static IvParameterSpec getIV(){
    	byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        return new IvParameterSpec(iv);
    }
    /**
	 * Generate the secrey key and return as a hex string
	 *
	 * @return Secret key
	 * @throws AESException AES exception
	 */
	public byte[] generateSecretKey() throws AESException {
		try {
			// Get the KeyGenerator
			KeyGenerator kgen = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
			kgen.init(KEY_SIZE); // 192 and 256 bits may not be available
			// Generate the secret key specs.
			SecretKey skey = kgen.generateKey();
			secretKey = skey.getEncoded();
			return secretKey;
		} catch (NoSuchAlgorithmException e) {
			LogRegister.get().error(log, "Error en generacion de llave ", e);
			throw new AESException(e);
		}
	}

	public byte[] encrypt(String plainText) throws AESException {
		try {
			SecretKeySpec skeySpec = new SecretKeySpec(secretKey, ENCRYPTION_ALGORITHM);
			// Instantiate the cipher
			Cipher cipher = Cipher.getInstance(ENCRYPTION_TYPE);
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, getIV());
			return cipher.doFinal(plainText.getBytes());
		} catch (NoSuchAlgorithmException e) {
			LogRegister.get().error(log, "Error en encripcion AES ", e);
			throw new AESException(e);
		} catch (NoSuchPaddingException e) {
			LogRegister.get().error(log, "Error en encripcion AES ", e);
			throw new AESException(e);
		} catch (InvalidKeyException e) {
			LogRegister.get().error(log, "Error en encripcion AES ", e);
			throw new AESException(e);
		} catch (IllegalBlockSizeException e) {
			LogRegister.get().error(log, "Error en encripcion AES ", e);
			throw new AESException(e);
		} catch (BadPaddingException e) {
			LogRegister.get().error(log, "Error en encripcion AES ", e);
			throw new AESException(e);
		} catch (InvalidAlgorithmParameterException e) {
			LogRegister.get().error(log, "Error en encripcion AES ", e);
			throw new AESException(e);
		}
	}


	public byte[] decrypt(byte[] encrypted) throws AESException {
		try {
			SecretKeySpec skeySpec = new SecretKeySpec(secretKey, ENCRYPTION_ALGORITHM);
			Cipher cipher = Cipher.getInstance(ENCRYPTION_TYPE);
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, getIV());
			return cipher.doFinal(encrypted);
		} catch (NoSuchAlgorithmException e) {
			LogRegister.get().error(log, "Error en desencripcion AES ", e);
			throw new AESException(e);
		} catch (NoSuchPaddingException e) {
			LogRegister.get().error(log, "Error en desencripcion AES ", e);
			throw new AESException(e);
		} catch (InvalidKeyException e) {
			LogRegister.get().error(log, "Error en desencripcion AES ", e);
			throw new AESException(e);
		} catch (IllegalBlockSizeException e) {
			LogRegister.get().error(log, "Error en desencripcion AES ", e);
			throw new AESException(e);
		} catch (BadPaddingException e) {
			LogRegister.get().error(log, "Error en desencripcion AES ", e);
			throw new AESException(e);
		} catch (InvalidAlgorithmParameterException e) {
			LogRegister.get().error(log, "Error en desencripcion AES ", e);
			throw new AESException(e);
		}

	}

	public String getSecretyKey() {
		return asHex(secretKey);
	}

	public byte[] getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(byte[] secretKey) {
		this.secretKey = secretKey;
	}


}

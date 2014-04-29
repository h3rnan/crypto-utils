package cl.utils.crypto.impl;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * RSA Encryptor
 */
public class RSAEncryptor extends BaseCrypto {

    private static final String ENCRYPTION_ALGORITHM = "RSA";
    private static final String DEFAULT_PUBLIC_EXPONENT = "10001"; // This is the hex value for 65537

    private RSAPublicKey publicKey;

    private byte[] encryptedBytes;

    public RSAEncryptor(RSAPublicKey key) throws RSAException {
        publicKey = key;
    }

    /**
     * Reconstruct the public key using the modulus, and the standard public exponent (65537)
     *
     * @param modulus
     * @throws RSAException
     */
    public RSAEncryptor(String modulus) throws RSAException {
        BigInteger modulusBI = KeyMath.hexToBigInt(modulus);
        BigInteger publicExponentBI = KeyMath.hexToBigInt(DEFAULT_PUBLIC_EXPONENT);
        publicKey = RSAKeyManager.reconstructPublicKey(modulusBI, publicExponentBI);
    }

    /**
     * Reconstruct the public key, using the modulus and exponent values
     *
     * @param modulus
     * @param exponent
     * @throws RSAException
     */
    public RSAEncryptor(String modulus, String exponent) throws RSAException {
        BigInteger modulusBI = KeyMath.hexToBigInt(modulus);
        BigInteger publicExponentBI = KeyMath.hexToBigInt(exponent);
        publicKey = RSAKeyManager.reconstructPublicKey(modulusBI, publicExponentBI);
    }


    /**
     * Given a cleartext value, encrypt using the RSA algorithm and return the hexadecimal result
     * (provide the encrypted byte array as a member field of the object
     *
     * @param cleartext
     * @return
     * @throws RSAException
     */
    public String encryptString(String cleartext) throws RSAException {

        String encryptedText;
        try {
            encryptedText = null;
            Cipher clientCipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            clientCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedBytes = clientCipher.doFinal(cleartext.getBytes());
            encryptedText = KeyMath.bytesToHex(encryptedBytes);
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

        return encryptedText;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public byte[] getEncryptedBytes() {
		return encryptedBytes;
	}

}

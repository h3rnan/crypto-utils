package cl.utils.crypto.impl;


import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * A utility class for managing RSA keys
 */
public class RSAKeyManager {

    public static final String KEYGEN_ALGORITHM = "RSA";

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    private int keySize = 1024;

    /**
     * Default constructor will generate keys with a size of 1024 bits
     */
    public RSAKeyManager() {
    }

    public RSAKeyManager(int requestedKeySize) {
        keySize = requestedKeySize;
    }

    /**
     * Generate a pair of RSA keys - public and private (secret)
     *
     * @throws RSAException
     */
    public void generateKeyPair() throws RSAException {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEYGEN_ALGORITHM);
            keyGen.initialize(keySize);
            KeyPair pair = keyGen.generateKeyPair();
            publicKey = (RSAPublicKey) pair.getPublic();
            privateKey = (RSAPrivateKey) pair.getPrivate();

        } catch (NoSuchAlgorithmException e) {
            throw new RSAException(e);
        }
    }

    /**
     * The modulus is common to both the private and public keys
     *
     * @return
     */
    public String getModulusAsHex() {
        return KeyMath.bigIntToHex(publicKey.getModulus());
    }

    /**
     * The private exponent should remain a secret, kept only on the server
     *
     * @return
     */
    public String getPrivateExponentAsHex() {
        return KeyMath.bigIntToHex(privateKey.getPrivateExponent());
    }

    /**
     * The public exponent is commonly 10001 (hex value)
     *
     * @return
     */
    public String getPublicExponentAsHex() {
        return KeyMath.bigIntToHex(publicKey.getPublicExponent());
    }

    /**
     * Reconstruct a public key, given its modulus and exponent values
     * as BigIntegers
     *
     * @param modulus
     * @param publicExponent
     * @return
     * @throws RSAException
     */
    public static RSAPublicKey reconstructPublicKey(BigInteger modulus, BigInteger publicExponent) throws RSAException {

        RSAPublicKey rsaPublicKey = null;
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEYGEN_ALGORITHM);
            rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RSAException(e);
        } catch (InvalidKeySpecException e) {
            throw new RSAException(e);
        }

        return rsaPublicKey;
    }

    /**
     * Reconstruct a private key, given its modulus and exponent values
     * as BigIntegers
     *
     * @param modulus
     * @param privateExponent
     * @return
     * @throws RSAException
     */
    public static RSAPrivateKey reconstructPrivateKey(BigInteger modulus, BigInteger privateExponent) throws RSAException {

        RSAPrivateKey rsaPrivateKey = null;
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEYGEN_ALGORITHM);
            rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RSAException(e);
        } catch (InvalidKeySpecException e) {
            throw new RSAException(e);
        }

        return rsaPrivateKey;
    }

    public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}

	public RSAPublicKey getPublicKey() {
		return publicKey;
	}
}

package cl.utils.crypto.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cl.utils.crypto.DeliveryCrypto;

public class CryptoProviderKey implements DeliveryCrypto{

	private static Logger log = LogManager.getLogger(CryptoProviderKey.class);

	static {
		if (java.security.Security.getProvider("BC") == null)
		 {
			log.debug("Agregando BouncyCastleProvider a java.security.Security");
			System.out.println("Agregando BouncyCastleProvider a java.security.Security");
			Security.addProvider(new BouncyCastleProvider());
		 }
	}

	private String provider;
	private String cipherForm;
	private String keystoreName;
	private String keystorePassword;
	private String keystoreAlias;
	private String keyPassword;
	private String keystoreType;

	private boolean initialized = false;
	private KeyStore keystore = null;
	private PublicKey keyPublic = null;
	private PrivateKey keyPrivate = null;
	//private Cipher cipher = null;
	private AsymmetricBlockCipher cipher = null;

	@Override
	public String encryptMessage(Object message) throws Exception {
		if (!this.initialized){
			buildKeyStore();
		}

		if (this.initialized){
			AsymmetricKeyParameter pub = PublicKeyFactory.createKey(keyPublic.getEncoded());
			cipher.init(true, pub);
//			byte[] messageBytes = message.getBytes();
//			byte[] hexEncodedCipher = cipher.processBlock(messageBytes, 0, messageBytes.length);
//			return hexEncodedCipher;
			return null;
		} else {
			throw new Exception("Error de inicialización");
		}
	}

	@Override
	public Object decryptMessage(String encrypted) throws Exception {
		Object decrypted = null;;
		if (!this.initialized){
			buildKeyStore();
		}
		if (this.initialized){
//			SealedObject so = (SealedObject) deserialize(encrypted);
//		    cipher.init(Cipher.DECRYPT_MODE, this.keyPrivate);
//		    decrypted = (MessageParams) so.getObject(cipher);
		}
		return decrypted;
	}

	protected void buildKeyStore(){
		try {
	        KeyStore ks = KeyStore.getInstance(this.keystoreType);
	        ks.load(new FileInputStream(this.keystoreName), this.keystorePassword.toCharArray());
		    KeyPair kp = null;

	        Key key = ks.getKey(this.keystoreAlias, this.keyPassword.toCharArray());
	        if (key instanceof PrivateKey) {
	            java.security.cert.Certificate cert = ks.getCertificate(keystoreAlias);
	            PublicKey publicKey = cert.getPublicKey();
	            kp =  new KeyPair(publicKey, (PrivateKey)key);
	        }

		    this.keyPublic = kp.getPublic();
		    this.keyPrivate = kp.getPrivate();
		    if ((this.provider != null) && (this.provider != "")) {
		    	this.cipher = new RSAEngine();
			    //this.cipher = Cipher.getInstance(this.cipherForm, this.provider);
		    } else {
		    	this.cipher = new RSAEngine();
			    //this.cipher = Cipher.getInstance(this.cipherForm);
		    }
	        this.initialized = true;
		} catch (Exception e) {
			log.error("Error Inicializando parametros de Desencriptado", e);
	        this.initialized = false;
		}


	}

	private Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
		ByteArrayInputStream in = new ByteArrayInputStream(data);
		ObjectInputStream is = new ObjectInputStream(in);
		try {
			Object obj = is.readObject();
			return obj;
		} finally {
			is.close();
		}
	}

	public byte[] serialize(Object obj) throws IOException {
		byte[] out;
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);;
		try {
			oos.writeObject(obj);
			oos.flush();
			out = bos.toByteArray();
		} finally {
			oos.close();
		}
		return out;
	}

	/**
	 * @return the provider
	 */
	public String getProvider() {
		return provider;
	}

	/**
	 * @param provider the provider to set
	 */
	public void setProvider(String provider) {
		this.provider = provider;
	}

	/**
	 * @return the cipherForm
	 */
	public String getCipherForm() {
		return cipherForm;
	}

	/**
	 * @param cipherForm the cipherForm to set
	 */
	public void setCipherForm(String cipherForm) {
		this.cipherForm = cipherForm;
	}

	/**
	 * @return the keystoreName
	 */
	public String getKeystoreName() {
		return keystoreName;
	}

	/**
	 * @param keystoreName the keystoreName to set
	 */
	public void setKeystoreName(String keystoreName) {
		this.keystoreName = keystoreName;
	}

	/**
	 * @return the keystorePassword
	 */
	public String getKeystorePassword() {
		return keystorePassword;
	}

	/**
	 * @param keystorePassword the keystorePassword to set
	 */
	public void setKeystorePassword(String keystorePassword) {
		this.keystorePassword = keystorePassword;
	}

	/**
	 * @return the keystoreAlias
	 */
	public String getKeystoreAlias() {
		return keystoreAlias;
	}

	/**
	 * @param keystoreAlias the keystoreAlias to set
	 */
	public void setKeystoreAlias(String keystoreAlias) {
		this.keystoreAlias = keystoreAlias;
	}

	/**
	 * @return the keyPassword
	 */
	public String getKeyPassword() {
		return keyPassword;
	}

	/**
	 * @param keyPassword the keyPassword to set
	 */
	public void setKeyPassword(String keyPassword) {
		this.keyPassword = keyPassword;
	}

	/**
	 * @return the keystoreType
	 */
	public String getKeystoreType() {
		return keystoreType;
	}

	/**
	 * @param keystoreType the keystoreType to set
	 */
	public void setKeystoreType(String keystoreType) {
		this.keystoreType = keystoreType;
	}

	/**
	 * @return the keystore
	 */
	public KeyStore getKeystore() {
		return keystore;
	}

	/**
	 * @param keystore the keystore to set
	 */
	public void setKeystore(KeyStore keystore) {
		this.keystore = keystore;
	}

}

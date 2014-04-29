package cl.utils.crypto.impl;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.Serializable;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cl.utils.crypto.DeliveryCrypto;
import cl.utils.log.LogRegister;

public class CryptoProviderCertified implements DeliveryCrypto {

	private static Logger log = LogManager.getLogger(CryptoProviderCertified.class.getName());

	private String provider;
	private String cipherForm;

	private String publicKeyFilename;
	private String privateKeyFilename;

	private PublicKey publicKey;
	private PrivateKey privateKey;
	private Cipher cipher;

	static {
		if (java.security.Security.getProvider("BC") == null)
		{
			LogRegister.get().info(log,"Agregando BouncyCastleProvider a java.security.Security");
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	@Override
	public String encryptMessage(Object message) throws Exception {
		String dataBytes = null;
		try {
			instancePublicCertificate();
			cipher = Cipher.getInstance(cipherForm, provider);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			SealedObject so = new SealedObject((Serializable) message, cipher);
		    //dataBytes = (String) serialize(so);
		    return dataBytes;
		}
		catch (Exception e) {
//			LogRegister.get().error(log, "Error en encripcion ", e);
			throw new Exception("Error en encripcion ", e);
		}
	}

	@Override
	public Object decryptMessage(String encrypted) throws Exception {
		Object decrypted = null;
		try {
			instancePrivateCertificate();
			cipher = Cipher.getInstance(cipherForm, provider);
		    cipher.init(Cipher.DECRYPT_MODE, privateKey);
//			SealedObject so = (String) deserialize(encrypted);
//		    decrypted = (MessageParams) so.getObject(cipher);
		    return decrypted;
		}
		catch (Exception e) {
//			LogRegister.get().error(log, "Error en desencripcion ", e);
			throw new Exception("Error en desencripcion ", e);
		}
	}

	public void instancePublicCertificate() throws Exception {
		try {
			File cerFile = new File(publicKeyFilename);
			FileInputStream fis = new FileInputStream(cerFile);
			CertificateFactory cFact = CertificateFactory.getInstance("X.509", "BC");
			Certificate cert = cFact.generateCertificate(fis);
			publicKey = cert.getPublicKey();
			fis.close();
			LogRegister.get().info(log, "Se ha inicializado la llave publica");
		} catch (Exception e) {
//			LogRegister.get().error(log, "Error inicializando llave publica ", e);
			throw new Exception("Error inicializando llave publica ", e);
		}
	}

	public void instancePrivateCertificate() throws Exception {
		FileInputStream fis;
		DataInputStream dis = null;
		try {
			fis = new FileInputStream(new File(privateKeyFilename));
			dis = new DataInputStream(fis);
			byte[] derFile = new byte[dis.available()];
			dis.readFully(derFile);
			KeyFactory kFact = KeyFactory.getInstance("RSA", "BC");
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(derFile);
			privateKey = kFact.generatePrivate(spec);
			dis.close();
			fis.close();
			LogRegister.get().info(log, "Se ha inicializado la llave privada");
		} catch (Exception e) {
//			LogRegister.get().error(log, "Error inicializando llave privada ", e);
			throw new Exception("Error inicializando llave privada ", e);
		}
	}

	public String getProvider() {
		return provider;
	}

	public void setProvider(String provider) {
		this.provider = provider;
	}

	public String getCipherForm() {
		return cipherForm;
	}

	public void setCipherForm(String cipherForm) {
		this.cipherForm = cipherForm;
	}

	public String getPublicKeyFilename() {
		return publicKeyFilename;
	}

	public void setPublicKeyFilename(String publicKeyFilename) {
		this.publicKeyFilename = publicKeyFilename;
	}

	public String getPrivateKeyFilename() {
		return privateKeyFilename;
	}

	public void setPrivateKeyFilename(String privateKeyFilename) {
		this.privateKeyFilename = privateKeyFilename;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public Cipher getCipher() {
		return cipher;
	}

	public void setCipher(Cipher cipher) {
		this.cipher = cipher;
	}

	public static void main(String[] args) {
		System.out.println("XDG..............: " + pcName());
		System.out.println("User name........: " + userName());
		System.out.println("Processor........: " + procesadorInfo());
		System.out.println("Operating System.: " + osInfo());
		System.out.println("JDK version......: " + jdkVersion());
	}

	public static String pcName() {
		return System.getenv("XDG_SESSION_PATH");
	}

	public static String userName() {
		return System.getProperty("user.name");
	}

	public static String procesadorInfo() {
		return System.getenv("PROCESSOR_IDENTIFIER");
	}

	public static String osInfo() {
		return System.getProperty("file.separator");
	}

	public static String jdkVersion() {
		return System.getProperty("java.version");
	}
}

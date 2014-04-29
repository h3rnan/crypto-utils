package cl.utils.crypto.impl;

import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import cl.utils.log.LogRegister;

public class StartDecryptor {

	private static Logger log = LogManager.getLogger(StartDecryptor.class.getName());

	private RSADecryptor rsaDec;
	private AESUtils utils;

	public StartDecryptor(String pathPrivateKey, String secretKeyEnc) {
		//Load encrypt RSA
		try {
			CryptoProviderCertified crypto = new CryptoProviderCertified();
			crypto.setPrivateKeyFilename(pathPrivateKey);
			crypto.instancePrivateCertificate();
			rsaDec = new RSADecryptor((RSAPrivateKey)crypto.getPrivateKey());
			//Decryption RSA
			String hexSecretKey = rsaDec.decryptText(secretKeyEnc);
			byte[] secretKey = Hex.decodeHex(hexSecretKey.toCharArray());
			//Set Secret Key AES
			utils = new AESUtils();
			utils.setSecretKey(secretKey);
		} catch (RSAException e) {
			LogRegister.get().error(log, "Error inicializando desencripción ", e);
		} catch (Exception e) {
			LogRegister.get().error(log, "Error en llave privada", e);
		}
	}

	public String decryptString (String encValue) {
		try {
			byte[] encryptedContent = Hex.decodeHex(encValue.toCharArray());
			byte[] originalContent = utils.decrypt(encryptedContent);
			return new String(originalContent);
		} catch (AESException e){
			LogRegister.get().error(log, "Error en desencrpcion AES, ", e);
		} catch (DecoderException e) {
			LogRegister.get().error(log, "Error en formato del valor encriptado [" + encValue + "]", e);
		}
		return "Error";
	}

	public List<String> decryptStringList(List<String> encList) throws Exception{
		List<String> valueList = new ArrayList<String>();
		for (String encValue : encList) {
			String valueString = decryptString(encValue);
			if (valueString.equals("Error"))
				throw new Exception("Error en formato del valor encriptado [" + encValue + "]");
			valueList.add(valueString);
		}
		return valueList;
	}

}

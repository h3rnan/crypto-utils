package cl.utils.crypto.impl;

import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import cl.utils.log.LogRegister;

public class StartEncryptor {

	private static Logger log = LogManager.getLogger(StartEncryptor.class.getName());

	private AESUtils utils;
	private RSAEncryptor rsaEnc;
	private String secretKeyEnc;

	public StartEncryptor(String pathPublicKey) {
		try {
			//Load encrypt RSA
			CryptoProviderCertified crypto = new CryptoProviderCertified();
			crypto.setPublicKeyFilename(pathPublicKey);
			crypto.instancePublicCertificate();
			rsaEnc = new RSAEncryptor((RSAPublicKey)crypto.getPublicKey());
			//Generate secret Key
			utils = new AESUtils();
			utils.generateSecretKey();
			secretKeyEnc = rsaEnc.encryptString(utils.getSecretyKey());
		} catch (RSAException e) {
			LogRegister.get().error(log, "Error Inicializando encripcion ", e);
		} catch (Exception e) {
			LogRegister.get().error(log, "Error Inicializando encripcion ", e);
		}
	}

	public String encryptString (String valueString) {
		try {
			byte[] valueByte = utils.encrypt(valueString);
			return new String(Hex.encodeHex(valueByte));
		} catch (AESException e){
			LogRegister.get().error(log, "Error de encripcion AES: ", e);
		}
		return "Error";
	}

	public List<String> encryptStringList (List<String> valueList) throws Exception{
		List<String> encList = new ArrayList<String>();
		for (String valueString : valueList) {
			String encValue = encryptString(valueString);
			if (encValue.equals("Error"))
				throw new Exception("Error de encripción con valor [" + valueString + "]");
			encList.add(encValue);
		}
		return encList;
	}

	public String getSecretKeyEnc() {
		return secretKeyEnc;
	}

}

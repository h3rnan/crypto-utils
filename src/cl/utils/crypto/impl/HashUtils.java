package cl.utils.crypto.impl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Hex;

public class HashUtils {

	public static String md5(String string) {
		try {
			MessageDigest digest = java.security.MessageDigest.getInstance("MD5");
			digest.update(string.getBytes());
			byte messageDigest[] = digest.digest();
			return new String(Hex.encodeHex(messageDigest));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return "Error";
	}

	public static String hashCode(String string) {
		String hashCode = Integer.toString(string.hashCode());
		if (hashCode.contains("-")) {
			return hashCode.replace("-", "¡");
		}
		return hashCode;
	}

	public static boolean verifyHashCode(String hash, String string, char convension) {
		String charString = String.valueOf(convension);
		hash = hash.replace(charString, "");
		return hash.equals(hashCode(string));
	}

}

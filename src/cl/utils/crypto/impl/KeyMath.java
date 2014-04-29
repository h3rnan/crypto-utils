package cl.utils.crypto.impl;

import java.math.BigInteger;

/**
 *  Utility class for converting between hexadecimal strings, byte[] and BigInteger
 *
 */
public class KeyMath {

	public static String bigIntToHex(BigInteger bi) {
		int radix = 16;
		return bi.toString(radix);
	}

	public static BigInteger hexToBigInt(String hex) {
		int radix = 16;
		BigInteger bi = new BigInteger(hex, radix);
		return bi;
	}

	public static String bytesToHex(byte[] bytes) {
		BigInteger bi = new BigInteger(bytes);
		return bigIntToHex(bi);
	}

	public static byte[] hexToBytes(String hex) {
		BigInteger bi = hexToBigInt(hex);
		return bi.toByteArray();
	}

	public static void main (String[] args) {

	}

}

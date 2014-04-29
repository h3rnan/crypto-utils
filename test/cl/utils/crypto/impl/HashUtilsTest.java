package cl.utils.crypto.impl;

import junit.framework.TestCase;

public class HashUtilsTest extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
	}

	protected void tearDown() throws Exception {
		super.tearDown();
	}

	public static void testHashCode() {
//		if (args.length <= 0) {
//			args = new String[] {"78965412","78965412"};
//		}
		String[] args = new String[] {"789654111", "789654111", "#", "15"};
		char convension = args[2].charAt(0);
		int longitud = Integer.parseInt(args[3]);

		String hashOut = HashUtils.hashCode(args[0]);

		System.out.println("Entrada: " + args[0] +" | hash: " + hashOut);
		llenarCadena(hashOut, convension, longitud);
		System.out.println("Validando hash con argumento [" + args[1] + "]...");
		if (HashUtils.verifyHashCode(hashOut, args[1], convension))
			System.out.println("Hash corresponde");
			else
				System.out.println("Hash invalido");
	}

	private static void llenarCadena(String hashOut, char convension, int longitud) {
		int longitudIni = hashOut.length();
		for (int i = 0; i < (longitud - longitudIni); i++) {
			hashOut = hashOut + convension;
		}
		System.out.println("Hash ajustado a " + longitud + " caracteres = " + hashOut);
	}
}

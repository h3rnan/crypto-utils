package cl.utils.crypto.impl;
/**
 * DES exception
 *
*/
public class AESException extends Exception {


    /**
	 *
	 */
	private static final long serialVersionUID = 1L;

	public AESException(Exception e) {
		super(e);
	}

	public AESException(String message) {
		super(message);
	}
}

package cl.utils.crypto.impl;


/**
 * RSA Util Exception
 */
public class RSAException extends Exception {

	private static final long serialVersionUID = -4844296213355201538L;

	public RSAException(Exception e) {
		super(e);
	}

	public RSAException(String message) {
		super(message);
	}

}

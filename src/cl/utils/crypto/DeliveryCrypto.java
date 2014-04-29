package cl.utils.crypto;

public interface DeliveryCrypto {

	public String encryptMessage(Object message) throws Exception ;
	public Object decryptMessage(String messageStringCode) throws Exception ;

}

package cl.utils.crypto;

public interface CryptoProvider {

	public byte[] encrypt(String normal) throws Exception ;
	public String decrypt(byte[] encrypted) throws Exception ;

}

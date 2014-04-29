package cl.utils.crypto.impl;

import java.io.FileReader;
import java.io.IOException;
import java.io.LineNumberReader;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

import cl.utils.log.LogRegister;

public class StartDecryptorTest extends TestCase {

	private Logger log = Logger.getLogger(StartDecryptorTest.class.getName());

	public static final String RUTA_LLAVE_PRIVADA = "/home/haja/delivery-certified.der";
	public static final String RUTA_ENTRADA_LIST  = "/home/haja/pruebas/crypto/outEncryptionList.txt";
	public static final String RUTA_ENTRADA_UNO  =  "/home/haja/pruebas/crypto/outEncryptionUno.txt";
	public String messageEnc;
	public String keyEnc;

	protected void setUp() throws Exception {
		super.setUp();
	}

	protected void tearDown() throws Exception {
		super.tearDown();
	}

	public void testDecryptString() {
		String message;
		try {
			readFileLine();
			StartDecryptor dec = new StartDecryptor(RUTA_LLAVE_PRIVADA, keyEnc);
			message = dec.decryptString(messageEnc);
			LogRegister.get().info(log, "------<<Inicia desencriptacion normal>>------");
			LogRegister.get().info(log, "Message Encriptado: " + messageEnc);
			LogRegister.get().info(log, "Message desencriptado: " + message);
			LogRegister.get().info(log, "------<<Fin desencriptacion normal>>------");
		} catch (Exception e) {
			LogRegister.get().error(log , "Ocurrio un error ", e);
		}
	}

	public void testDecryptList() {
		List<String> decList = new ArrayList<String>();
		try {
			List<String> encriptados = readFileList();
			StartDecryptor dec = new StartDecryptor(RUTA_LLAVE_PRIVADA, keyEnc);
			decList = dec.decryptStringList(encriptados);
			LogRegister.get().info(log, "------<<Inicia desencriptacion lista>>------");
			for (int i = 0; i < decList.size(); i++) {
				LogRegister.get().info(log, "Message Encriptado "+ i +": "+ encriptados.get(i));
				LogRegister.get().info(log, "Message Desencriptado "+ i +": "+ decList.get(i));
			}
			LogRegister.get().info(log, "------<<Fin desencriptacion lista>>------");
		} catch (Exception e) {
			LogRegister.get().error(log , "Ocurrio un error ", e);
		}
	}

	//---------------------------------METODOS PARA EL TEST---------------------------------------//

	private void readFileLine() throws IOException {
		keyEnc = null;
		LineNumberReader r = new LineNumberReader(new FileReader(RUTA_ENTRADA_UNO));
		String line = null;
		while ((line = r.readLine()) != null) {
			if (line.startsWith("Mensaje encriptado")) {
				messageEnc = line.substring(20);
			} else if (line.startsWith("Llave encriptada")) {
				keyEnc = line.substring(18);
			}
			System.out.println(r.getLineNumber() + ": " + line);
		}
		r.close();
	}

	private List<String> readFileList() throws IOException {
		keyEnc = null;
		LineNumberReader r = new LineNumberReader(new FileReader(RUTA_ENTRADA_LIST));
		List<String> encList = new ArrayList<String>();
		String line = null;
		while ((line = r.readLine()) != null) {
			if (line.startsWith("Mensaje encriptado")) {
				encList.add(line.substring(22));
			} else if (line.startsWith("Llave encriptada")) {
				keyEnc = line.substring(18);
			}
		}
		r.close();
		return encList;
	}

}

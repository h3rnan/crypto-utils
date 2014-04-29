package cl.utils.crypto.impl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import cl.utils.log.LogRegister;

import junit.framework.TestCase;

public class StartEncryptorTest extends TestCase {

	public static final String RUTA_LLAVE_PUBLICA = "/home/haja/delivery-certified.cer";
	public static final String RUTA_ENTRADA_UNO   = "/home/haja/pruebas/crypto/entradaUno.txt";
	public static final String RUTA_ENTRADA_LIST  = "/home/haja/pruebas/crypto/entradaList.txt";
	public static final String RUTA_SALIDA_LIST   = "/home/haja/pruebas/crypto/outEncryptionList.txt";
	public static final String RUTA_SALIDA_UNO    = "/home/haja/pruebas/crypto/outEncryptionUno.txt";

	private Logger log = Logger.getLogger(StartEncryptorTest.class.getName());

	protected void setUp() throws Exception {
		super.setUp();
	}

	protected void tearDown() throws Exception {
		super.tearDown();
	}

	public void testEncryptString() {
		String message;
		try {
			StartEncryptor enc = new StartEncryptor(RUTA_LLAVE_PUBLICA);
			message = readFiletoString(RUTA_ENTRADA_UNO);
			String messageEnc = "Mensaje encriptado: " + enc.encryptString(message);
			String keyEnc = "Llave encriptada: " + enc.getSecretKeyEnc();
			writeSingleOutText(messageEnc, keyEnc);
			LogRegister.get().info(log, messageEnc);
			LogRegister.get().info(log, keyEnc);
		} catch (Exception e) {
			LogRegister.get().error(log , "Ocurrio un error ", e);
		}
	}

	public void testEncryptStringList() {
		List<String> salida;
		try {
			List<String> entrada = readFiletoList(RUTA_ENTRADA_LIST);
			StartEncryptor enc = new StartEncryptor(RUTA_LLAVE_PUBLICA);
			salida = enc.encryptStringList(entrada);
			for (String stringEnc : salida) {
				String out = stringEnc;
				LogRegister.get().info(log, out);
			}
			String keyEnc = enc.getSecretKeyEnc();
			LogRegister.get().info(log, keyEnc);
			writeListOutText(salida, keyEnc);
		} catch (Exception e) {
			LogRegister.get().error(log , "Ocurrio un error ", e);
		}
	}

//---------------------------------METODOS PARA EL TEST---------------------------------------//

	private void writeSingleOutText(String message, String key) throws IOException{
	    FileWriter fw = new FileWriter(RUTA_SALIDA_UNO);
	    fw.write("------<<Inicia encriptacion>>------" + System.getProperty("line.separator"));
	    fw.write(message + System.getProperty("line.separator"));
	    fw.write(key + System.getProperty("line.separator"));
	    fw.write("------<<Fin encriptacion>>------" + System.getProperty("line.separator"));
	    fw.close();
	}

	private void writeListOutText(List<String> stringList, String key) throws IOException{
	    FileWriter fw = new FileWriter(RUTA_SALIDA_LIST);
	    fw.write("------<<Inicia encriptacion lista>>------" + System.getProperty("line.separator"));
	    for (int i=0; i < stringList.size(); i++) {
	    	String string = stringList.get(i);
		    fw.write("Mensaje encriptado "+i+": "+string + System.getProperty("line.separator"));
		}
	    fw.write("Llave encriptada: " + key + System.getProperty("line.separator"));
	    fw.write("------<<Fin encriptacion lista>>------" + System.getProperty("line.separator"));
	    fw.close();
	}

    private String readFiletoString(String filePath) throws Exception {
        File aFile = new File(filePath);
        StringBuffer contents = new StringBuffer();
        BufferedReader input = null;
        try {
            input = new BufferedReader(new FileReader(aFile));
            String line = null; //not declared within while loop
            while ((line = input.readLine()) != null) {
                contents.append(line);
                contents.append(System.getProperty("line.separator"));
            }
        }
        catch (FileNotFoundException ex) {
            ex.printStackTrace();
        }
        catch (IOException ex) {
            ex.printStackTrace();
        }
        finally {
            try {
                if (input != null) {
                    input.close();
                }
            }
            catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        return contents.toString();
    }

    private List<String> readFiletoList(String filePath) throws Exception {
        File aFile = new File(filePath);
        BufferedReader input = null;
        List<String> salida = new ArrayList<String>();
        try {
            input = new BufferedReader(new FileReader(aFile));
            String line = null; //not declared within while loop
            while ((line = input.readLine()) != null) {
                if (!(line == "" || line == System.getProperty("line.separator"))) salida.add(line);
            }
        }
        catch (FileNotFoundException ex) {
            ex.printStackTrace();
        }
        catch (IOException ex) {
            ex.printStackTrace();
        }
        finally {
            try {
                if (input != null) {
                    input.close();
                }
            }
            catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        return salida;
    }


}

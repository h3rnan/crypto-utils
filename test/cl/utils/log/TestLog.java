package cl.utils.log;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

public class TestLog {

	private static Logger log = LogManager.getLogger(TestLog.class.getName());
	public static void main(String[] args) {
		LogRegister.get().debug(log, "Mensaje de Debug, Mensaje de Debug, Mensaje de Debug, Mensaje de Debug, Mensaje de Debug, Mensaje de Debug");
		LogRegister.get().info(log, "Mensaje de Info, Mensaje de Info, Mensaje de Info, Mensaje de Info, Mensaje de Info, Mensaje de Info");
		LogRegister.get().warnig(log, "Mensaje de Warning, Mensaje de Warning, Mensaje de Warning, Mensaje de Warning, Mensaje de Warning, Mensaje de Warning");
		LogRegister.get().error(log, "Mensaje de error, Mensaje de error, Mensaje de error, Mensaje de error, Mensaje de error, Mensaje de error");
		LogRegister.get().error(log, "Mensaje de fatal, Mensaje de fatal, Mensaje de fatal, Mensaje de fatal, Mensaje de fatal, Mensaje de fatal");
	}

}

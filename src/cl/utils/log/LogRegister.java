package cl.utils.log;

import java.io.IOException;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;


public class LogRegister {

	private Properties properties;

	/** Configuration file name */
	private final static String CONFIG_FILE_NAME = "config/log4j-delivery.properties";

	private LogRegister() {
		this.properties = new Properties();
		try {
			properties.load(LogRegister.class.getClassLoader().getResourceAsStream(CONFIG_FILE_NAME));
			PropertyConfigurator.configure(properties);
		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}//Configuration

	/**
	* Implementando Singleton
	*
	* @return
	*/
	public static LogRegister get() {
		return LogHolder.INSTANCE;
	}

	private static class LogHolder {
		private static final LogRegister INSTANCE = new LogRegister();
	}

	public void debug(Logger log, String message) {
		log.debug(message);
	}

	public void debug(Logger log, String message, Throwable t) {
		log.debug(message, t);
	}

	public void info(Logger log, String message) {
		log.info(message);
	}

	public void info(Logger log, String message, Throwable t) {
		log.info(message, t);
	}

	public void warnig(Logger log, String message) {
		log.warn(message);
	}

	public void warnig(Logger log, String message, Throwable t) {
		log.warn(message, t);
	}

	public void error(Logger log, String message) {
		log.error(message);
	}

	public void error(Logger log, String message, Throwable t) {
		log.error(message, t);
	}

	public void fatal(Logger log, String message) {
		log.fatal(message);
	}

	public void fatal(Logger log, String message, Throwable t) {
		log.fatal(message, t);
	}
}
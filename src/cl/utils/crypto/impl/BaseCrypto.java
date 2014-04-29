package cl.utils.crypto.impl;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * Base class for cryptography.
 */
public abstract class BaseCrypto {

    /**
     * Turns array of bytes into string
     *
     * @param buf Array of bytes to convert to hex string
     * @return Generated hex string
     */
    public static String asHex(byte buf[]) {
        return new String(Hex.encodeHex(buf));
    }

    /**
     * Turns hex stringinto byte array
     *
     * @param hexString Hex string
     * @return  Byte array
     * @throws DecoderException Decoder exception
     */
    public static byte[] asByte(String hexString) throws DecoderException {
        return Hex.decodeHex(hexString.toCharArray());
    }
}

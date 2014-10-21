package com.test;

import org.globalplatform.GPSystem;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/***** From http://en.wikipedia.org/wiki/Hash-based_message_authentication_code:
function hmac (key, message)
    if (length(key) > blocksize) then
        key = hash(key) // keys longer than blocksize are shortened
    end if
    if (length(key) < blocksize) then
        key = key ? [0x00 * (blocksize - length(key))] // keys shorter than blocksize are zero-padded (where ? is concatenation)
    end if
   
    o_key_pad = [0x5c * blocksize] ? key // Where blocksize is that of the underlying hash function
    i_key_pad = [0x36 * blocksize] ? key // Where ? is exclusive or (XOR)
   
    return hash(o_key_pad ? hash(i_key_pad ? message)) // Where ? is concatenation
end function
*****/
public class MacApplet extends Applet {

    // Test Applet AID (A0FFFFFFFF1010) Length
    private static final byte TEST_AID_LENGTH = (byte) 7;

    // CLA for supported commands.
    private static final byte CLA_PROPRIETARY = (byte) 0x80;

    // CLA/INS for personalization commands.
    private static final short CLA_SET_HMAC_KEY = (short) 0x8010;
    private static final short CLA_HMAC_MSG     = (short) 0x8012;

    private static final short BLOCKSIZE = (short) 64;

    private byte MD_TYPE_NONE   = (byte) 0;
    private byte MD_TYPE_SHA    = (byte) 1;
    private byte MD_TYPE_SHA256 = (byte) 2;
    private byte mdType;

    private byte[] keyBuffer;

    private MessageDigest mdSha;
    private MessageDigest mdSha256;

    /**
     * Creates Java Card applet object.
     * 
     * @param array
     *            the byte array containing the AID bytes
     * @param offset
     *            the start of AID bytes in array
     * @param length
     *            the length of the AID bytes in array
     */
    private MacApplet(byte[] array, short offset, byte length) {
        this.keyBuffer = JCSystem.makeTransientByteArray(BLOCKSIZE, JCSystem.CLEAR_ON_DESELECT);
        this.mdSha = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        this.mdSha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        // Register instance AID.
        register(array, (short) (offset + (byte) 1), array[offset]);
    }

    /**
     * Registers applet instance AID by calling constructor.
     * 
     * @param array
     *            the byte array containing the AID bytes
     * @param offset
     *            the start of AID bytes in array
     * @param length
     *            the length of the AID bytes in array
     * @see javacard.framework.Applet.install
     */
    public static final void install(byte[] array, short offset, byte length) {
        new MacApplet(array, offset, length);
    }

    /**
     * Processes incoming APDU command.
     * <p>
     * Supported commands (<b>CLA INS</b>):
     * <ul>
     * <li><b>00 A4</b>: Select
     * <li><b>80 10</b>: Set HMAC Key
     * <li><b>80 12</b>: HMAC Message
     * </ul>
     * 
     * @param apdu
     *            the incoming <code>APDU</code> object
     * @see javacard.framework.Applet.process
     */
    public final void process(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        if (selectingApplet()) {
            // Process Select command.

            // For better security, only allow for first record.
            if (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) != (short) 0x0400) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            // For better security, do not allow partial selection.
            if (apdu.setIncomingAndReceive() != TEST_AID_LENGTH) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            this.mdType = MD_TYPE_NONE;

            return;
        }

        // Get CLA (ignore logical channel bits) and INS.
        byte claByte = (byte) (apduBuffer[ISO7816.OFFSET_CLA] & 0xFC);
        short capduClaIns = (short) (Util.getShort(apduBuffer, ISO7816.OFFSET_CLA) & (short) 0xFCFF);
        switch (capduClaIns) {
        case CLA_SET_HMAC_KEY: {
            // TODO: P2 ignored.

            MessageDigest md = null;
            this.mdType = apduBuffer[ISO7816.OFFSET_P1];
            if (this.mdType == MD_TYPE_SHA) {
                md = this.mdSha;
            }
            else if (this.mdType == MD_TYPE_SHA256) {
                md = this.mdSha256;
            }
            else {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            short keyLength = apdu.setIncomingAndReceive();

            try {
                Util.arrayFillNonAtomic(this.keyBuffer, (short) 0, BLOCKSIZE, (byte) 0);

                if (keyLength > BLOCKSIZE) {
                    md.doFinal(apduBuffer, apdu.getOffsetCdata(), keyLength, this.keyBuffer, (short) 0);
                }
                else {
                    Util.arrayCopyNonAtomic(apduBuffer, apdu.getOffsetCdata(), this.keyBuffer, (short) 0, keyLength);
                }
            }
            catch (Exception e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // Return 0x9000.
            return;
        }
        case CLA_HMAC_MSG: {
            // TODO: P1/P2 ignored.

            MessageDigest md = null;
            if (this.mdType == MD_TYPE_SHA) {
                md = this.mdSha;
            }
            else if (this.mdType == MD_TYPE_SHA256) {
                md = this.mdSha256;
            }
            else {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // TODO: Le ignored.
            short msgLength = apdu.setIncomingAndReceive();

            // NOTE: Assume APDU buffer is at least (255 + 64) bytes.

            // Shift message.
            Util.arrayCopyNonAtomic(apduBuffer, apdu.getOffsetCdata(), 
                                    apduBuffer, BLOCKSIZE, msgLength);

            for (short offset = (short) 0; offset < BLOCKSIZE; offset++) {
                apduBuffer[offset] = (byte) (this.keyBuffer[offset] ^ (byte) 0x36);
            }
            msgLength = md.doFinal(apduBuffer, (short) 0, (short) (BLOCKSIZE + msgLength), 
                                   apduBuffer, BLOCKSIZE);

            for (short offset = (short) 0; offset < BLOCKSIZE; offset++) {
                apduBuffer[offset] = (byte) (this.keyBuffer[offset] ^ (byte) 0x5C);
            }
            msgLength = md.doFinal(apduBuffer, (short) 0, (short) (BLOCKSIZE + msgLength), 
                                   apduBuffer, (short) 0);

            apdu.setOutgoingAndSend((short) 0, msgLength);

            return;
        }
        default:
        }

        // Get CLA byte, ignore logical channels bits.
        if ((claByte == ISO7816.CLA_ISO7816) || 
            (claByte == CLA_PROPRIETARY)) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

}

package com.test;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;

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
/***** From http://tools.ietf.org/html/rfc4493:
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   +                   Algorithm AES-CMAC                              +
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   +                                                                   +
   +   Input    : K    ( 128-bit key )                                 +
   +            : M    ( message to be authenticated )                 +
   +            : len  ( length of the message in octets )             +
   +   Output   : T    ( message authentication code )                 +
   +                                                                   +
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   +   Constants: const_Zero is 0x00000000000000000000000000000000     +
   +              const_Bsize is 16                                    +
   +                                                                   +
   +   Variables: K1, K2 for 128-bit subkeys                           +
   +              M_i is the i-th block (i=1..ceil(len/const_Bsize))   +
   +              M_last is the last block xor-ed with K1 or K2        +
   +              n      for number of blocks to be processed          +
   +              r      for number of octets of last block            +
   +              flag   for denoting if last block is complete or not +
   +                                                                   +
   +   Step 1.  (K1,K2) := Generate_Subkey(K);                         +
   +   Step 2.  n := ceil(len/const_Bsize);                            +
   +   Step 3.  if n = 0                                               +
   +            then                                                   +
   +                 n := 1;                                           +
   +                 flag := false;                                    +
   +            else                                                   +
   +                 if len mod const_Bsize is 0                       +
   +                 then flag := true;                                +
   +                 else flag := false;                               +
   +                                                                   +
   +   Step 4.  if flag is true                                        +
   +            then M_last := M_n XOR K1;                             +
   +            else M_last := padding(M_n) XOR K2;                    +
   +   Step 5.  X := const_Zero;                                       +
   +   Step 6.  for i := 1 to n-1 do                                   +
   +                begin                                              +
   +                  Y := X XOR M_i;                                  +
   +                  X := AES-128(K,Y);                               +
   +                end                                                +
   +            Y := M_last XOR X;                                     +
   +            T := AES-128(K,Y);                                     +
   +   Step 7.  return T;                                              +
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*****/
public class MacApplet extends Applet {

    // Test Applet AID (A0FFFFFFFF1010) Length
    private static final byte TEST_AID_LENGTH = (byte) 7;

    // CLA for supported commands.
    private static final byte CLA_PROPRIETARY = (byte) 0x80;

    // CLA/INS for supported commands.
    private static final short CLAINS_SET_HMAC_KEY = (short) 0x8010;
    private static final short CLAINS_GEN_HMAC     = (short) 0x8012;
    private static final short CLAINS_SET_CMAC_KEY = (short) 0x8020;
    private static final short CLAINS_GEN_CMAC     = (short) 0x8022;

    private static final short BLOCKSIZE = (short) 64;

    private static final short BSIZE = (short) 16;

    private static final byte[] IV_AES = new byte[BSIZE];

    private static final byte MD_TYPE_SHA    = (byte) 1;
    private static final byte MD_TYPE_SHA256 = (byte) 2;

    private byte[] keyBuffer;

    private MessageDigest md;
    private MessageDigest mdSha;
    private MessageDigest mdSha256;

    private AESKey aesKey;

    private byte[] k1;
    private byte[] k2;

    private Cipher aesCipher;

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

        this.aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);

        this.k1 = JCSystem.makeTransientByteArray(BSIZE, JCSystem.CLEAR_ON_DESELECT);
        this.k2 = JCSystem.makeTransientByteArray(BSIZE, JCSystem.CLEAR_ON_DESELECT);

        this.aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

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
     * <li><b>80 12</b>: Generate HMAC
     * <li><b>80 20</b>: Set CMAC Key
     * <li><b>80 22</b>: Generate CMAC
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

            this.md = null;

            // No R-APDU data, just return 0x9000.

            return;
        }

        // Get CLA (ignore logical channel bits) and INS.
        byte claByte = (byte) (apduBuffer[ISO7816.OFFSET_CLA] & 0xFC);
        short capduClaIns = (short) (Util.getShort(apduBuffer, ISO7816.OFFSET_CLA) & (short) 0xFCFF);
        switch (capduClaIns) {
        case CLAINS_SET_HMAC_KEY: {
            // TODO: P2 ignored.

            byte mdType = apduBuffer[ISO7816.OFFSET_P1];
            if (mdType == MD_TYPE_SHA) {
                this.md = this.mdSha;
            }
            else if (mdType == MD_TYPE_SHA256) {
                this.md = this.mdSha256;
            }
            else {
                // Unsupported hash function.
                this.md = null;
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
                // Failed to initialize key.
                this.md = null;
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // No R-APDU data, just return 0x9000.

            return;
        }
        case CLAINS_GEN_HMAC: {
            // TODO: P1/P2 ignored.

            if (this.md == null) {
                // Failed to process Set HMAC Key APDU successfully.
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // TODO: Le ignored.
            short msgLength = apdu.setIncomingAndReceive();

            // NOTE: Assume APDU buffer is at least (255 + 64) bytes.

            try {
                // Shift message.
                Util.arrayCopyNonAtomic(apduBuffer, apdu.getOffsetCdata(), 
                                        apduBuffer, BLOCKSIZE, msgLength);

                // i_key_pad
                for (short offset = (short) 0; offset < BLOCKSIZE; offset++) {
                    apduBuffer[offset] = (byte) (this.keyBuffer[offset] ^ (byte) 0x36);
                }
                // hash(i_key_pad ? message)
                msgLength = this.md.doFinal(apduBuffer, (short) 0, (short) (BLOCKSIZE + msgLength), 
                                            apduBuffer, BLOCKSIZE);

                // o_key_pad
                for (short offset = (short) 0; offset < BLOCKSIZE; offset++) {
                    apduBuffer[offset] = (byte) (this.keyBuffer[offset] ^ (byte) 0x5C);
                }
                // hash(o_key_pad ? hash(i_key_pad ? message))
                msgLength = this.md.doFinal(apduBuffer, (short) 0, (short) (BLOCKSIZE + msgLength), 
                                            apduBuffer, (short) 0);
            }
            catch (Exception e) {
                // Failed to generate HMAC.
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // Return HMAC in R-APDU data.
            apdu.setOutgoingAndSend((short) 0, msgLength);

            return;
        }
        case CLAINS_SET_CMAC_KEY: {
            // TODO: P1/P2 ignored.

            // TODO: Can use Secure Channel to unwrap key.

            this.aesKey.clearKey();

            short keyLength = apdu.setIncomingAndReceive();
            if (keyLength != (short) (this.aesKey.getSize() / 8)) {
                // Incorrect AES key length.
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            try {
                this.aesKey.setKey(apduBuffer, apdu.getOffsetCdata());
            }
            catch (Exception e) {
            }
            if (!this.aesKey.isInitialized()) {
                // Failed to set AES key.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            try {
                // Generate subkeys.
                this.aesCipher.init(this.aesKey, Cipher.MODE_ENCRYPT, IV_AES, (short) 0, (short) IV_AES.length);
                // L [0:15]
                this.aesCipher.doFinal(apduBuffer, (short) 0, 
                                       Util.arrayFillNonAtomic(apduBuffer, (short) 0, (short) 16, (byte) 0), 
                                       apduBuffer, (short) 0);

                boolean msbZero = ((byte) (apduBuffer[0] & (byte) 0x80) != (byte) 0x80);
                byte overflow = (byte) 0;
                // K1
                for (byte offset = (byte) 15; offset >= (byte) 0; offset--) {
                    this.k1[offset] = (byte) (apduBuffer[offset] << (byte) 1);
                    this.k1[offset] |= overflow;
                    overflow = ((byte) (apduBuffer[offset] & (byte) 0x80) == (byte) 0x80) ? (byte) 1 : (byte) 0;
                }
                if (!msbZero) {
                    this.k1[15] ^= (byte) 0x87;
                }

                msbZero = ((byte) (this.k1[0] & (byte) 0x80) != (byte) 0x80);
                overflow = (byte) 0;
                // K2
                for (byte offset = (byte) 15; offset >= (byte) 0; offset--) {
                    this.k2[offset] = (byte) (this.k1[offset] << (byte) 1);
                    this.k2[offset] |= overflow;
                    overflow = ((byte) (this.k1[offset] & (byte) 0x80) == (byte) 0x80) ? (byte) 1 : (byte) 0;
                }
                if (!msbZero) {
                    this.k2[15] ^= (byte) 0x87;
                }
            }
            catch (Exception e) {
                // Failed to generate subkeys.
                this.aesKey.clearKey();
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // No R-APDU data, just return 0x9000.

            // TEST to return subkeys in R-APDU data.
            /*
            apdu.setOutgoingAndSend((short) 0, 
                                    Util.arrayCopyNonAtomic(this.k2, (short) 0, 
                                                            apduBuffer, Util.arrayCopyNonAtomic(this.k1, (short) 0, 
                                                                                                apduBuffer, (short) 0, (short) k1.length), 
                                                            (short) k2.length));
            */

            return;
        }
        case CLAINS_GEN_CMAC: {
            // TODO: P1/P2 ignored.

            if (!this.aesKey.isInitialized()) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // TODO: Le ignored.
            short msgLength = apdu.setIncomingAndReceive();

            try {
                boolean flag = false;
                short n = (short) ((msgLength + 15) / 16);
                if (n == (short) 0) {
                    n = (short) 1;

                    // Pad message.
                    msgLength = Util.arrayFillNonAtomic(apduBuffer, (short) 0, BSIZE, (byte) 0);
                    apduBuffer[0] = (byte) 0x80;
                }
                else {
                    // Shift message.
                    Util.arrayCopyNonAtomic(apduBuffer, apdu.getOffsetCdata(), apduBuffer, (short) 0, msgLength);

                    byte padBytes = (byte) (msgLength % 16);
                    if (padBytes == (byte) 0) {
                        flag = true;
                    }
                    else {
                        // Pad message.
                        apduBuffer[msgLength++] = (byte) 0x80;
                        padBytes = (byte) (15 - padBytes);
                        if (padBytes > (byte) 0) {
                            msgLength = Util.arrayFillNonAtomic(apduBuffer, msgLength, padBytes, (byte) 0);
                        }
                    }
                }

                short msgOffset = (short) ((n - 1) * BSIZE);
                for (byte offset = (byte) 0; offset < BSIZE; offset++) {
                    if (flag) {
                        apduBuffer[(short) (msgOffset + offset)] ^= this.k1[offset];
                    }
                    else {
                        apduBuffer[(short) (msgOffset + offset)] ^= this.k2[offset];
                    }
                }

                this.aesCipher.init(this.aesKey, Cipher.MODE_ENCRYPT, IV_AES, (short) 0, (short) IV_AES.length);
                msgLength = this.aesCipher.doFinal(apduBuffer, (short) 0, msgLength, apduBuffer, (short) 0);
            }
            catch (Exception e) {
                // Failed to generate CMAC.
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // Return CMAC in R-APDU data.
            apdu.setOutgoingAndSend((short) (msgLength - BSIZE), BSIZE);

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

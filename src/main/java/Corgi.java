import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;


public class Corgi {

    public static byte[] calculateMFCMAC(byte[] key, byte[] valueToMAC) {
        try {
            int cmacSize = 16;
            BlockCipher cipher = new AESFastEngine();
            Mac cmac = new CMac(cipher, cmacSize * 8);
            KeyParameter keyParameter = new KeyParameter(key);
            cmac.init(keyParameter);
            cmac.update(valueToMAC, 0, valueToMAC.length);
            byte[] CMAC = new byte[cmacSize];
            cmac.doFinal(CMAC, 0);
            byte[] MFCMAC = new byte[cmacSize / 2];
            int j = 0;
            for (int i = 0; i < CMAC.length; i++) {
                if (i % 2 != 0) {
                    MFCMAC[j] = CMAC[i];
                    j += 1;
                }
            }
            return MFCMAC;

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static byte[] CalculationMac(byte[] key, byte[] valueToMAC)
    {
        int cmacSize = 16;
        BlockCipher cipher = new AESFastEngine();
        Mac cmac = new CMac(cipher, cmacSize * 8);
        KeyParameter keyParameter = new KeyParameter(key);
        cmac.init(keyParameter);
        cmac.update(valueToMAC, 0, valueToMAC.length);
        byte[] CMAC = new byte[cmacSize];
        cmac.doFinal(CMAC, 0);
        return CMAC;
    }

    public static byte[] CalMac(byte[] key, byte[] msg)
    {
        CipherParameters params = new KeyParameter(key);
        BlockCipher aes = new AESEngine();
        CMac mac = new CMac(aes);
        mac.init(params);
        mac.update(msg, 0, msg.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

}

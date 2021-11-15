import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.Key;

public class MyClass {

    public static void main(String[] args) throws DecoderException {
//        String test = "hello world";
//        char[] result = Hex.encodeHex(test.getBytes());
//        System.out.println("edcode HEX:" + new String(result));
//        System.out.println("encodeStr:" + Hex.encodeHexString(test.getBytes()));

        //key1
        String keyHexString = "0102030405060708090A0B0C0D0E0F10";

//        //ascii
//        String piccData32 = "4132393041313842363145443536424338363746303646363739333435433236";
//
//        char[] piccChars = piccData32.toCharArray();
//
//        StringBuffer piccHexBuilder = new StringBuffer();
//
//        for (int i = 0; i < piccChars.length; i += 2) {
//            StringBuffer bb = new StringBuffer()
//                    .append(piccChars[i])
//                    .append(piccChars[i + 1]);
//            int charValue = Integer.valueOf(bb.toString());
//            System.out.println("charValue INT:" + charValue);
//            piccHexBuilder.append(Integer.toHexString(charValue));
//        }
//        System.out.println(piccHexBuilder);

        String picc="DA8CE35F108EC158A6276F17A125E21E";

        byte[] piccByte = Hex.decodeHex(picc);

        String ivStr="00000000000000000000000000000000";

        try {
            SecretKeySpec keySpec = new SecretKeySpec(Hex.decodeHex(keyHexString), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            IvParameterSpec ips = new IvParameterSpec(Hex.decodeHex(ivStr));
            cipher.init(Cipher.DECRYPT_MODE, keySpec,ips);
            byte[] resultDes = cipher.doFinal(piccByte);
            ByteBuffer byteBuffer=ByteBuffer.allocate(resultDes.length);
            byteBuffer.put(resultDes);
            System.out.println(Hex.encodeHexString(resultDes).toUpperCase());
            byte[] Tag=new byte[1];
            byte[] UID=new byte[7];
            byte[] Counter=new byte[3];
            byteBuffer.get(0,Tag);
            byteBuffer.get(1,UID);
            byteBuffer.get(7,Counter);
            System.out.println("TagData:"+Hex.encodeHexString(Tag).toUpperCase());
            //System.out.println("TagData:"+Hex.encodeHexString(byteBuffer.).toUpperCase());
            System.out.println("UID:"+Hex.encodeHexString(UID).toUpperCase());
            System.out.println("Counter:"+Hex.encodeHexString(Counter).toUpperCase());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

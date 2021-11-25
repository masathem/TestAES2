import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Scanner;
import java.util.regex.*;


public class DecryptENCFIleData {

    public static void main(String[] args) throws DecoderException, IOException {
//        String test = "hello world";
//        char[] result = Hex.encodeHex(test.getBytes());
//        System.out.println("edcode HEX:" + new String(result));
//        System.out.println("encodeStr:" + Hex.encodeHexString(test.getBytes()));
        //key1
//        String keyHexString = "0102030405060708090A0B0C0D0E0F10";
        String keyHexString = "00000000000000000000000000000000";

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


//        Scanner scanner = new Scanner(System.in);
//
//        System.out.println("please input picc Data 16/Hex String:");
//        String piccData16 = scanner.nextLine();
        String piccData16="FDE4AFA99B5C820A2C1BB0F1C792D0EB";
        String picc = piccData16;
//        String piccData16="4441384345333546313038454331353841363237364631374131323545323145";

        Pattern regex = Pattern.compile("(A|B|C|D|E|F)");
        Matcher regexMatcher = regex.matcher(piccData16);
        if (!regexMatcher.find()) {
            // Successful match
            picc = HexStringUtil.hexString2Str(piccData16);
        }
        System.out.println("input is:" + picc);
//        String picc="DA8CE35F108EC158A6276F17A125E21E";

        byte[] piccByte = Hex.decodeHex(picc);

        String ivStr = "00000000000000000000000000000000";

        try {
            SecretKeySpec keySpec = new SecretKeySpec(Hex.decodeHex(keyHexString), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            IvParameterSpec ips = new IvParameterSpec(Hex.decodeHex(ivStr));
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ips);
            byte[] resultDes = cipher.doFinal(piccByte);
            ByteBuffer byteBuffer = ByteBuffer.allocate(resultDes.length);
            byteBuffer.put(resultDes);
            System.out.println(Hex.encodeHexString(resultDes).toUpperCase());
            byte[] Tag = new byte[1];
            byte[] UID = new byte[7];
            byte[] Counter = new byte[3];
            byteBuffer.get(0, Tag);
            byteBuffer.get(1, UID);
            byteBuffer.get(8, Counter);
            System.out.println("TagData:" + Hex.encodeHexString(Tag).toUpperCase());
            //System.out.println("TagData:"+Hex.encodeHexString(byteBuffer.).toUpperCase());
            System.out.println("UID:" + Hex.encodeHexString(UID).toUpperCase());
            System.out.println("Counter:" + Hex.encodeHexString(Counter).toUpperCase());

            String sv1 = "C33C00010080" + Hex.encodeHexString(UID).toUpperCase() + Hex.encodeHexString(Counter).toUpperCase();
            System.out.println("sv1:"+sv1);
            String KSes = MacFormat(keyHexString, sv1);
            System.out.println("kes:" + KSes);
            String Ive = IVe(KSes, ivStr, Hex.encodeHexString(Counter).toUpperCase() + "0000000000000");
            System.out.println("IVE:" + Ive);
            //decrypt final


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String IVe(String kSes, String ivrS, String toUpperCase) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(Hex.decodeHex(kSes), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        IvParameterSpec ips = new IvParameterSpec(Hex.decodeHex(ivrS));
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ips);
        byte[] resultDes = cipher.doFinal(toUpperCase.getBytes());
        return Hex.encodeHexString(resultDes);
    }

    private static String MacFormat(String keyHexString, String sv1) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(Hex.decodeHex(keyHexString), "HmacMD5");
        Mac mac = Mac.getInstance(keySpec.getAlgorithm());
        mac.init(keySpec);
        byte[] resultBytes = mac.doFinal(sv1.getBytes());
        return Hex.encodeHexString(resultBytes);
    }


    public class HexStringUtil {


        private static String hexCharsStr = "0123456789ABCDEF";


        private static char[] hexCharsArr = hexCharsStr.toCharArray();

        /**
         * 0123456789ABCDEF -> 0 ~ 15
         */
        private static byte oneHexChar2Byte(char c) {
            byte b = (byte) hexCharsStr.indexOf(c);
            return b;
        }

        /**
         * 0 ~ 15 -> 0123456789ABCDEF
         */
        private static char byte2OneHexChar(byte b) {
            char c = hexCharsArr[b];
            return c;
        }

        /**
         *
         */
        private static byte twoHexChar2Byte(char high, char low) {
            byte b = (byte) (oneHexChar2Byte(high) << 4 | oneHexChar2Byte(low));
            return b;
        }

        /**
         *
         */
        private static char[] byte2TwoHexChar(byte b) {
            char[] chars = new char[2];


            byte high4bit = (byte) ((b & 0x0f0) >> 4);
            chars[0] = byte2OneHexChar((byte) high4bit);


            byte low4bit = (byte) (b & 0x0f);
            chars[1] = byte2OneHexChar((byte) low4bit);

            return chars;
        }

        /**
         *
         */
        public static String str2HexString(String str) {
            byte[] bytes = str.getBytes();
            return bytes2HexString(bytes);
        }

        /**
         *
         */
        public static final String bytes2HexString(byte[] bytes) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                char[] chars = byte2TwoHexChar(bytes[i]);
                sb.append(new String(chars));
            }
            return sb.toString();
        }

        /**
         *
         */
        public static String hexString2Str(String hexStr) {
            byte[] bytes = hexString2Bytes(hexStr);
            return new String(bytes);
        }

        /**
         *
         */
        public static byte[] hexString2Bytes(String hexStr) {
            int length = (hexStr.length() / 2);
            byte[] bytes = new byte[length];
            char[] charArr = hexStr.toCharArray();
            for (int i = 0; i < length; i++) {
                int position = i * 2;
                bytes[i] = twoHexChar2Byte(charArr[position], charArr[position + 1]);
            }
            return bytes;
        }

    }
}

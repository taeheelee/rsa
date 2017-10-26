package kr.co.mobidoo;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

//https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
//Cipher.getInstance 첫번째 인자 의미
/*
Parameters:
transformation - the name of the transformation, e.g., DES/CBC/PKCS5Padding. See the Cipher section in the Java Cryptography Architecture Standard Algorithm Name Documentation for information about standard transformation names.
 Cipher Algorithm Names/Cipher Algorithm Modes/Cipher Algorithm Padding
 provider - the name of the provider.

provider 관련
https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html
*/

//https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher
//http://stackoverflow.com/questions/7348224/generating-constant-rsa-keys-java

/*
Sample Result

pubKeyHex:30820122300d06092a864886f70d01010105000382010f003082010a02820101009852cfb349e4c63501ea5124b62bd96fac2e46a4cbc08745f8ef446e495433ecf55619fcff9e57f00a2ea19a6955598cfde5a9ebd0c04be9e4102c25dfa8e7538c1b7f4697ee8811fa15e76b60767d08e61d3dbf713f33c90fd0584e5b7808fcdfcce1b4fc8eec983dbdc9ee4a02b6564a8abdc1abddc0db7b320f697434ddbc5bc789636083c79e8f1a05c6c8d5c4c75a7fc2473de0ca84c41d8ed9416f5e8a8d87cab787950347b1392ecb87d7732b9f382308211f9a31f6b17611ab273e896e862b42aec7d1bea4a0b08a26d91244900aaeba172ed5dc48f985ad1a980148ce20b06d4f9fdcd2437a16ab6e93411aad1885bc3675fe563a654ee547e3433f0203010001
inputText:암호화된 문자열 abcdefg hijklmn
inputHex:(31):becfc8a3c8adb5c820b9aec0dabfad20616263646566672068696a6b6c6d6e
cipherHex:(256):74e199ec8b1d1845a7569622a43500598bab5b194b44915da91929aa2007564cbe8ac4e996ead6b3cdc337603c4a031e18471e35efd3d8e49590e3269ba2254c095bc6c0c38ca113b7760b7ea792f3fa1bb3b5560d918f81b48e189da29c369fffac7e7b4e722de70e87b719d827c380cbec1cd446c1f81084a7429f627443580943937f46af78d1e76b83fc26e2b1010a70cfcf396dfa76f0edfbee9c3515efcc1c803798411a54c83e35f60b1089626a4c6106a355b27e86d56d06447186b33b2884f8e73986cc5c44bf2a00ddab7c3fdb1138c3e86208ec7ed5210d18bd97bed15653f76ca7ddae2acf4d338cfd8bcd91fe18d94ca4fed5759dc7f1f0ec79
*/

// 공개키와 평문을 이용하여 암호화하는 모듈
public class RSAEncrypter {

//    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//        Cipher cipher = Cipher.getInstance("RSACrypto/ECB/PKCS1PADDING", "SunJCE");
//        String pubKeyStr = "30820122300d06092a864886f70d01010105000382010f003082010a02820101009852cfb349e4c63501ea5124b62bd96fac2e46a4cbc08745f8ef446e495433ecf55619fcff9e57f00a2ea19a6955598cfde5a9ebd0c04be9e4102c25dfa8e7538c1b7f4697ee8811fa15e76b60767d08e61d3dbf713f33c90fd0584e5b7808fcdfcce1b4fc8eec983dbdc9ee4a02b6564a8abdc1abddc0db7b320f697434ddbc5bc789636083c79e8f1a05c6c8d5c4c75a7fc2473de0ca84c41d8ed9416f5e8a8d87cab787950347b1392ecb87d7732b9f382308211f9a31f6b17611ab273e896e862b42aec7d1bea4a0b08a26d91244900aaeba172ed5dc48f985ad1a980148ce20b06d4f9fdcd2437a16ab6e93411aad1885bc3675fe563a654ee547e3433f0203010001";
//
//        // Turn the encoded key into a real RSACrypto public key.
//        // Public keys are encoded in X.509.
//        X509EncodedKeySpec ukeySpec = new X509EncodedKeySpec(hexToByteArray(pubKeyStr));
//        KeyFactory ukeyFactory = KeyFactory.getInstance("RSACrypto");
//        PublicKey publicKey = null;
//        try {
//            publicKey = ukeyFactory.generatePublic(ukeySpec);
//            System.out.println("pubKeyHex:"+byteArrayToHex(publicKey.getEncoded()));
//        } catch (InvalidKeySpecException e) {
//            e.printStackTrace();
//        }
//
//        // 공개키를 전달하여 암호화
//        byte[] input = "암호화된 문자열 abcdefg hijklmn".getBytes();
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] cipherText = cipher.doFinal(input);
//        System.out.println("inputText:"+new String(input));
//        System.out.println("inputHex:("+ input.length +"):"+byteArrayToHex(input));
//        System.out.println("cipherHex:("+ cipherText.length +"):"+byteArrayToHex(cipherText));
//    }

    /**
     * @param input,
     * @param pubKeyStr
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] encrypt(String input, String pubKeyStr) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSACrypto/ECB/PKCS1PADDING", "SunJCE");

        // Turn the encoded key into a real RSACrypto public key.
        // Public keys are encoded in X.509.
        X509EncodedKeySpec ukeySpec = new X509EncodedKeySpec(hexToByteArray(pubKeyStr)); //일단 X.509 인코딩
        KeyFactory ukeyFactory = KeyFactory.getInstance("RSACrypto");
        PublicKey publicKey = null;

        try {
            publicKey = ukeyFactory.generatePublic(ukeySpec);
            System.out.println("pubKeyHex:"+byteArrayToHex(publicKey.getEncoded()));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        // 공개키를 전달하여 암호화
        byte[] inputByte = input.getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(inputByte);
        System.out.println("inputText:"+new String(inputByte));
        System.out.println("inputHex:("+ inputByte.length +"):"+byteArrayToHex(inputByte));
        System.out.println("cipherHex:("+ cipherText.length +"):"+byteArrayToHex(cipherText));

        return cipherText; // 공개키로 암호화한 데이터 반환
    }



    // hex string to byte[]
    public static byte[] hexToByteArray(String hex) {
        if (hex == null || hex.length() == 0) {
            return null;
        }
        byte[] ba = new byte[hex.length() / 2];
        for (int i = 0; i < ba.length; i++) {
            ba[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return ba;
    }

    // byte[] to hex sting
    public static String byteArrayToHex(byte[] ba) {
        if (ba == null || ba.length == 0) {
            return null;
        }
        StringBuffer sb = new StringBuffer(ba.length * 2);
        String hexNumber;
        for (int x = 0; x < ba.length; x++) {
            hexNumber = "0" + Integer.toHexString(0xff & ba[x]);

            sb.append(hexNumber.substring(hexNumber.length() - 2));
        }
        return sb.toString();
    }
}

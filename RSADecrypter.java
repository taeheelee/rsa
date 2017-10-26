package kr.co.mobidoo;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
Sample Result

privKeyHex:308204bd020100300d06092a864886f70d0101010500048204a7308204a302010002820101009852cfb349e4c63501ea5124b62bd96fac2e46a4cbc08745f8ef446e495433ecf55619fcff9e57f00a2ea19a6955598cfde5a9ebd0c04be9e4102c25dfa8e7538c1b7f4697ee8811fa15e76b60767d08e61d3dbf713f33c90fd0584e5b7808fcdfcce1b4fc8eec983dbdc9ee4a02b6564a8abdc1abddc0db7b320f697434ddbc5bc789636083c79e8f1a05c6c8d5c4c75a7fc2473de0ca84c41d8ed9416f5e8a8d87cab787950347b1392ecb87d7732b9f382308211f9a31f6b17611ab273e896e862b42aec7d1bea4a0b08a26d91244900aaeba172ed5dc48f985ad1a980148ce20b06d4f9fdcd2437a16ab6e93411aad1885bc3675fe563a654ee547e3433f02030100010282010019070239631ac3b651ea3e0ada23ba462ef42b8748330a06e52feafe73edf1da2d35486fd9501b02c5a983c3eb2aaadc0f9b7c9fd25cc61c57ec905468bb47c6e26e622b272b7a0ffa173f3ed54aa2a0a3ae8a46ba44b82d80fbaa86b560b39958ec40e98bd5afea13baeb42cbc6464f4750247d7dcfa1b06e3d7b6ac83d27715a7987731f44c7d8109d6fa10425bc7a13347331a7d9f9629a4a2ff0ccb6270f8a8ae6a05ad92354c364e79837c0613c5375d476bc9291b24b1067439fbda1ba387589064cf1a0b050f1f8db7d5313bc6697c0e0736876847631ad7101263ae9a0f2f4738f297fcb55357c5d70518138c75e3be0ddd68cf6444b31c5cacf918102818100ca8a99d468aec849d1488fe032059d8ff1167c9278b3b8822bae8cb87191d3cfa4ae6e20493300bc7930e9dbb94197bee93f595cc32d9d037aebc868147a37cfcc788cf37d4187e3e040afd08f33a992ee73fa6162286ca5b6d1ad8a984554bc30f3491de3ee47e68eb2d08a1b09a99694bcd799df3af47285d4289fbd66ab8b02818100c08710bb50462ef44d793482d68eb63f06ed1d3d725b1154abe8de7db4b153d1b1d33f69f151b2550b4c18e15e2ac1419d936aa789d94e16989e10163668859665327b084cb9510922a80b0e45844a467f41520304b1bab05f6b1612f25d6b204d60a097fd1239835c8262f852cd4396264404e234706a9550defc067a620d9d0281804f7fefb98c0d6ed86aa94caff77274d21713787a159e9581a29bb4e880cb78943c53ab2e490d17f0e2b0ec5a2e712c9ae6fad29cb28fa8ddc0d5e3a7d6c1d23e6247bf2ba3b2a12034d9af28f1cc9976eed9df217261e3a3780afd4f354da160ece5d1814602357eadec4a26ab4e339ec36b0c457d75aa95792a3977d9e3fed902818100b2280a169b78e698515cb877de5d9f4d8176479985c9b9a6d5919ed94a2cd1b878ca57a30c9921e1ca9b77668d021965439097a04352600d4edaed5df0a915fd0ed600bdb469c410250ec5744665dd6990f67c12a8f462223599dd8a58d6937c07be43bd8184accddefc14e35f93ec57f43efb19eb969f3a5ee488e8e1b4fc8d02818010fff11dd0b121624e7b324001972652db00fe2d45fe98c80cac0e25e9e814b1c1f7373d939641a3a03529020c94e4e34471efaab5ccc23093f15d9c2202185a38af3df95e5adff66bcf29c22a1699ab46b00bc6b885f12e77a371a51e9a2228fac2369f52d5d2d27873e56e86a1f2dd0c5c5d67d9241592a876d06c78a13fcc
plainText:암호화된 문자열 abcdefg hijklmn
 */

//전달된 암호문과 가지고 있는 개인키를 이용하여 복호화하는 모듈
public class RSADecrypter {

    /**
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
//    public static void main(String[] args) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
//        String privKeyStr = "308204bd020100300d06092a864886f70d0101010500048204a7308204a302010002820101009852cfb349e4c63501ea5124b62bd96fac2e46a4cbc08745f8ef446e495433ecf55619fcff9e57f00a2ea19a6955598cfde5a9ebd0c04be9e4102c25dfa8e7538c1b7f4697ee8811fa15e76b60767d08e61d3dbf713f33c90fd0584e5b7808fcdfcce1b4fc8eec983dbdc9ee4a02b6564a8abdc1abddc0db7b320f697434ddbc5bc789636083c79e8f1a05c6c8d5c4c75a7fc2473de0ca84c41d8ed9416f5e8a8d87cab787950347b1392ecb87d7732b9f382308211f9a31f6b17611ab273e896e862b42aec7d1bea4a0b08a26d91244900aaeba172ed5dc48f985ad1a980148ce20b06d4f9fdcd2437a16ab6e93411aad1885bc3675fe563a654ee547e3433f02030100010282010019070239631ac3b651ea3e0ada23ba462ef42b8748330a06e52feafe73edf1da2d35486fd9501b02c5a983c3eb2aaadc0f9b7c9fd25cc61c57ec905468bb47c6e26e622b272b7a0ffa173f3ed54aa2a0a3ae8a46ba44b82d80fbaa86b560b39958ec40e98bd5afea13baeb42cbc6464f4750247d7dcfa1b06e3d7b6ac83d27715a7987731f44c7d8109d6fa10425bc7a13347331a7d9f9629a4a2ff0ccb6270f8a8ae6a05ad92354c364e79837c0613c5375d476bc9291b24b1067439fbda1ba387589064cf1a0b050f1f8db7d5313bc6697c0e0736876847631ad7101263ae9a0f2f4738f297fcb55357c5d70518138c75e3be0ddd68cf6444b31c5cacf918102818100ca8a99d468aec849d1488fe032059d8ff1167c9278b3b8822bae8cb87191d3cfa4ae6e20493300bc7930e9dbb94197bee93f595cc32d9d037aebc868147a37cfcc788cf37d4187e3e040afd08f33a992ee73fa6162286ca5b6d1ad8a984554bc30f3491de3ee47e68eb2d08a1b09a99694bcd799df3af47285d4289fbd66ab8b02818100c08710bb50462ef44d793482d68eb63f06ed1d3d725b1154abe8de7db4b153d1b1d33f69f151b2550b4c18e15e2ac1419d936aa789d94e16989e10163668859665327b084cb9510922a80b0e45844a467f41520304b1bab05f6b1612f25d6b204d60a097fd1239835c8262f852cd4396264404e234706a9550defc067a620d9d0281804f7fefb98c0d6ed86aa94caff77274d21713787a159e9581a29bb4e880cb78943c53ab2e490d17f0e2b0ec5a2e712c9ae6fad29cb28fa8ddc0d5e3a7d6c1d23e6247bf2ba3b2a12034d9af28f1cc9976eed9df217261e3a3780afd4f354da160ece5d1814602357eadec4a26ab4e339ec36b0c457d75aa95792a3977d9e3fed902818100b2280a169b78e698515cb877de5d9f4d8176479985c9b9a6d5919ed94a2cd1b878ca57a30c9921e1ca9b77668d021965439097a04352600d4edaed5df0a915fd0ed600bdb469c410250ec5744665dd6990f67c12a8f462223599dd8a58d6937c07be43bd8184accddefc14e35f93ec57f43efb19eb969f3a5ee488e8e1b4fc8d02818010fff11dd0b121624e7b324001972652db00fe2d45fe98c80cac0e25e9e814b1c1f7373d939641a3a03529020c94e4e34471efaab5ccc23093f15d9c2202185a38af3df95e5adff66bcf29c22a1699ab46b00bc6b885f12e77a371a51e9a2228fac2369f52d5d2d27873e56e86a1f2dd0c5c5d67d9241592a876d06c78a13fcc";
//        String cipherText = "74e199ec8b1d1845a7569622a43500598bab5b194b44915da91929aa2007564cbe8ac4e996ead6b3cdc337603c4a031e18471e35efd3d8e49590e3269ba2254c095bc6c0c38ca113b7760b7ea792f3fa1bb3b5560d918f81b48e189da29c369fffac7e7b4e722de70e87b719d827c380cbec1cd446c1f81084a7429f627443580943937f46af78d1e76b83fc26e2b1010a70cfcf396dfa76f0edfbee9c3515efcc1c803798411a54c83e35f60b1089626a4c6106a355b27e86d56d06447186b33b2884f8e73986cc5c44bf2a00ddab7c3fdb1138c3e86208ec7ed5210d18bd97bed15653f76ca7ddae2acf4d338cfd8bcd91fe18d94ca4fed5759dc7f1f0ec79";
//        Cipher cipher = Cipher.getInstance("RSACrypto/ECB/PKCS1PADDING", "SunJCE");
//        // Turn the encoded key into a real RSACrypto private key.
//        // Private keys are encoded in PKCS#8.
//        PKCS8EncodedKeySpec rkeySpec = new PKCS8EncodedKeySpec(hexToByteArray(privKeyStr));
//        KeyFactory rkeyFactory = KeyFactory.getInstance("RSACrypto");
//        PrivateKey privateKey = null;
//        try {
//            privateKey = rkeyFactory.generatePrivate(rkeySpec);
//            System.out.println("privKeyHex:"+byteArrayToHex(privateKey.getEncoded()));
//        } catch (InvalidKeySpecException e) {
//            e.printStackTrace();
//        }
//
//        // 개인키를 가지고있는쪽에서 복호화
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        byte[] plainText = cipher.doFinal(hexToByteArray(cipherText));
//        System.out.println("plainText:" + new String(plainText));
//    }

    public static byte[] decrypt(String privKeyStr, String cipherText) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
//        String privKeyStr = "308204bd020100300d06092a864886f70d0101010500048204a7308204a302010002820101009852cfb349e4c63501ea5124b62bd96fac2e46a4cbc08745f8ef446e495433ecf55619fcff9e57f00a2ea19a6955598cfde5a9ebd0c04be9e4102c25dfa8e7538c1b7f4697ee8811fa15e76b60767d08e61d3dbf713f33c90fd0584e5b7808fcdfcce1b4fc8eec983dbdc9ee4a02b6564a8abdc1abddc0db7b320f697434ddbc5bc789636083c79e8f1a05c6c8d5c4c75a7fc2473de0ca84c41d8ed9416f5e8a8d87cab787950347b1392ecb87d7732b9f382308211f9a31f6b17611ab273e896e862b42aec7d1bea4a0b08a26d91244900aaeba172ed5dc48f985ad1a980148ce20b06d4f9fdcd2437a16ab6e93411aad1885bc3675fe563a654ee547e3433f02030100010282010019070239631ac3b651ea3e0ada23ba462ef42b8748330a06e52feafe73edf1da2d35486fd9501b02c5a983c3eb2aaadc0f9b7c9fd25cc61c57ec905468bb47c6e26e622b272b7a0ffa173f3ed54aa2a0a3ae8a46ba44b82d80fbaa86b560b39958ec40e98bd5afea13baeb42cbc6464f4750247d7dcfa1b06e3d7b6ac83d27715a7987731f44c7d8109d6fa10425bc7a13347331a7d9f9629a4a2ff0ccb6270f8a8ae6a05ad92354c364e79837c0613c5375d476bc9291b24b1067439fbda1ba387589064cf1a0b050f1f8db7d5313bc6697c0e0736876847631ad7101263ae9a0f2f4738f297fcb55357c5d70518138c75e3be0ddd68cf6444b31c5cacf918102818100ca8a99d468aec849d1488fe032059d8ff1167c9278b3b8822bae8cb87191d3cfa4ae6e20493300bc7930e9dbb94197bee93f595cc32d9d037aebc868147a37cfcc788cf37d4187e3e040afd08f33a992ee73fa6162286ca5b6d1ad8a984554bc30f3491de3ee47e68eb2d08a1b09a99694bcd799df3af47285d4289fbd66ab8b02818100c08710bb50462ef44d793482d68eb63f06ed1d3d725b1154abe8de7db4b153d1b1d33f69f151b2550b4c18e15e2ac1419d936aa789d94e16989e10163668859665327b084cb9510922a80b0e45844a467f41520304b1bab05f6b1612f25d6b204d60a097fd1239835c8262f852cd4396264404e234706a9550defc067a620d9d0281804f7fefb98c0d6ed86aa94caff77274d21713787a159e9581a29bb4e880cb78943c53ab2e490d17f0e2b0ec5a2e712c9ae6fad29cb28fa8ddc0d5e3a7d6c1d23e6247bf2ba3b2a12034d9af28f1cc9976eed9df217261e3a3780afd4f354da160ece5d1814602357eadec4a26ab4e339ec36b0c457d75aa95792a3977d9e3fed902818100b2280a169b78e698515cb877de5d9f4d8176479985c9b9a6d5919ed94a2cd1b878ca57a30c9921e1ca9b77668d021965439097a04352600d4edaed5df0a915fd0ed600bdb469c410250ec5744665dd6990f67c12a8f462223599dd8a58d6937c07be43bd8184accddefc14e35f93ec57f43efb19eb969f3a5ee488e8e1b4fc8d02818010fff11dd0b121624e7b324001972652db00fe2d45fe98c80cac0e25e9e814b1c1f7373d939641a3a03529020c94e4e34471efaab5ccc23093f15d9c2202185a38af3df95e5adff66bcf29c22a1699ab46b00bc6b885f12e77a371a51e9a2228fac2369f52d5d2d27873e56e86a1f2dd0c5c5d67d9241592a876d06c78a13fcc";
//        String cipherText = "74e199ec8b1d1845a7569622a43500598bab5b194b44915da91929aa2007564cbe8ac4e996ead6b3cdc337603c4a031e18471e35efd3d8e49590e3269ba2254c095bc6c0c38ca113b7760b7ea792f3fa1bb3b5560d918f81b48e189da29c369fffac7e7b4e722de70e87b719d827c380cbec1cd446c1f81084a7429f627443580943937f46af78d1e76b83fc26e2b1010a70cfcf396dfa76f0edfbee9c3515efcc1c803798411a54c83e35f60b1089626a4c6106a355b27e86d56d06447186b33b2884f8e73986cc5c44bf2a00ddab7c3fdb1138c3e86208ec7ed5210d18bd97bed15653f76ca7ddae2acf4d338cfd8bcd91fe18d94ca4fed5759dc7f1f0ec79";
        Cipher cipher = Cipher.getInstance("RSACrypto/ECB/PKCS1PADDING", "SunJCE");
        // Turn the encoded key into a real RSACrypto private key.
        // Private keys are encoded in PKCS#8.
        PKCS8EncodedKeySpec rkeySpec = new PKCS8EncodedKeySpec(hexToByteArray(privKeyStr));
        KeyFactory rkeyFactory = KeyFactory.getInstance("RSACrypto");
        PrivateKey privateKey = null;
        try {
            privateKey = rkeyFactory.generatePrivate(rkeySpec);
            System.out.println("privKeyHex:"+byteArrayToHex(privateKey.getEncoded()));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        // 개인키를 가지고있는쪽에서 복호화
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(hexToByteArray(cipherText));
        System.out.println("plainText:" + new String(plainText));

        return plainText;
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

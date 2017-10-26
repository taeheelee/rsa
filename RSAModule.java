package kr.co.mobidoo;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.Scanner;

public class RSAModule {

    //암호화 및 복호화 예제
    public static void main(String[] args) {
        try {
            //공개키에서 modulus, exponent를 생성
            //KeySpec 객체에 공개키를 매개변수로 넣어야 함
            RSAPublicKeySpec publicKeySpec = toPublicKeySpec(keyPair.getPublic());
            System.out.println("Modulus\n" + publicKeySpec.getModulus().toString(16));
            System.out.println("Public Exponent\n" + publicKeySpec.getPublicExponent().toString(16));

            //공개키의 Modulus는 프로그램이 실행될 때마다 임의로 변경된다.
            //테스트의 편리함을 위해 Thread를 생성하고 그 안에서 무한 반복문을 실행
            //암호화 된 문자열을 계속 복호화를 할 수 있음
            new Thread(new Runnable() {
                @Override
                public void run() {
                    while(true) {
                        //암호화 테스트 시 아래 코드 2줄 주석 해제 및 복호화 테스트 코드 3줄 주석 처리.
                        //String temp = encrypt(new String("암호화 할 메세지").getBytes());
                        //System.out.println("암호화된 문자열 : " + temp);

                        //복호화 테스트를 할 때, 암호화 문자열을 입력받는 부분
                        System.out.println("암호화 문자열 입력 :");
                        Scanner sc = new Scanner(System.in);
                        String temp = sc.nextLine();

                        try{
                            //decrypt는 복호화된 메소드를 반환함
                            System.out.println("복호화 결과 : " + decrypt(temp));
                        }catch (Exception e){
                            e.printStackTrace();
                        }

                    }
                }
            }).start();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //private, public key를 담고있는 객체
    private static final KeyPair keyPair = generateKeyPair(2048);
    //암호화를 할 알고리즘 지정
    private static final String Algorithm = "RSA";

    //private, public key를 담고 있는 KeyPair(키쌍)을 반환
    //bit 수를 매개변수로 넘겨 암호화 수준을 결정함
    public static KeyPair generateKeyPair(int KeyBits)
    {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Algorithm);
            keyPairGenerator.initialize(KeyBits);
            return keyPairGenerator.genKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    //공개키의 Modulus, Exponent를 생성하기 위해, RSAPublicKeySpec가 있어야 함
    //Public Key를 매개변수로 넘겨 RSAPublicKeySpec을 생성하고 반환함
    public static RSAPublicKeySpec toPublicKeySpec(Key key)
    {
        try {
            return (RSAPublicKeySpec) KeyFactory.getInstance(Algorithm).getKeySpec(key, RSAPublicKeySpec.class);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    //공개키의 Modulus, Exponent를 매개변수로 넘겨 공개키를 생성하는 메소드
    public static PublicKey toPublicKey(byte[] modulus, byte[] exponent)
    {
        try {
            //매개변수로 받은 Modulus, Exponent를 BigInteger 객체로 변경함
            BigInteger bigModulus = new BigInteger(1, modulus);
            BigInteger bigExponent = new BigInteger(1, exponent);
            //위에서 생성한 BigInteger 객체를 RSAPublicKeySpec 생성자에 매개변수로 삽입
            RSAPublicKeySpec spec = new RSAPublicKeySpec(bigModulus, bigExponent);

            //KeyFactory를 이용하여 PublicKey 생성
            return KeyFactory.getInstance(Algorithm).generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    //암호화, 복호화를 수행하는 메소드
    //mode에 따라 수행 작업이 다르다. mode 1 : 암호화, mode2 : 복호화
    //암호화 시 공개키, 복호화 시 개인키를 매개변수로 넘겨야 한다.
    //msg는 암호화 및 복호화를 진행할 메세지
    //provider는 암호화 알고리즘을 제공하는 제공자를 의미
    private static byte[] doCipher(Key key, int mode, String Algorithm, String provider, byte[] msg)
    {

        try {
            //알고리즘과 제공자를 이용해 암복호화 객체를 생성
            Cipher cipher = Cipher.getInstance(Algorithm, provider);
            //mode에 맞게 객체 초기화
            cipher.init(mode, key);
            //메세지 암복호화 실행 및 반환
            return cipher.doFinal(msg);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }


    //byte 배열을 Base64 String으로 변환하는 메소드
    private static String toBase64(byte[] text) {
        return Base64.getEncoder().encodeToString(text);
    }

    //Base64로 인코딩된 String에서 PrivateKey를 생성해 반환하는 메소드
    public static PrivateKey genPrivateKeyFromBase64(String privateKeyBase64)
    {
        try {
            //base64를 디코딩하고, KeySpec 객체를 생성
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyBase64));
            //KeyFactory에 KeySpec을 넘겨서 privateKey를 생성
            KeyFactory kf = KeyFactory.getInstance(Algorithm);

            return kf.generatePrivate(spec);
        }catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    //Base64로 인코딩된 modulus, exponent에서 PublicKey를 생성해 반환하는 메소드
    public static PublicKey generatePublicKeyFromBase64(byte[] modulus, byte[] exponent)
    {
        try {

            //base64 디코딩
            byte[] decodedModulus = Base64.getDecoder().decode(modulus);
            byte[] decodedExponent = Base64.getDecoder().decode(exponent);

            //publicKey 생성
            PublicKey publicKey = toPublicKey(decodedModulus, decodedExponent);

            return publicKey;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    // 16진수 String을 byte 배열로 변환하는 메소드
    public static byte[] hexToByteArray(String hex) {
        byte[] bytes = new java.math.BigInteger(hex, 16).toByteArray();
        return bytes;
    }

    // byte 배열을 16진수 String으로 변환하는 메소드
    public static String byteArrayToHex(byte[] ba) {
        String hexText = new java.math.BigInteger(ba).toString(16);
        return hexText;
    }


    //메세지를 공개키로 암호화하는 메소드
    //매개변수는 일반 String
    public static String encrypt(String plainMsg)
    {
        //메세지를 byte 배열로 변환
        byte[] bytePlainMsg = plainMsg.getBytes();
        //암호화 모드로 cipher 객체를 동작시킴
        byte[] encodedMsg = doCipher(keyPair.getPublic(), Cipher.ENCRYPT_MODE, "RSA/ECB/PKCS1PADDING", "SunJCE", bytePlainMsg);

        //16진수 String으로 변환 후 반환
        return byteArrayToHex(encodedMsg);
    }

    //메세지를 비밀키로 복호화하는 메소드
    public static String decrypt(String cipherMsg)
    {
        //암호화된 16진수 String을 byte 배열로 변환
        byte[] byteCipherMsg = hexToByteArray(cipherMsg);
        //cipher 객체를 복호화 모드로 동작시켜 디코딩 된 메세지 생성
        byte[] decodedMsg = doCipher(keyPair.getPrivate(), Cipher.DECRYPT_MODE, "RSA/ECB/PKCS1PADDING", "SunJCE", byteCipherMsg);

        try {
            //한글 깨짐 문제 해결 위해 "UTF-8"로 인코딩
            return new String(decodedMsg, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

}

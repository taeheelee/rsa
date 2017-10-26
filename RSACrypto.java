package kr.co.mobidoo;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

import sun.security.pkcs.PKCS8Key;

import java.util.Scanner;

public class RSACrypto {
    private static final String Algorithm = "RSACrypto";
    private RSACrypto() {
    }

    public static KeyPair genKey(int KeyBits)
    {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Algorithm);
            keyPairGenerator.initialize(KeyBits);
            return keyPairGenerator.genKeyPair();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    public static RSAPublicKeySpec toPublicKeySpec(PublicKey key)
    {
        try {
            return (RSAPublicKeySpec) KeyFactory.getInstance(Algorithm).getKeySpec(key, RSAPublicKeySpec.class);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    public static PublicKey toPublicKey(byte[] modulus, byte[] exponent)
    {
        try {
            BigInteger bigModulus = new BigInteger(1, modulus);
            BigInteger bigExponent = new BigInteger(1, exponent);
            RSAPublicKeySpec spec = new RSAPublicKeySpec(bigModulus, bigExponent);

            return KeyFactory.getInstance(Algorithm).generatePublic(spec);
            //return KeyFactory.getInstance(Algorithm).generatePublic(new X509EncodedKeySpec(bytes));
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    public  static boolean  writePrivateKeyToFile(PrivateKey key, String filename)
    {
        try {
            FileWriter fw = new FileWriter(filename, false);
            BufferedWriter bw = new BufferedWriter(fw);

            byte[] keyBytes = key.getEncoded();
            PKCS8Key pkcs8= new PKCS8Key();
            pkcs8.decode(keyBytes);
            byte[] b=pkcs8.encode();

//            bw.write(Base64.encodeBase64String(b));
            bw.write(Base64.getEncoder().encode(b).toString());
            bw.close();

            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    public static PrivateKey genPrivateKeyFromBase64(String privateKeyBase64)
    {
        try {
//            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyBase64));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyBase64));
            //Base64.getDecoder().decode(privateKeyBase64)
            KeyFactory kf = KeyFactory.getInstance(Algorithm);

            return kf.generatePrivate(spec);
        }catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public  static PrivateKey readPrivateKeyFromFile(String filename)
    {
        try {
            FileReader fr = new FileReader(filename);
            BufferedReader br = new BufferedReader(fr);

            String keyBase64 = br.readLine();
            br.close();

            return genPrivateKeyFromBase64(keyBase64);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }


    public static void writePublicKeyToFile(PublicKey key, String fileName)
    {
        try {
            RSAPublicKeySpec spec = RSACrypto.toPublicKeySpec(key);
            byte[] modulus = RSACrypto.removeSigPaddingOfBigIntger(spec.getModulus().toByteArray());
            byte[] exponent = spec.getPublicExponent().toByteArray();

            FileWriter fw = new FileWriter(fileName, false);
            BufferedWriter bw = new BufferedWriter(fw);
//            bw.write(Base64.encodeBase64String(modulus));
            bw.write(Base64.getEncoder().encode(modulus).toString());
            bw.newLine();
//            bw.write(Base64.encodeBase64String(exponent));
            bw.write(Base64.getEncoder().encode(exponent).toString());
            bw.close();

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static PublicKey readPublicKeyFromFile(String fileName)
    {
        try {

            FileReader fr = new FileReader(fileName);
            BufferedReader br = new BufferedReader(fr);
//            byte[] modulus = Base64.decodeBase64(br.readLine());
            byte[] modulus = Base64.getDecoder().decode(br.readLine());
//            byte[] exponent = Base64.decodeBase64(br.readLine());
            byte[] exponent = Base64.getDecoder().decode(br.readLine());

            PublicKey publicKey = RSACrypto.toPublicKey(modulus, exponent);

            return publicKey;

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    private static byte[] doCipher(Key key, int mode, byte[] msg)
    {

        try {
            Cipher cipher = Cipher.getInstance(Algorithm);
            cipher.init(mode, key);
            return cipher.doFinal(msg);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    private static byte[] removeSigPaddingOfBigIntger(byte[] a)
    {
        if (a[0] == 0) {
            byte[] tmp = new byte[a.length - 1];
            System.arraycopy(a, 1, tmp, 0, tmp.length);
            return tmp;
        }

        return a;
    }

    public static byte[] encrypt(PublicKey key, byte[] plainMsg)
    {
        return doCipher(key, Cipher.ENCRYPT_MODE, plainMsg);
    }

    public static byte[] decrypt(PrivateKey key, byte[] cipherMsg)
    {
        return doCipher(key, Cipher.DECRYPT_MODE, cipherMsg);
    }

    public static byte[] encrypt(PrivateKey key, byte[] plainMsg)
    {
        return doCipher(key, Cipher.ENCRYPT_MODE, plainMsg);
    }

    public static byte[] decrypt(PublicKey key, byte[] cipherMsg)
    {
        return doCipher(key, Cipher.DECRYPT_MODE, cipherMsg);
    }

    static String ToHexStr(byte[] b)
    {
        return javax.xml.bind.DatatypeConverter.printHexBinary(b);
    }

    public static void main(String[] args) {
        String PlainText = "java Python C";
        try {
            System.out.println("RSA Basic Enc/Decrypt");
            KeyPair keyPair = RSACrypto.genKey(2048);
            RSAPublicKeySpec spec = RSACrypto.toPublicKeySpec(keyPair.getPublic());
            System.out.println("modulus : " + spec.getModulus());
            System.out.println("exponent : " + spec.getPublicExponent());
//            byte[] plain = PlainText.getBytes("UTF-8");
//            byte[] enc = RSACrypto.encrypt(keyPair.getPublic(), plain);
//            byte[] enc1 = RSACrypto.encrypt(keyPair.getPublic(), plain);
//            byte[] dec = RSACrypto.decrypt(keyPair.getPrivate(), enc);
//            RSACrypto.writePrivateKeyToFile(keyPair.getPrivate(), "d:/javaRSAPrivateKey.txt");
//            PrivateKey pKey = RSACrypto.readPrivateKeyFromFile("d:/javaRSAPrivateKey.txt");
//            byte[] dec1 = RSACrypto.decrypt(pKey, enc1);
//            byte[] renc = RSACrypto.encrypt(keyPair.getPrivate(), plain);
//            byte[] renc1 = RSACrypto.encrypt(keyPair.getPrivate(), plain);
//            byte[] rdec = RSACrypto.decrypt(keyPair.getPublic(), renc);
//            byte[] rdec1 = RSACrypto.decrypt(keyPair.getPublic(), renc1);
//
//            System.out.println("plain:" + ToHexStr(plain) + " " + new String(plain, "UTF-8"));
//            System.out.println("enc  :" + ToHexStr(enc));
//            System.out.println("enc1 :" + ToHexStr(enc1));
//            System.out.println("dec  :" + ToHexStr(dec) + " " + new String(dec, "UTF-8"));
//            System.out.println("dec1 :" + ToHexStr(dec1) + " " + new String(dec1, "UTF-8"));
//            System.out.println("renc :" + ToHexStr(renc));
//            System.out.println("renc1:" + ToHexStr(renc1));
//            System.out.println("rdec :" + ToHexStr(rdec) + " " + new String(rdec, "UTF-8"));
//            System.out.println("rdec1:" + ToHexStr(rdec1) + " " + new String(rdec1, "UTF-8"));
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}

package com.example;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import java.util.Base64;

public class PublicPrivateKey {

    public static String getEncrypted(String data, String key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(key)));
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedbytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedbytes);
    }

    public static String getDecrypted(String data, String key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key)));
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);  // Uso di una chiave più lunga per una migliore sicurezza
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        String pubKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String priKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        System.out.println("Public Key: " + pubKey);
        System.out.println("Private Key: " + priKey);

        String cipherText = getEncrypted("hi this is a string", pubKey);
        System.out.println("CIPHER: " + cipherText);

        String decryptedText = getDecrypted(cipherText, priKey);
        System.out.println("DECRYPTED STRING: " + decryptedText);
    }
}

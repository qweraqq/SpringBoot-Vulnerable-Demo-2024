package com.shen1991.vulnerable.service;

import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;


@Service
public class CryptoService {
    private static final byte[] KEY = new byte[16];
    private static final String ALGO = "AES/CBC/PKCS5Padding";

    static {
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(KEY);
    }

    public byte[] encrypt(byte[] plaintext, byte[] IV) {
        try {
            IvParameterSpec iv = new IvParameterSpec(IV);
            SecretKeySpec secretkeySpec = new SecretKeySpec(KEY, "AES");

            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, secretkeySpec, iv);

            return cipher.doFinal(plaintext);
        } catch (Exception ignored) {
        }
        return null;
    }

    public byte[] decrypt(byte[] ciphertext, byte[] IV) {
        try {
            IvParameterSpec iv = new IvParameterSpec(IV);
            SecretKeySpec secretkeySpec = new SecretKeySpec(KEY, "AES");

            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.DECRYPT_MODE, secretkeySpec, iv);

            return cipher.doFinal(ciphertext);
        } catch (Exception ignored) {
        }
        return null;
    }


    public byte[] hmac(byte[] message) {
        try{
            SecretKeySpec secretkeySpec = new SecretKeySpec(KEY, "HmacSHA256");
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(secretkeySpec);
            return hmac.doFinal(message);
        } catch (Exception ignored) {

        }
        return null;
    }



}


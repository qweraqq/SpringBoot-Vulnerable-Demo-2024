package com.shen1991.vulnerable.controller;

import com.shen1991.vulnerable.entity.CryptoResponse;
import com.shen1991.vulnerable.service.CryptoService;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;


@RestController
public class CryptoController {
    private static final byte[] MAGIC = "role=admin".getBytes(StandardCharsets.UTF_8);

    @Autowired
    private CryptoService cryptoService;

    @PostMapping("/decrypt-vulnerable")
    public CryptoResponse decryptVulnerable(@RequestParam(value = "data") String data){
        CryptoResponse cryptoResponse = new CryptoResponse();
        byte[] plaintext;
        try {
            byte[] raw = Base64.getUrlDecoder().decode(data);
            byte[] IV = Arrays.copyOfRange(raw, 0, 16);
            byte[] ciphertext = Arrays.copyOfRange(raw, 16,  raw.length);
            plaintext = cryptoService.decrypt(ciphertext, IV);
            cryptoResponse.setPlaintext(Base64.getUrlEncoder().encodeToString(plaintext));
        } catch (Exception ignored) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if(Arrays.equals(plaintext, MAGIC)){
            // YOU CAN do some privileged action
            cryptoResponse.setPlaintext("YOU ARE ADMIN");
        }

        return cryptoResponse;
    }

    @PostMapping("/encrypt-vulnerable")
    public CryptoResponse encryptVulnerable(@RequestParam(value = "data") String data){
        CryptoResponse cryptoResponse = new CryptoResponse();
        byte[] plaintext;
        try {
            plaintext = Base64.getUrlDecoder().decode(data);
        } catch (Exception ignored) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if(Arrays.equals(plaintext, MAGIC)){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }

        byte[] IV = new byte[16];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(IV);

        byte[] ciphertext = cryptoService.encrypt(Base64.getUrlDecoder().decode(data), IV);
        byte[] ciphertextWithIV = new byte[IV.length + ciphertext.length];
        System.arraycopy(IV,0, ciphertextWithIV,0, IV.length);
        System.arraycopy(ciphertext,0,ciphertextWithIV, IV.length, ciphertext.length);
        cryptoResponse.setCiphertext(Base64.getUrlEncoder().encodeToString(ciphertextWithIV));
        return cryptoResponse;
    }

    // https://gist.github.com/patrickfav/b323f0d9cbd81d5fa9cc4c971b732c77


    @PostMapping("/decrypt")
    public CryptoResponse decrypt(@RequestParam(value = "data") String data){
        CryptoResponse cryptoResponse = new CryptoResponse();

        byte[] raw = Base64.getUrlDecoder().decode(data);
        byte[] hmacReceived = Arrays.copyOfRange(raw, 0, 32);
        byte[] ciphertextWithIV = Arrays.copyOfRange(raw, 32, raw.length);
        byte[] IV = Arrays.copyOfRange(raw, 32, 32+16);
        byte[] ciphertext = Arrays.copyOfRange(raw, 32+16,  raw.length);

        byte[] hmacCalculated = cryptoService.hmac(ciphertextWithIV);

        if(! Arrays.equals(hmacCalculated, hmacReceived)){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }

        byte[] plaintext = cryptoService.decrypt(ciphertext, IV);
        cryptoResponse.setPlaintext(Base64.getUrlEncoder().encodeToString(plaintext));

        if(Arrays.equals(plaintext, MAGIC)){
            // YOU CAN do some privileged action
            cryptoResponse.setPlaintext("YOU ARE ADMIN");
        }

        return cryptoResponse;
    }

    @PostMapping("/encrypt")
    public CryptoResponse encrypt(@RequestParam(value = "data") String data){
        CryptoResponse cryptoResponse = new CryptoResponse();
        byte[] plaintext = Base64.getUrlDecoder().decode(data);
        if(Arrays.equals(plaintext, MAGIC)){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        byte[] IV = new byte[16];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(IV);

        byte[] ciphertext = cryptoService.encrypt(Base64.getUrlDecoder().decode(data), IV);
        byte[] ciphertextWithIV = new byte[IV.length + ciphertext.length];
        System.arraycopy(IV,0, ciphertextWithIV,0, IV.length);
        System.arraycopy(ciphertext,0,ciphertextWithIV, IV.length, ciphertext.length);

        byte[] hmac = cryptoService.hmac(ciphertextWithIV);

        byte[] ciphertextWithHmac = new byte[hmac.length + ciphertextWithIV.length];
        System.arraycopy(hmac,0, ciphertextWithHmac,0, hmac.length);
        System.arraycopy(ciphertextWithIV,0,ciphertextWithHmac, hmac.length, ciphertextWithIV.length);
        cryptoResponse.setCiphertext(Base64.getUrlEncoder().encodeToString(ciphertextWithHmac));

        return cryptoResponse;
    }
}

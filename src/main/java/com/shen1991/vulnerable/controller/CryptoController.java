package com.shen1991.vulnerable.controller;

import com.shen1991.vulnerable.entity.CryptoResponse;
import com.shen1991.vulnerable.service.CryptoService;

import java.nio.charset.StandardCharsets;
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
            plaintext = cryptoService.decrypt(Base64.getDecoder().decode(data));
            cryptoResponse.setPlaintext(Base64.getEncoder().encodeToString(plaintext));
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
            plaintext = Base64.getDecoder().decode(data);
        } catch (Exception ignored) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        if(Arrays.equals(plaintext, MAGIC)){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        byte[] ciphertext = cryptoService.encrypt(Base64.getDecoder().decode(data));
        cryptoResponse.setCiphertext(Base64.getEncoder().encodeToString(ciphertext));
        return cryptoResponse;
    }

    // https://gist.github.com/patrickfav/b323f0d9cbd81d5fa9cc4c971b732c77


    @PostMapping("/decrypt")
    public CryptoResponse decrypt(@RequestParam(value = "data") String data){
        CryptoResponse cryptoResponse = new CryptoResponse();

        byte[] raw = Base64.getDecoder().decode(data);
        byte[] hmacReceived = Arrays.copyOfRange(raw, 0, 32);
        byte[] ciphertext = Arrays.copyOfRange(raw, 32,  raw.length);

        byte[] hmacCalculated = cryptoService.hmac(ciphertext);

        if(! Arrays.equals(hmacCalculated, hmacReceived)){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }

        byte[] plaintext = cryptoService.decrypt(ciphertext);
        cryptoResponse.setPlaintext(Base64.getEncoder().encodeToString(plaintext));

        if(Arrays.equals(plaintext, MAGIC)){
            // YOU CAN do some privileged action
            cryptoResponse.setPlaintext("YOU ARE ADMIN");
        }

        return cryptoResponse;
    }

    @PostMapping("/encrypt")
    public CryptoResponse encrypt(@RequestParam(value = "data") String data){
        CryptoResponse cryptoResponse = new CryptoResponse();
        byte[] plaintext = Base64.getDecoder().decode(data);
        if(Arrays.equals(plaintext, MAGIC)){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        byte[] ciphertext = cryptoService.encrypt(Base64.getDecoder().decode(data));
        byte[] hmac = cryptoService.hmac(ciphertext);

        byte[] ciphertextWithHmac = new byte[hmac.length + ciphertext.length];
        System.arraycopy(hmac,0, ciphertextWithHmac,0, hmac.length);
        System.arraycopy(ciphertext,0,ciphertextWithHmac, hmac.length, ciphertext.length);
        cryptoResponse.setCiphertext(Base64.getEncoder().encodeToString(ciphertextWithHmac));

        return cryptoResponse;
    }
}

package com.shen1991.vulnerable.controller;

import com.shen1991.vulnerable.entity.CryptoResponse;
import com.shen1991.vulnerable.service.CryptoService;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CryptoController {
    private CryptoService cryptoService;

    public CryptoController(CryptoService cryptoService){
        this.cryptoService = cryptoService;
    }

    @GetMapping("/decrypt")
    public CryptoResponse decryptVulnerable(@RequestParam(value = "data") String data){
        CryptoResponse cryptoResponse = new CryptoResponse();
        cryptoResponse.setPlaintext(cryptoService.decrypt(data));
        return cryptoResponse;
    }

    @GetMapping("/encrypt")
    public CryptoResponse encryptVulnerable(@RequestParam(value = "data") String data){
        CryptoResponse cryptoResponse = new CryptoResponse();
        cryptoResponse.setCiphertext(cryptoService.encrypt(data));
        return cryptoResponse;
    }
}

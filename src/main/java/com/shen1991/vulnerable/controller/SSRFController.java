package com.shen1991.vulnerable.controller;

import com.shen1991.vulnerable.handler.ResponseHandler;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.*;
import java.util.stream.Collectors;


@Controller
public class SSRFController {
    
    @RequestMapping(value = "/ssrf-vulnerable", method = RequestMethod.POST)
    public ResponseEntity<Object> ssrfVulnerable(
            @RequestParam(name = "hostname", required = false, defaultValue = "http://www.baidu.com") String hostname,
            Model model) {
        try {
            String body = fetchRemoteObjectVulnerable(hostname);
            return ResponseHandler.generateResponse("Success", body, HttpStatus.OK);
        } catch (Exception e) {
            return ResponseHandler.generateErrorResponse("Failed", e.getMessage(), HttpStatus.UNPROCESSABLE_ENTITY);
        }

    }

    private static String fetchRemoteObjectVulnerable(String hostname) throws Exception {
        URL url = new URI(hostname).toURL();
        URLConnection connection = url.openConnection();
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        return reader.lines().collect(Collectors.joining());
    }

    @RequestMapping(value = "/ssrf", method = RequestMethod.POST)
    public ResponseEntity<Object> ssrf(
            @RequestParam(name = "hostname", required = false, defaultValue = "http://www.baidu.com") String hostname,
            Model model) {
        try {
            String body = fetchRemoteObject(hostname);
            return ResponseHandler.generateResponse("Success", body, HttpStatus.OK);
        } catch (Exception e) {
            return ResponseHandler.generateErrorResponse("Failed", e.getMessage(), HttpStatus.UNPROCESSABLE_ENTITY);
        }

    }

    private static String fetchRemoteObject(String hostname) throws Exception {
        URL url = new URI(hostname).toURL();

        if (!url.getHost().endsWith(".baidu.com") ||
                !url.getProtocol().equals("http") &&
                        !url.getProtocol().equals("https")) {
            throw new Exception("Forbidden remote source");
        }

        URLConnection connection = url.openConnection();
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        return reader.lines().collect(Collectors.joining());
    }

}

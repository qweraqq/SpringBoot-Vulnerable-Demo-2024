package com.shen1991.vulnerable.controller;

import com.shen1991.vulnerable.handler.ResponseHandler;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;

@Controller
public class SSRFController {

    Set<String> blockedIpPool = new HashSet<>(Arrays.asList("127.0.0.1", "::1"));

    @RequestMapping(value = "/ssrf-vulnerable", method = RequestMethod.POST)
    public ResponseEntity<Object> ssrfVulnerable(
            @RequestParam(name = "hostname", required = false, defaultValue = "http://www.baidu.com") String hostname,
            Model model) {
        Map<String, Object> data = new HashMap<>();
        URL aURL;
        try {
            aURL = new URI(hostname).toURL();
        } catch (MalformedURLException e) {
            return ResponseHandler.generateErrorResponse("Failed", e.getMessage(), HttpStatus.UNPROCESSABLE_ENTITY);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        InetAddress inet;
        try {
            inet = InetAddress.getByName(aURL.getAuthority());
        } catch (UnknownHostException e) {
            return ResponseHandler.generateErrorResponse("Failed", e.getMessage(), HttpStatus.UNPROCESSABLE_ENTITY);
        }

        String ip = inet.getHostAddress();
        if (blockedIpPool.contains(ip)) {
            return ResponseHandler.generateErrorResponse("Failed", "Forbidden", HttpStatus.FORBIDDEN);
        }

        String body = FetchHost(hostname);
        return ResponseHandler.generateResponse("Success", body, HttpStatus.OK);
    }


    protected String FetchHost(String host) {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(host))
                .GET()
                .build();

        HttpResponse<String> response;
        try {
            response = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            return null; // Consider returning an error message or handling the error more gracefully
        }

        return response.body();
    }

}

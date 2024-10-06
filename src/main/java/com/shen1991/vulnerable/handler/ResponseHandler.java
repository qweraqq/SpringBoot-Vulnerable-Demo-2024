package com.shen1991.vulnerable.handler;

import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class ResponseHandler {
    public static ResponseEntity<Object> generateResponse(String status, String message, HttpStatus statusCode) {
        Map<String, String> map = new HashMap<String, String>();

        map.put("status", status);
        map.put("message", message);

        return new ResponseEntity<Object>(map, statusCode);
    }

    public static ResponseEntity<Object> generateErrorResponse(String status, String error, HttpStatus statusCode) {
        Map<String, String> map = new HashMap<String, String>();
        map.put("status", status);
        map.put("error", error);

        return new ResponseEntity<Object>(map, statusCode);
    }
}

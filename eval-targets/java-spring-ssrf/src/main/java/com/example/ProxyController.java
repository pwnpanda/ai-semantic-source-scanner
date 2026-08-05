package com.example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class ProxyController {

    private final RestTemplate rest = new RestTemplate();

    @GetMapping("/proxy")
    public String proxy(@RequestParam String url) {
        // VULNERABLE: user-controlled URL into RestTemplate.getForObject (SSRF).
        return rest.getForObject(url, String.class);
    }
}

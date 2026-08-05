package com.example;

import java.io.IOException;
import java.io.PrintWriter;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EchoController {

    @GetMapping("/echo")
    public void echo(@RequestParam String message, HttpServletResponse response) throws IOException {
        // VULNERABLE: user-controlled string written directly into the
        // response body without HTML escaping.
        PrintWriter writer = response.getWriter();
        writer.println("<p>" + message + "</p>");
    }
}

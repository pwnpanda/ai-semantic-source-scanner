package com.example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private final CustomJdbcWrapper jdbc;

    public UserController(CustomJdbcWrapper jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/user")
    public String getUser(@RequestParam String id) {
        // VULNERABLE: user-controlled `id` flows through the wrapper's
        // `runSelect` method, which is NOT modelled by stock CodeQL.
        String sql = "SELECT name FROM users WHERE id = " + id;
        return jdbc.runSelect(sql);
    }
}

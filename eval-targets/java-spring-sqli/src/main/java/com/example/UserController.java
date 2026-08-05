package com.example;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private final JdbcTemplate jdbc;

    public UserController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/user")
    public String getUser(@RequestParam String id) {
        // VULNERABLE: string-concatenated SQL into queryForObject.
        String sql = "SELECT name FROM users WHERE id = " + id;
        return jdbc.queryForObject(sql, String.class);
    }
}

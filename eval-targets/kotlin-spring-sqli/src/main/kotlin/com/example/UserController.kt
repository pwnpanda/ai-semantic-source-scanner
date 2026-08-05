package com.example

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class UserController(private val jdbc: JdbcTemplate) {

    @GetMapping("/user")
    fun getUser(@RequestParam id: String): String {
        // VULNERABLE: string-concatenated SQL into queryForObject.
        val sql = "SELECT name FROM users WHERE id = $id"
        return jdbc.queryForObject(sql, String::class.java) ?: ""
    }
}

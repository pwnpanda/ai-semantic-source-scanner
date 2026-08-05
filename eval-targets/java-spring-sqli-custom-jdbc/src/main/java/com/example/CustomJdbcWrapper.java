package com.example;

import org.springframework.jdbc.core.JdbcTemplate;

// Custom wrapper around JdbcTemplate. CodeQL's stock model for queryForObject
// is on the JdbcTemplate type; the wrapper's `runSelect` method has no model
// out of the box, so stock CodeQL misses any flow that goes through here.
// This is the shape an LLM-proposed CodeQL extension would target.
public class CustomJdbcWrapper {

    private final JdbcTemplate delegate;

    public CustomJdbcWrapper(JdbcTemplate delegate) {
        this.delegate = delegate;
    }

    public String runSelect(String sql) {
        return delegate.queryForObject(sql, String.class);
    }
}

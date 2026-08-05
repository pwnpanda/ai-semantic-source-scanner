// Phase 18 positive eval — open redirect (CWE-601).
// Source: req.query.next (attacker-controlled URL).
// Sink: res.redirect with no allowlist — Joern's new
// (?i)^redirect$ JS open-redirect sink should fire.

const express = require("express");
const app = express();

app.get("/login", (req, res) => {
    const next = req.query.next;
    res.redirect(next);  // VULNERABLE: arbitrary URL redirect
});

app.listen(3000);

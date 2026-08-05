// Phase 18 NEGATIVE eval (Recall-First Invariant 5).
// Same source shape as the positive, but the redirect target is gated
// against an allowlist — the mitigations layer should demote this
// candidate; reviewers verify the allowlist is actually exhaustive.

const express = require("express");
const app = express();

const ALLOWED = new Set(["/dashboard", "/profile", "/settings"]);

app.get("/login", (req, res) => {
    const next = req.query.next;
    if (!ALLOWED.has(next)) {
        return res.status(400).send("invalid redirect target");
    }
    res.redirect(next);  // bounded by ALLOWED set
});

app.listen(3000);

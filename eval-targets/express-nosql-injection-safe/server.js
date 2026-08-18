// Phase 21 NEGATIVE (Recall-First Invariant 5) — same endpoint, but both
// credential fields are coerced to primitive strings before they reach the
// query, so an attacker-supplied {"$ne": null} becomes the literal string
// "[object Object]" and matches nothing. The candidate may still surface
// (Invariant 2: mitigations demote, never drop) but must not be expected.

const express = require("express");
const { MongoClient } = require("mongodb");

const app = express();
app.use(express.json());

const client = new MongoClient("mongodb://localhost:27017");
const users = client.db("app").collection("users");

app.post("/login", async (req, res) => {
    // SAFE: String() collapses any operator object to a scalar.
    const username = String(req.body.username);
    const password = String(req.body.password);
    const user = await users.findOne({ username: username, password: password });
    res.json({ ok: Boolean(user) });
});

app.listen(3000);

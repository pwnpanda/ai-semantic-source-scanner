// Phase 21 positive — NoSQL operator injection (CWE-943).
// Source: req.body (the attacker controls the whole JSON object).
// Sink: the object is handed straight to a Mongo query, so
//   {"username": "admin", "password": {"$ne": null}}
// authenticates as admin without knowing the password.

const express = require("express");
const { MongoClient } = require("mongodb");

const app = express();
app.use(express.json());

const client = new MongoClient("mongodb://localhost:27017");
const users = client.db("app").collection("users");

app.post("/login", async (req, res) => {
    const creds = req.body;
    // VULNERABLE: operator objects in creds are interpreted as query operators.
    const user = await users.findOne({ username: creds.username, password: creds.password });
    res.json({ ok: Boolean(user) });
});

app.listen(3000);

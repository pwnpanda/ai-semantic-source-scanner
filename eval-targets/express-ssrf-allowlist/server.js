// Safe Express SSRF target: validates request URL against an allowlist
// before fetching. Negative eval target for §7 — the broadened SSRF sink
// pattern WILL fire here, but the `ssrf.host-allowlist` mitigation in
// scoring should demote the candidate.

const express = require("express");
const app = express();

const ALLOWED_HOSTS = new Set(["api.example.com", "cdn.example.com"]);

app.get("/proxy", async (req, res) => {
  const target = new URL(req.query.url);
  if (!ALLOWED_HOSTS.has(target.host)) {
    return res.status(400).send("host not allowed");
  }
  const response = await fetch(target.toString());
  res.send(await response.text());
});

app.listen(3000);

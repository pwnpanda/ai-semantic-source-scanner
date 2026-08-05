// Safe Express logging target: redacts sensitive fields before logging.
// Negative eval target for §7 — the broadened CWE-532 sink pattern still
// fires on the logger call, but the `log.redaction` mitigation should
// demote the candidate.

const express = require("express");
const app = express();

function redact(payload) {
  const safe = { ...payload };
  delete safe.password;
  delete safe.token;
  delete safe.authorization;
  return safe;
}

app.post("/login", (req, res) => {
  const safe = redact(req.body);
  console.log("login attempt", safe);
  res.send("ok");
});

app.listen(3000);

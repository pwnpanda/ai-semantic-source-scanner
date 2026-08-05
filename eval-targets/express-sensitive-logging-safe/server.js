// Safe Express logging target with no request-derived sensitive data in logs.

const express = require("express");
const app = express();

app.get("/debug", (_req, res) => {
  console.error("debug endpoint called");
  res.send("ok");
});

app.listen(3000);

// Safe Express outbound request target with a fixed upstream URL.

const express = require("express");
const app = express();

app.get("/fetch-status", async (_req, res) => {
  const response = await fetch("https://api.example.com/status");
  res.send(await response.text());
});

app.listen(3000);

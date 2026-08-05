// Deliberately vulnerable Express SSRF target.

const express = require("express");
const app = express();

app.get("/fetch", async (req, res) => {
  const url = req.query.url;
  const response = await fetch(url);
  res.send(await response.text());
});

app.listen(3000);

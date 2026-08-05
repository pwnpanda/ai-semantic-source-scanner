// Deliberately vulnerable Express SSRF target using axios.
// Positive eval target for the broadened SSRF sink pattern (§7).

const express = require("express");
const axios = require("axios");
const app = express();

app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  const response = await axios.get(target);
  res.send(response.data);
});

app.listen(3000);

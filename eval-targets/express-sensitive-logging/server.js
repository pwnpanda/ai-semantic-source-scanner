// Deliberately vulnerable Express sensitive-logging target.

const express = require("express");
const app = express();

app.get("/debug", (req, res) => {
  const token = req.headers.authorization;
  console.error(token);
  res.send("ok");
});

app.listen(3000);

// Safe Express response target with no request-controlled HTML.

const express = require("express");
const app = express();

app.get("/hello", (_req, res) => {
  res.send("<h1>Hello</h1>");
});

app.listen(3000);

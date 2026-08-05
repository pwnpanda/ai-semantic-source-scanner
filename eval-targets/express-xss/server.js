// Deliberately vulnerable Express reflected-XSS target.

const express = require("express");
const app = express();

app.get("/hello", (req, res) => {
  const name = req.query.name;
  res.send("<h1>Hello " + name + "</h1>");
});

app.listen(3000);

// Deliberately vulnerable Express command-injection target.

const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/run", (req, res) => {
  const command = req.query.cmd;
  exec(command, () => res.send("done"));
});

app.listen(3000);

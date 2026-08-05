// Safe Express command execution target.

const express = require("express");
const { execFile } = require("child_process");
const app = express();

app.get("/status", (_req, res) => {
  execFile("git", ["status", "--short"], () => res.send("done"));
});

app.listen(3000);

const express = require("express");
const db = require("./db");

const app = express();
app.use(express.json());

app.post("/profile", async (req, res) => {
  const bio = req.body.bio;
  await db.query(`UPDATE profiles SET bio = '${bio}' WHERE id = 1`);
  res.send("saved");
});

app.get("/profile", async (req, res) => {
  const rows = await db.query("SELECT bio FROM profiles WHERE id = 1");
  const preview = req.query.preview;
  res.send(rows[0].bio + preview);
});

app.listen(3000);

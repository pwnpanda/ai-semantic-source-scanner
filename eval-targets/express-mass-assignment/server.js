// Deliberately vulnerable Express/Firestore mass-assignment target.

const express = require("express");
const app = express();

app.use(express.json());

app.post("/profile", async (req, res) => {
  const updates = req.body;
  await db.collection("users").doc(req.user.id).update(updates);
  res.sendStatus(204);
});

app.listen(3000);

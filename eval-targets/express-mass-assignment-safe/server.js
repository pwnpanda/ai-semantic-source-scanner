// Safe Express/Firestore update target with no request-body assignment.

const express = require("express");
const app = express();

app.post("/profile", async (_req, res) => {
  const updates = { displayName: "demo" };
  await db.collection("users").doc("current").update(updates);
  res.sendStatus(204);
});

app.listen(3000);

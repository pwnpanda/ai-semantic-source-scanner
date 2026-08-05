// Deliberately vulnerable Express target for semantic scanner evaluation.
//
// Ground truth:
// - CWE-639 BOLA/IDOR: user id is accepted from the URL without ownership check.
// - CWE-862 BFLA: privileged admin deletion route has no role/policy check.
// - CWE-287 Missing authn: state-changing route has no authn middleware.

const express = require("express");
const app = express();

app.use(express.json());

app.delete("/admin/users/:id", async (req, res) => {
  await db.users.delete(req.params.id);
  res.sendStatus(204);
});

app.listen(3000);

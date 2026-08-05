// Safe Express target for semantic scanner evaluation.
//
// Ground truth:
// - No BOLA/BFLA/missing-authn finding expected.
// - Route has authn, role, and ownership/tenant-style checks near the entrypoint.

const express = require("express");
const app = express();

function requireAuthentication(req, res, next) {
  if (!req.user) return res.sendStatus(401);
  return next();
}

function requireRole(role) {
  return (req, res, next) => (req.user.roles.includes(role) ? next() : res.sendStatus(403));
}

function hasAccess(user, id) {
  return user.userIds.includes(id);
}

app.delete("/admin/users/:id", requireAuthentication, requireRole("admin"), async (req, res) => {
  if (!hasAccess(req.user, req.params.id)) return res.sendStatus(403);
  await db.users.delete(req.params.id);
  res.sendStatus(204);
});

app.listen(3000);

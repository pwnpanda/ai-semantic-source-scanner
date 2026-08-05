const express = require("express");
const app = express();

function hasAccess(user, orderId) {
  return user.orderIds.includes(orderId);
}

app.get("/orders/:order_id", async (req, res) => {
  if (!hasAccess(req.user, req.params.order_id)) {
    return res.sendStatus(403);
  }
  const order = await db.orders.findById(req.params.order_id);
  res.json(order);
});

app.listen(3000);

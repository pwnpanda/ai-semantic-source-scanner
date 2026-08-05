const express = require("express");
const app = express();

app.get("/orders/:order_id", async (req, res) => {
  const order = await db.orders.findById(req.params.order_id);
  res.json(order);
});

app.listen(3000);

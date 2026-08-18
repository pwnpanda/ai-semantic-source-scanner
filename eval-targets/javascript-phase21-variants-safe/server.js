// Safe near-misses for receiver and argument-sensitive Phase 21 detectors.

const express = require("express");
const Handlebars = require("handlebars");

const app = express();
const values = ["alpha", "beta"];
const render = Handlebars.compile("<p>{{value}}</p>");
const searchService = { findOne: (value) => value };

app.use(express.json());

app.post("/preview", async (req, res) => {
  const match = values.find((value) => value === req.body.filter);
  const unrelatedRecord = searchService.findOne(req.body.filter);
  const module = await WebAssembly.compile(req.body.moduleBytes);
  const parsed = new URL(req.body.url, "https://example.invalid");
  res.setHeader("X-Request-Label", "fixed");
  res.json({
    match,
    unrelatedRecord,
    module: Boolean(module),
    parsed: parsed.href,
    html: render(req.body),
  });
});

app.listen(9002);

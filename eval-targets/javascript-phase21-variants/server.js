// Positive Phase 21 variants: canonical receivers and constructor lowering.

const express = require("express");
const hbs = require("handlebars");
const { MongoClient } = require("mongodb");

const app = express();
const client = new MongoClient("mongodb://example.invalid");
const storedUsers = client.db("app").collection("users");
const users = storedUsers;
const transporter = { sendMail: async () => undefined };

app.use(express.json());

app.post("/preview", async (req, res) => {
  const filter = req.body.filter;
  const templateSource = req.body.template;
  const pattern = req.body.pattern;
  const headerValue = req.body.headerValue;
  const mailHeaders = req.body.mailHeaders;
  const records = await users.find(filter).toArray();
  const render = hbs.compile(templateSource);
  const matcher = new RegExp(pattern);
  res.setHeader("X-Request-Label", headerValue);
  await transporter.sendMail(mailHeaders);
  res.json({ records, preview: render({ records }), matches: matcher.test("probe") });
});

app.listen(9001);

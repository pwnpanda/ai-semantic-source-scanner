const { readFileSync } = require("node:fs");

const request = Object.create(null);
readFileSync(request.path, "utf8");

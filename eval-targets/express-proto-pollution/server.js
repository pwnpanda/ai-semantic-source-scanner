// Phase 20 positive — prototype pollution (CWE-1321).
// Source: req.body (attacker controls the full JSON object, including a
// "__proto__" key).
// Sink: a hand-rolled recursive merge that copies keys onto the target
// without filtering prototype-ish keys. POSTing
//   {"__proto__": {"isAdmin": true}}
// pollutes Object.prototype for the whole process.

const express = require("express");
const app = express();
app.use(express.json());

const settings = {};

function merge(target, source) {
    for (const key of Object.keys(source)) {
        if (typeof source[key] === "object" && source[key] !== null) {
            target[key] = target[key] || {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

app.post("/settings", (req, res) => {
    merge(settings, req.body);  // VULNERABLE: no __proto__ / constructor filter
    res.json(settings);
});

app.listen(3000);

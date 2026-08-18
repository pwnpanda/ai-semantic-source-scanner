// Phase 20 NEGATIVE (Recall-First Invariant 5) — same merge shape as the
// positive, but prototype-ish keys are rejected before assignment and the
// target is a null-prototype object. The candidate may still surface
// (Invariant 2: mitigations demote, never drop) but must not be an
// expected finding.

const express = require("express");
const app = express();
app.use(express.json());

const settings = Object.create(null);

const FORBIDDEN = new Set(["__proto__", "constructor", "prototype"]);

function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (FORBIDDEN.has(key)) {
            continue;  // drop prototype-polluting keys
        }
        if (typeof source[key] === "object" && source[key] !== null) {
            target[key] = target[key] || Object.create(null);
            safeMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

app.post("/settings", (req, res) => {
    safeMerge(settings, req.body);
    res.json(settings);
});

app.listen(3000);

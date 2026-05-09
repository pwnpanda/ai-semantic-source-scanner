# Nominations

## Stream A — Pre-traced

- [ ] N-001 | api | sqli | src/users.ts:42 | rec: high | y/n: 
    Summary: SQLi via id path param into pg.query.
    Flows: F-1 (CWE-89, template-literal)

- [ ] N-002 | api | xss | src/profile.ts:10 | rec: med | y/n: y
    Summary: Possible XSS in bio render.
    Flows: F-2 (CWE-79)

## Stream B — AI-discovered

- [ ] N-003 | api | idor | src/orders.ts:58 | rec: med | y/n: n
    Summary: Possible IDOR — no ownership check.
    Heuristic: req.params.orderId → Order.findOne; no req.user.id

## Stream C — Proposed model extensions

- [ ] N-004 | api | model-proposal | extensions/bullmq.model.yml | rec: high | y/n: 
    Summary: Library bullmq is unmodelled by CodeQL.

```yaml
extensions:
  - addsTo:
      pack: codeql/javascript-queries
      extensible: sourceModel
    data:
      - ["bullmq", "Worker.process", true, "remote", "", "", "Argument[0]", "manual"]
```

# ASP.NET Minimal API SQLi Eval Target

This target contains one intentional vulnerability:

| ID | CWE | Location | Source | Sink | Expected result |
| --- | --- | --- | --- | --- | --- |
| `ASPNET-MINIMAL-SQLI-001` | CWE-89 | `Program.cs` | route-bound `id` parameter in `app.MapGet("/users/{id}", (string id) => ...)` | `SqliteCommand.ExecuteReader()` | Report as SQL injection |

The `/health` route is intentionally clean.

This target is meant to compare Ghost-style LLM code scanning with
`ai-codescan` hybrid static analysis. The important shape is the implicit
ASP.NET Core minimal API binding: Joern exposes `id` as a lambda parameter,
not as a `Request.Query` or `HttpContext.Request` field access.

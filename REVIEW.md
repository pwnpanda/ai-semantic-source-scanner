# Review Notes

This file is for design review, not scan-result review.

It documents the choices made during the current implementation pass.

The full set of recall-first rules lives in `TODO.md` ("Recall-First Invariants 1–6"). Every section below tags itself against those invariants when relevant.

## Phase 14 — sanitizer_pattern cleanup, live LLM verification, cross-file matcher, CI removal

This session's work, driven by four explicit user directives.

### 1. Removed the `sanitizer_pattern` backward-compat fallback

`sanitizer_pattern` is a `ModelProposal` field with two historical meanings:
- **Semgrep (legitimate):** the `pattern-not` clause — code matching it is treated as sanitized. `apply_proposal_to_semgrep` still uses it this way. **Kept.**
- **Joern (back-compat hack):** before Phase 5.1 there was no dedicated field for the receiver-filter regex, so it was crammed into `sanitizer_pattern`. Phase 5.1 added `receiver_regex`; `apply_proposal_to_joern` kept a `receiver_regex or sanitizer_pattern` fallback for pre-5.1 proposals.

The user confirmed no pre-5.1 proposals exist anywhere, so the fallback was dead code. Removed:
- The `or proposal.sanitizer_pattern` fallback in `joern_extensions.apply_proposal_to_joern` — `receiver_regex` is now the sole source.
- `ai_codescan/proposal_migrate.py` (the whole module existed only to migrate the legacy shape) + `tests/test_proposal_migrate.py` + the `model-proposals migrate` CLI command.
- Stale field comment in `model_proposals.py`.

`sanitizer_pattern` the field stays — it has a real Semgrep job.

### 2. Live LLM verification of Phase 7 features

All three Phase 7 LLM-assisted features were verified against the real `claude`, `gemini`, and `codex` CLIs (all on the user's PATH). Probe: `severity_judge`, `proposal_routing_judge`, `proposal_clone_rewrite`. Results recorded in the Phase 14 verification block below — every provider returned parseable output and the parsers handled it. Phase 7 is no longer "mocked-only".

### 3. Cross-file eval matcher (polish)

`ExpectedFinding` gained optional `source_file` / `sink_file`. When set, the matcher checks the flow's source and sink files independently; when absent, it falls back to the single `file` field (every existing manifest entry is unaffected). This lets wrapper-style flows — source in controller, sink in a helper file — score as full matches instead of partials. `java-spring-sqli-custom-jdbc` updated to use it.

### 4. Removed the GitHub Actions CI workflows

Both `.github/workflows/test.yml` (the real lint+types+test+coverage workflow) and `.github/workflows/ci.yml` (the Phase 9 scaffold) deleted at the user's request — the project is developed, tested, and run locally 99% of the time, so PR-gated CI added no value. The whole `.github/` directory is gone. The `prek` pre-commit hooks stay (they run locally, which is the workflow the user wants) and are now the sole automated quality gate; the stale "local and CI parity" comment in `.pre-commit-config.yaml` was corrected.

### Phase 14 verification

- **Ruff:** `ruff check` + `ruff format --check` clean.
- **Pytest:** 567 pass / 2 skipped (569 collected). Down from 572 — `tests/test_proposal_migrate.py` (7 tests) deleted, 2 cross-file matcher tests added, 1 joern-extensions test rewritten to assert the new no-fallback contract.
- **Eval:** 33 pass / 3 miss / 36 total. `java-spring-sqli-custom-jdbc` moved partial → **pass** via the cross-file matcher. The 3 misses are still php/ruby/kotlin (Joern frontend limitations, Phase 12 — unchanged).
- **Live LLM probe** (`severity_judge`, `proposal_routing_judge`, `proposal_clone_rewrite`) — identical correct output from all three providers:
  - `claude`: severity `high`, route `custom-rule`, rewrite `(?i)^(fetch)$`
  - `gemini`: severity `high`, route `custom-rule`, rewrite `(?i)^(fetch)$`
  - `codex`:  severity `high`, route `custom-rule`, rewrite `(?i)^(fetch)$`
  Every provider's output parsed cleanly. `build_argv` shapes are correct for all three CLIs.

## Phase 19 — CSPT (Client-Side Path Traversal)

The user clarified: CSPT is client-side only, semantically a path-traversal class (CWE-22), and the discriminator is "user input lands in the URL's path section, before any `?`/`#`/`&`".

### What changed

A new JS-only post-loop block in `joern_queries.sc`. For every call whose name is in the HTTP-client set (`fetch` / `request` / `get` / `post` / ...), check the call's full source text against:

```
(?s)['"`]/[^?#&'"`$]*(?:['"`]\s*\+|\$\{)
```

A literal that starts with `/` and contains none of `?`/`#`/`&` before a concat (`+`) or template substitution (`${`). The `$`-exclusion in the character class is load-bearing — without it the greedy match swallows past the `${userId}` marker on template literals and the alternative never fires (caught in initial testing).

When the shape matches, the block runs `reachableByFlows(rawSources)` against the call's arguments and emits a `CWE-22` flow with `sink_class=cspt`. Scoring weight 0.12 — similar to `fs.read`, the recall-first stance is "show the candidate, scoring decides ranking".

### Eval targets

- `cspt-fetch-path` — positive: `location.search` → `` fetch(`/api/users/${userId}/profile`) ``. CSPT detector fires.
- `cspt-fetch-querystring-safe` — negative: `` fetch(`/api/profile?user=${userId}`) `` — the `?` before the substitution suppresses CSPT (the bare SSRF flow may still fire and is allowed in the manifest).

### Verification

- **Eval: 40 pass / 3 miss / 43 total.** Both new targets pass.
- **Pytest:** unchanged.
- **Ruff:** clean.

## Phase 18 — Open redirect, SSTI, email injection, fixpoint in scan

Audit of `joern_queries.sc` against the OWASP-y common vuln list surfaced four real gaps. This phase plugs three of them and finishes Phase 17's follow-up.

### Sinks added per language

| Class | CWE | Sinks |
|---|---|---|
| Open redirect | CWE-601 | JS `redirect`; Python `redirect`/`RedirectResponse`/`HttpResponseRedirect`; Java + Kotlin `sendRedirect`; Ruby `redirect_to`; C# `Redirect`/`RedirectToAction`/`RedirectToRoute`; Go `Redirect` |
| SSTI | CWE-1336 | Python `render_template_string` — added **in addition to** the existing CWE-79 mapping. The same flow emits both rows so reviewers see "this is XSS *and* potential Jinja RCE" |
| Email / SMTP header injection | CWE-93 | JS `sendMail` / `sendEmail` (nodemailer / sendgrid / ses); Python `send_message` / `send_mail` / `sendmail` (smtplib / Django) |

Scoring (`_DANGEROUS_SINK_CLASSES`) gained matching weights — `open.redirect` +0.10 (credential-phishing impact), `ssti` +0.22 (typically RCE), `email.send` +0.10.

### `secscan` now runs the storage_taint fixpoint

Closes Phase 17 follow-up A. The `scan` command's stage chain now slots `taint-schema` between `gate-2` and `validate`, so stored-XSS synthesis (Phase 17 `stored_xss.py`) auto-fires in the one-shot pipeline. Non-fatal: a repo with no recognisable storage patterns simply yields zero rounds.

### Eval targets

- `express-open-redirect` — positive: `req.query.next → res.redirect(next)`.
- `express-open-redirect-safe` — negative: same source gated by an allowlist `Set`.
- `python-flask-xss` manifest **updated** to pin both CWE-79 (reflected XSS) and CWE-1336 (SSTI) — the same `render_template_string(user_input)` is both.

### Verification

- **Eval: 38 pass / 3 miss / 41 total.** New open-redirect target passes (Joern's new `^redirect$` sink fires on `res.redirect(req.query.next)`); the allowlisted negative produces no flow. The SSTI-on-flask flow now correctly counts as a separate match, not a false positive.
- **Pytest:** 627+ collected, exit 0.
- **Ruff:** clean.

### What's NOT yet covered (the audit found these too — flagged for next pass)

- **XXE (CWE-611)** — no sinks anywhere. `DocumentBuilder.parse` (Java), `lxml.etree.parse` / `xml.sax.parse` (Python), `simplexml_load_string` (PHP), `XmlDocument.LoadXml` (C#). Well-defined, additive.
- **HTTP response splitting (CWE-93/444)** — `response.setHeader` / `addHeader` with attacker-controlled values. Java/Python/Go.
- **Prototype pollution (CWE-1321)** — JS-specific. `lodash.merge` / `_.set` / recursive merge with user input.
- **NoSQL injection (CWE-943)** — Mongoose `$where` / `$function` operators. Firestore is partially covered already.
- **LDAP / XPath injection (CWE-90 / CWE-643)** — `DirContext.search` / `XPath.evaluate`.
- **SSTI for non-Python** — Java Velocity / FreeMarker, Ruby ERB, JS Handlebars.
- **Sensitive logging beyond JS** — only JS has CWE-532 sinks; Python `logging.info(secret)`, Java `Logger.info`, etc. missing.
- **Email injection beyond JS/Python** — Java `JavaMailSender.send`, Ruby `Mail.deliver`, PHP `mail()`, Go `smtp.SendMail`.
- **CSPT (Client-Side Path Traversal)** — needs a design call (the sink overlaps SSRF; the discriminator is structural, not a call-name). Question to the user.

## Phase 17 — stored + reflected XSS coverage

Closes the user's follow-up to Phase 16: "Just DOM will cause us to miss vulns." Adds stored-XSS synthesis on top of the existing `storage_taint` pipeline and a small reflected-XSS sink gap-fill per language.

### Stored XSS

`ai_codescan/stored_xss.py` — new module. The existing `storage_taint` pipeline (round-2 fixpoint) already marks a `storage_id` "dirty" when a request-controlled value writes to it, and emits `write_origin → write → read_site` flows that inherit the contributing flow's CWE. That tracks **stored-injection**, not stored-XSS — Joern can't see "the read result later flows into a render sink" on its own because the source pattern only matches HTTP shapes, not storage reads.

`synthesize_stored_xss_flows(conn)` closes that gap with a recall-first proximity heuristic:

> For every tainted `storage_id` that has at least one `storage_reads`, find every Joern CWE-79 `html.write` flow whose sink lands in the **same file** as the read. Emit a synthetic 4-step `CWE-79` flow `[origin, write_site, read_site, xss_sink]` with `engine="stored-xss-r3"` and `confidence="inferred"`.

Wired into `storage_taint.run_full_fixpoint` as step 5 of each iteration so any caller that runs the fixpoint (currently `ai-codescan taint-schema`) gets stored XSS for free. Idempotent — synthetic fids are content-addressed.

Recall-first reconciliation:
- The same-file proximity gate is **deliberately coarse**. A reviewer (or the adversarial validator) handles the false positives; the cost of a tighter gate is missing a real bug. A same-function gate is a follow-up once the call graph is wired into the proximity check.
- The detector **excludes its own synthetic engine** from the XSS-flow scan — without that filter, every newly-emitted CWE-79 stored flow would feed the next iteration's scan, an infinite ladder.

6 unit tests cover: emits on same-file render, suppresses on cross-file render, idempotent re-run, no-op without `storage_taint` / `storage_reads`, no-op without schema.

### Reflected XSS sink gap-fill

Audit found the existing sinks were broadly correct but missed a few framework idioms. Added (precise call names, no receiver filter needed):

- **Python**: `make_response` (Flask), `HttpResponse` (Django) — both common patterns for returning a hand-built HTML body.
- **C# / Razor**: `Raw` (`@Html.Raw(x)`) and `HtmlString` constructor — both explicit opt-outs of the template engine's auto-escaping.
- **Ruby / Rails**: `send_data` — accepts an HTML body when `type:'text/html'`.

Eval still **36 pass / 3 miss / 39**: the new sinks don't fire on existing targets (no false positives), and existing reflected-XSS targets (`express-xss`, `python-flask-xss`, `java-spring-xss`) still pass.

### What's NOT in this slice (documented limits)

- **No end-to-end stored-XSS eval target.** A real positive target needs `storage_taint.run_fixpoint` to recognise the target's specific DB-write pattern (it knows common SQL access via `database/sql`, `mysqli`, ActiveRecord, Sequelize raw SQL; ORM method chains may not be modelled). Unit tests verify the `stored_xss.py` synthesis logic given the right preconditions; full pipeline verification needs a target whose write pattern `run_fixpoint` already understands. Follow-up.
- **Stored XSS is gated on the user running `taint-schema`.** It runs inside `run_full_fixpoint`, which only `taint-schema` calls today. Wiring `run_full_fixpoint` into `analyze` / `secscan` is the obvious next step — kept out of this slice because it changes the default pipeline cost (the fixpoint can be expensive on large repos).
- **Jinja2 `|safe`, Django template autoescape off, JSP `<%= %>`** — template-engine bypasses below Joern's CPG view. Detecting these needs a template-aware static analyser; not in scope.

## Phase 16 — pure-JS DOM-XSS coverage

The JS branch in `joern_queries.sc` was server-side only (Express `req.*` / `request.*`, response writes `res.send/write/end`). DOM-XSS sources and sinks weren't modelled at all.

### What changed in `joern_queries.sc`

1. **Explicit `case "javascript" | "typescript" | "jssrc" | _` block** (was the catch-all `case _`). Adds DOM sources alongside the server-side ones:
   `location.hash` / `.search` / `.href` / `.pathname`, `document.URL` / `.referrer` / `.baseURI` / `.documentURI`, `window.name`, `event.data`, `history.state`, `localStorage.getItem` / `sessionStorage.getItem`, `URLSearchParams`.
2. **DOM call-shaped sinks** added to `sinkClasses`:
   - CWE-79 (`html.write`): `insertAdjacentHTML`, `parseHTML`, plus `writeln` joining the existing `send|write|end` set.
   - CWE-94 (`code.exec`): `eval`, `Function`, `setTimeout`, `setInterval`.
3. **`xssReceiver` updated** to accept `document.write` / `document.writeln` (the DOM shape) alongside the server-side `res|response|reply|ctx.send|write|end`.
4. **`restrictXssSinks` JS CWE-79** now filters by receiver only for the *ambiguous* call names (`send`/`write`/`end`/`writeln`); precise DOM names (`insertAdjacentHTML`, `parseHTML`) pass through.
5. **Property-assignment sink scan** (the meaty new logic): `el.innerHTML = ...` lowers to `<operator>.assignment` with a fieldAccess LHS — the per-sinkClass call-name loop never sees it. A new post-loop block walks `cpg.call.name("<operator>.assignment")`, checks the LHS code matches `(?i).*\.(innerHTML|outerHTML|dangerouslySetInnerHTML)\s*$`, and runs `reachableByFlows(rawSources)` against the RHS. Emits standard flow JSON with `flow_type=dataflow`. Mirrors the existing Python HTTP-client assignment pre-pass shape.

### Eval targets (Recall-First Invariant 5)

- `eval-targets/dom-xss-innerhtml` — **positive**: `location.hash` → `el.innerHTML`. Exercises the property-assignment scan.
- `eval-targets/dom-xss-eval` — **positive**: `location.search` → `eval(...)`. Exercises the new CWE-94 `eval` call sink.
- `eval-targets/dom-xss-textcontent-safe` — **negative**: same `location.hash` source, but assigned to `el.textContent` (no HTML parsing). Must not flag.

Each ships a minimal `package.json` so `stack_detect` classifies the dir as NODE (bare `.js` without a manifest is invisible to project detection — surfaced when the first run skipped in 0.04 s).

### Verification

- **Eval: 36 pass / 3 miss / 39 total** (up from 33/3). All 3 DOM-XSS targets pass with real Joern flows — `dom-xss-innerhtml` matched via the property-assignment scan (~13 s), `dom-xss-eval` via the new `eval` call sink, `dom-xss-textcontent-safe` correctly produced no flows. The 3 remaining misses are still the Phase 12 Joern frontend limitations (PHP/Ruby/Kotlin).
- **Pytest:** 619 pass / 2 skipped (621 collected) — unchanged.
- **Ruff:** clean.

### Trade-offs

- The property-assignment scan matches on `lhsCode` text rather than walking the fieldAccess sub-AST. Text-based but the text is the parser's own `.code` field, so layout/formatting variance doesn't matter — same robustness as the Python pre-pass it mirrors.
- `setTimeout`/`setInterval` flag whenever attacker-controlled data reaches them, even though only the *string-argument* form is dangerous (callback-argument form is fine). False-positive risk is real but recall-first-aligned: a reviewer can dismiss; the scanner mustn't miss `setTimeout(userInput)`.
- The new sources include `localStorage`/`sessionStorage` reads. Strictly these are attacker-controllable only if the attacker also stored the value — second-order. Kept in because the project's recall-first stance prefers a noisy true positive over a silent miss, and second-order DOM-XSS is real.

## Phase 15 — HTML report + call-graph extraction

First two-thirds of the single-command-runner request. The `secscan` one-shot runner + HITL gates are still pending (see end of section).

### Call-graph extraction (`ai_codescan/call_graph.py`)

`build_call_graph(conn)` collapses the DuckDB `symbols` + `xrefs` (SCIP cross-reference) tables into a `{"nodes": [...], "edges": [...]}` shape. Nodes are callable symbols (functions/methods); edges are caller→callee xrefs. `finding_files(conn)` reads every file along every `flows.steps_json` path; nodes in those files are flagged `on_finding_path` so the report highlights the vulnerable region. `max_nodes` caps the graph (finding-path nodes kept preferentially) so a huge repo still renders. Empty graph — never an error — when the repo has no SCIP index. 6 tests.

### HTML report (`ai_codescan/html_report.py` + `report --html`)

`render_html_report(findings, out_dir, conn)` writes a self-contained report tree:

- `report.html` — the findings list. Each finding is a card: **title + criticality badge**, a **2–4 line summary** (first non-heading lines of the body), the **full detail behind a native `<details>` toggle** (collapsed by default — source, evidence, analysis), and a **link to its flow graph**. Pure HTML/CSS, zero JavaScript — it always renders. Findings sorted by severity. Bodies are `html.escape`d (they carry source code — XSS-safe).
- `call-graph.html` — whole-repo call graph, finding-path nodes in red. React Flow via esm.sh (no build step).
- `flow-<finding>.html` — per finding, the source→sink chain.
- `entrypoints.html` — entrypoint→sink map.

Graph pages are linked, not inlined, so the report page stays light (the user explicitly OK'd this). Reachable via `ai-codescan report --html`.

Design choices & trade-offs:
- **The findings page is JS-free.** `<details>` is native HTML — the user's items 1–3 (title/criticality, summary, toggled detail) render with no dependency. Only the graph pages need JS + network (esm.sh).
- **React Flow via esm.sh importmap** — the user asked for "react flow"; esm.sh is the established no-build CDN pattern. Node positions are computed in Python (a deterministic grid for the call graph, a vertical chain for flows) because the project ships no layout engine — adding `dagre` was not worth a dependency.
- **Verified:** all 4 page types generate and parse cleanly (`html.parser`); 6 unit tests cover cards, escaping, severity sort, graph-page emission, embedded flow data. The React Flow *render* itself needs a browser — that is the user's "start testing" pass; I validated structure and embedded JSON, not a live render.

### `secscan` one-shot runner + HITL gates

`ai-codescan scan <path>` + the `secscan` console script (`secscan .`). Chains the full pipeline as subprocesses — `prep → nominate → gate-1 → analyze → gate-2 → validate → gate-3 → report --html` — reusing each existing subcommand verbatim (the runner is pure orchestration, not a reimplementation).

- **HITL gates.** Three pause points: `gate-1` (nominations.md), `gate-2` (findings/), `gate-3` (sign-off). Each gate command already opens the file in `$EDITOR`; the runner adds a "press Enter to continue" after. `--skip-hitl` runs every gate with `--yes` (fully unattended). A non-interactive stdin is treated as "continue" so a piped/CI run does not hang.
- **`secscan` entry point.** `pyproject.toml` `[project.scripts]` adds `secscan = "ai_codescan.cli:secscan_main"`; `secscan_main` forwards argv to the `scan` command so `secscan . --skip-hitl` works.
- **Validator non-fatal.** `validate` (PoC + Docker sandbox) runs but a non-zero exit (e.g. no Docker) does not abort the scan — the run completes to the report, just with nothing flipped to `verified`. Every other stage is fatal.

Trade-offs:
- Subprocess-per-stage (vs. calling the `run_*` functions directly) was the deliberate choice: it reuses each command's exact contract, isolates failures, and lets `$EDITOR` + the press-Enter prompt inherit the TTY cleanly. The cost is process-spawn overhead — negligible against LLM-stage runtime.
- `secscan --help` shows `secscan scan [OPTIONS]` — the forwarded `scan` subcommand name leaks into the usage line. Cosmetic; `secscan .` works correctly.
- The validator-non-fatal choice means a Docker-less host gets an empty `report.html` (nothing verified). Honest, but a follow-up could let the HTML report show `unverified` findings too.

Verified: 3 mocked-sequence tests (`test_cli.py`) — stage order, fatal-abort on `prep` failure, non-fatal `validate`. `secscan --help` smoke-tested. A full live `secscan .` run (real LLMs + Docker) is the user's testing pass.

## Phase 13 — completion (scoring, consensus, reachability, recon)

The `evilsocket/audit` upgrade is now complete. Slice 1 (below) shipped the adversarial challenger; this section covers the rest.

- **Adversarial result as a score factor** — `adversarial_validator.adversarial_score_delta` maps a challenge consensus to a ranking delta: a disputed true-positive demotes (`adversarial_disputed`, −0.2), a disputed false-positive *re-elevates* (`adversarial_recall_flag`, +0.3 — the recall-critical inversion), a corroborated true-positive gets a small boost. `scoring._adversarial_factor` reads it; `adversarial-review` runs a re-score pass so a dispute shifts candidate ranking immediately.
- **Multi-challenger consensus** — `ChallengeConsensus` / `challenge_consensus_all` collapse every challenger's row for a finding into a majority verdict (`confirmed` / `disputed` / `split`). The score factor reads the consensus, so stacking `adversarial-review --challenger gemini` then `--challenger codex` strengthens the signal rather than the last writer winning.
- **Reachability as a verdict input** — `reachability_note` / `with_reachability_evidence` prepend a "data-flow proven" vs "co-location only — reachability unverified" line to the verdict evidence before the challenge (audit pillar #5). The challenger argues with reachability in hand. Recall-first: it informs the challenge, it does not gate or drop anything — co-location flows already self-demote via the existing `colocation_fallback` score factor.
- **Git-history recon + feedback loop** — `ai_codescan/recon.py` + the `recon` CLI. Two audit pillars collapse to one output ("which files to re-hunt"): git-history recon mines security-keyworded commits for once-vulnerable files; the feedback loop takes confirmed findings (true-positive AND not adversarially disputed). Both contribute their *sibling* files (same dir, same extension — the cheapest "same idiom" heuristic). Writes `recon_hints.jsonl`. Recall-first: recon only ever adds files to look at.

Trade-offs:
- The score-factor re-score in `adversarial-review` rebuilds the whole candidate queue (`build_queue` + `score_candidates`). For a large repo that's a few seconds of DuckDB work — acceptable, and it keeps the scoring path single-sourced rather than patching individual rows.
- `recon`'s sibling heuristic is deliberately crude (directory + extension). A real call-graph-aware "same idiom" would be sharper but needs the call-graph extraction that's slated for the HTML-report work. Crude-but-recall-first is the right default: a wrong sibling just means one extra file scanned.
- `recon_hints.jsonl` is produced but not yet *consumed* by the nominator queue — that wiring is deferred to the single-command runner work (documented in TODO Phase 13).

Tests: +20 across `test_adversarial_validator.py` (consensus, score delta, reachability) and the new `test_recon.py` (9). Live verification of the challenger against claude/gemini/codex stands from slice 1.

## Phase 13 — Adversarial cross-model validation (slice 1)

First slice of the `evilsocket/audit`-inspired validation upgrade (the planning lives in `TODO.md` Phase 13). audit's central idea: a finding is only trustworthy once a *second, independent model* has tried and failed to disprove it. A single reviewer's verdict is an unreliable signal.

### What shipped

`ai_codescan/adversarial_validator.py` + the `ai-codescan adversarial-review` CLI command.

For every decisive `review_verdicts` row (`true-positive` / `false-positive`), a challenger LLM — a *different provider* than the reviewer — is told to argue the opposite case:

- original `true-positive`  → challenger argues it is a false positive.
- original `false-positive` → challenger argues it is actually exploitable.

The result is uniform: `confirmed` (challenger agrees), `disputed` (challenger disagrees), `inconclusive`. Challenges land in a new `adversarial_challenges` table, keyed `(finding_id, challenger_provider)` so multiple challengers stack.

### Recall-first reconciliation (the key divergence from audit)

audit *drops* findings that fail validation. ai-codescan's Recall-First Invariants forbid silent drops, so a challenge **never deletes anything** — it records a row. The two disputed cases are handled by severity, not suppression:

- A disputed **true-positive** is a possible false positive — the CLI notes it for a second look, but the finding stays in the queue.
- A disputed **false-positive** is a possible *missed* vulnerability — the recall-critical case. The CLI flags these loudly (`⚠ N dismissed finding(s) the challenger thinks are REAL`). This is the inversion that makes adversarial validation serve recall, not just precision: the most valuable thing a second model can do here is catch a bug the first reviewer wrongly dismissed.

### Design choices & trade-offs

1. **Direct `build_argv` + subprocess**, not the skill-loop. The challenge is a single-shot per-verdict call with a narrow input (the verdict's cited evidence), so it mirrors the Phase 7 judges (`severity_judge` etc.), not the heavier `miss_review` skill loop. Trade-off: the challenger sees only the evidence the *first* reviewer cited, not the raw source. That's deliberate for cost, but it means a reviewer who cited thin evidence gets a thin challenge. Deeper source-reading is a documented follow-up.
2. **Schema-driven JSON output** (audit pillar #8). The prompt asks for `{"result": ..., "rationale": ...}`; `parse_challenge_output` parses JSON first, then falls back to a token scan for models that ignore the instruction.
3. **Challenger independence is the caller's job.** `review_verdicts` records the reviewer *skill* name, not its LLM provider, so the module can't auto-enforce "different model". The CLI defaults `--challenger gemini` (the reviewers default to `claude`), and the help text states the requirement. A future improvement: record the provider on each verdict so the mismatch can be enforced.
4. **Opt-in.** `adversarial-review` is a separate command, never auto-run — it is extra LLM spend (Invariant 4: cost limits opt-in only).
5. **Failure is silent-safe.** A challenger that times out / crashes / emits garbage returns None and the verdict is simply left unchallenged. A broken challenger must not break the pipeline.

### What's NOT in this slice (deferred — see TODO Phase 13)

- The challenge result is not yet a `scoring.py` score factor — it lives only in `adversarial_challenges`. Wiring it into ranking needs a re-score pass after adversarial-review.
- No multi-challenger consensus aggregation (the table supports stacking; nothing aggregates yet).
- Reachability-as-a-gate, the feedback loop, and git-history recon — the other audit pillars — are untouched.

### Tests

17 unit tests in `tests/test_adversarial_validator.py`: JSON + token-fallback parsing, prompt framing per verdict direction, challenger construction (raises on unavailable provider), mocked-subprocess success / skip-non-decisive / failure / unparseable paths, persistence idempotency + multi-challenger stacking, and the summary counts.

### Live verification

Probed the challenger against all three CLIs with two verdicts — a genuine SQLi (raw string concatenation, `true-positive`) and a safe parameterized query (`false-positive`):

- `claude`:  TP → `confirmed`, FP → `confirmed`
- `gemini`:  TP → `confirmed`, FP → `confirmed`
- `codex`:   TP → `confirmed`, FP → `confirmed`

Every challenger correctly resisted disputing a correct verdict — it could not disprove the real bug, and it agreed the parameterized query is safe. The `disputed` path is covered by the unit tests (mocked subprocess).

End-to-end CLI: `adversarial-review --challenger gemini` against a seeded `review_verdicts` row produced `1 challenged — 1 confirmed` and persisted the row to `adversarial_challenges`. The first run also exercised the recall-first ops path — a 60 s timeout was caught, logged, and the command completed cleanly with `0 challenged` rather than crashing. The per-challenge default timeout was raised to 180 s (these CLIs routinely take 60–120 s) and a `--timeout` option added.

### Phase 13 verification

- **Ruff:** `ruff check` + `ruff format --check` clean.
- **Pytest:** 584 pass / 2 skipped (586 collected) — 17 new `test_adversarial_validator.py` tests.
- **Live:** verified against claude/gemini/codex (above).

## Wake-Up Summary — Phases 6, 7, 8, 9 (autonomous overnight run)

Phases ran in sequence (Coverage breadth → LLM-assisted polish → Operational maturity → Schema migration + CI + CodeQL extension). Final state:

- **Eval:** 32/32 pass (no regressions from any phase). New targets: 4 Java/Spring (sqli/ssrf/xss/authz-missing) + 1 Go (net-ssrf).
- **Pytest:** 565 pass / 2 skipped. New tests: severity_judge (8), proposal_routing_judge (5), proposal_clone_rewrite (5), proposal_migrate (7), codeql_extensions (5), Phase 8 auto-invoke (2), Phase 6 eval-target alignments + miss-finder regex (handled via existing test surface).
- **Ruff:** clean.
- **Joern script:** `restrictXssSinks` made language-aware (Phase 6 caught a bug where JS-shaped XSS/SSRF receiver regexes were rejecting Java sinks). Java SSRF sinks added (RestTemplate/WebClient/openConnection/openStream). Go SSRF sinks added (Post/PostForm/NewRequest/Do; `Get` only via Phase 5 extensions). `_STATE_CHANGE_RE` in miss_finder now matches `DeleteMapping` / `PostMapping` (Spring annotation case-change).
- **CodeQL fallback:** `_run_codeql_for_projects` now catches `subprocess.SubprocessError` so a missing `go` toolchain doesn't fail the whole case (recall-first applies to ops).
- **LLM-assisted features** (Phase 7): `derive_meta(llm_judge=...)`, `triage_and_route(llm_route=...)`, `clone --rewrite-with-llm` — all opt-in callables with deterministic fallbacks. Tested via mocked subprocesses; live LLM verification requires the user's CLI configured.
- **Single-command UX** (Phase 8): `analyze` now auto-invokes `miss-finder` + `miss-review` at the end. `--skip-miss-review` preserves the old workflow.
- **Schema migration tool** (Phase 9): `model-proposals migrate` walks proposals on disk and moves `sanitizer_pattern` → `receiver_regex` for Joern-target proposals. Once it returns `migrated=0` on a clean repo, the back-compat fallback in `apply_proposal_to_joern` can be deleted.
- **CodeQL pack extension** (Phase 9): scaffolded as `ai_codescan/codeql_extensions.py` + YAML renderer + 5 unit tests. Production wiring into `engines/codeql.py` is deferred (parallel ~30 lines to the Semgrep path).
- **CI workflow + pre-commit** (Phase 9): `.github/workflows/ci.yml` runs ruff + pytest on PR. Existing `.pre-commit-config.yaml` was richer than my scaffold so I left it alone.

Open items (none blocking, all documented further down):
- ~~LLM-assisted features need live verification.~~ **Done in Phase 14** — verified against claude/gemini/codex.
- ~~`sanitizer_pattern` legacy fallback.~~ **Removed in Phase 14.**
- Kotlin/PHP/Ruby eval targets exist (Phase 12) but currently miss because their Joern frontends are immature (rubysrc2cpg is beta; kotlin2cpg lacks symbol resolution for Spring annotations; php2cpg needs `php` on PATH which isn't installed on every host). Documented as honest coverage gaps. See Phase 12 section.
- Java/Spring CodeQL eval target shipped (`java-spring-sqli-custom-jdbc`) but full end-to-end CodeQL extension verification needs `codeql` on PATH. Documented as a coverage positive that Joern catches via stock pattern; the CodeQL extension path is verified by unit tests of the renderer + prep helper.
- Phase 13 (adversarial multi-stage validation, modelled on `evilsocket/audit`) is planned in TODO.md — not started.

## Phase 11 — CodeQL Engine Runner Integration

Closes the Phase 10 callout: `engines/codeql.py` now auto-renders the YAML data-extension files at scan time.

Invariants: none (correctness).

Implemented:

1. **`ai_codescan/prep.py: _render_codeql_extension_packs(repo_dir)`** — reads `<repo_dir>/aics-codeql-extension-packs.json` (promoted only; staged entries stay invisible) and emits per-language YAML files via `render_codeql_yaml_extensions` into `<repo_dir>/codeql/model-packs/<lang>/`. Returns the language dirs.
2. **`_run_codeql_for_projects`** invokes the helper once before the per-project loop, then filters the resulting language dirs to the project's language and passes them to `run_queries(extension_packs=...)`. The runner threads them through as `--model-packs <dir>` (existing surface).
3. **`render_codeql_yaml_extensions`** now also writes `codeql-pack.yml` per language dir declaring `library: true` + `extensionTargets: codeql/<lang>-all` + `dataExtensions: extension.yml`. Without this manifest, `--model-packs <dir>` is silently ignored by recent CodeQL CLI versions — the YAML extension files never reach the analysis, so the model proposal flow would have looked working in tests but produced no behaviour at scan time.
4. **Tests added (3):** `prep_helper_renders_extension_packs_when_sidecar_present`, `prep_helper_returns_empty_when_no_sidecar`, and a manifest-assertion extension to the existing `render_yaml_extensions_writes_per_language_file`.

Trade-offs:
- The pack manifest pins `version: 0.0.1` literally. Future CodeQL versions could tighten manifest validation; the version number is non-meaningful (the pack is never published).
- Per-language filtering in the prep helper means a Java extension entry won't reach a Python CodeQL scan even if Python wouldn't fail on it. The filter is conservative — keeps `--model-packs` arguments well-typed across CodeQL versions.

What's still NOT done in this phase (and why):
- No live integration test that runs `codeql database analyze` end-to-end against a target with extensions applied. Reason: CodeQL toolchain isn't on CI hosts and the eval suite is explicitly gated off CI for runtime reasons. The unit tests cover renderer output + prep-helper plumbing; integration verification is the user's local-eval responsibility.

## Phase 12 — Coverage Breadth (Kotlin/PHP/Ruby)

Closes TODO Phase 9 line 433: "Cover at least C#, JS/TS, Python, Java/Kotlin, Go, PHP/Ruby where practical."

Invariants: 5 (every model expansion ships with a negative target — these are coverage targets, not model expansions, but the principle applies).

Added eval targets:

1. **`php-mysqli-sqli`** — `$_GET["id"]` flows into `$conn->query(...)` (mysqli). Sink line 10.
2. **`ruby-sinatra-sqli`** — `params[:id]` flows into `db.execute("... #{id}")`. Sink line 12.
3. **`kotlin-spring-sqli`** — `@RequestParam id: String` flows into `jdbc.queryForObject("... $id", ...)`. Sink line 14. Includes a minimal `build.gradle.kts` so `stack_detect` classifies the dir as a JVM project; without the manifest, `detect_projects` returns empty and the eval skips silently.
4. **`java-spring-sqli-custom-jdbc`** — Spring controller using a custom JDBC wrapper (`CustomJdbcWrapper.runSelect`). Documents the LLM-proposed-CodeQL-extension shape (no stock CodeQL model). Joern catches it via stock `queryForObject` on the wrapper's delegate call.

Outcome on this host:

- `java-spring-sqli-custom-jdbc`: **pass** (since Phase 14). Joern detects the CWE-89 flow with source in `UserController.java:17` and sink in `CustomJdbcWrapper.java:18`. Phase 14 added `source_file` / `sink_file` to the eval matcher, so this cross-file flow now scores as a full match. (Before Phase 14 it was a partial — the single `file:` field couldn't match both endpoints.)
- `php-mysqli-sqli`: **miss** — `joern-parse --language PHP` fails because `php` isn't on the host PATH (php2cpg shells out to PHP-Parser). The case becomes "pass" on a host with `php` installed.
- `ruby-sinatra-sqli`: **miss** — `rubysrc2cpg` produces a CPG with no identifier nodes for `params`. This is consistent with Joern's official "beta" status for the Ruby frontend; metaprogramming and DSL-style code (Sinatra blocks) are routinely under-modelled.
- `kotlin-spring-sqli`: **miss** — `kotlin2cpg` parses the file but doesn't model `@RequestParam` as a source. Resolution of Spring annotations on Kotlin is weaker than on Java.

Final eval (after Phase 14): **33 pass / 3 miss / 36 total**. The 3 misses are honest gap measurements (php/ruby/kotlin Joern frontends). Recall-first principle: keep the targets in the manifest so each future improvement is visible; remove them only if we decide the language won't be supported.

Trade-off — should the misses block? No. The Phase 1 invariant ("optimize against false negatives") applies to the scanner's behaviour, not to the eval suite's pass rate. A miss in the eval is a measurement of where the scanner currently can't see; suppressing the target would mean we *stop* measuring the gap. The user can still merge with these misses present — they show up as documented Joern frontend limitations.

Phase 12 done; the targets stay in place.

## Phase 10 — CodeQL CLI + Triage Wiring

## Phase 10 — CodeQL CLI + Triage Wiring

Closes the deferred Phase 9 callouts for CodeQL: `model-proposals apply --engine codeql` and `triage_and_route` routing for `target_engine="codeql"` proposals. Symmetric with the Joern flow from Phase 5.

Invariants: none (correctness — closes a Phase 9 callout). Recall-first applies indirectly: an unwired engine path means LLM-proposed CodeQL sinks were lost.

Implemented:

1. **`codeql_extensions.staged_path_for`** — returns the `.staged.json` sibling, parallel to the Joern helper. `apply_proposal_to_codeql(..., staged=True)` is now the default (mirrors Joern). Existing direct-call tests pass `staged=False` to assert against the promoted file.
2. **`codeql_extensions.promote_codeql_extension(proposal_id, *, extension_path)`** — moves a staged entry to the promoted file. Parallel to `promote_joern_extension`.
3. **CLI: `model-proposals apply --engine codeql`** — third branch in `cli.py:model_proposals_apply`, parallel to the Joern branch. Honours `--promote` to write directly to the active file, otherwise stages. Records the decision in `proposal_decisions` with engine `codeql-extension:<language>`.
4. **`triage_and_route` codeql branch** — proposals with `target_engine="codeql"` and a `sink_pattern` route to `apply_proposal_to_codeql(..., staged=True)`. Decision engine prefix `codeql-extension-staged:<language>`. Empty `sink_pattern` falls through to the existing Semgrep-or-pending path.
5. **Return shape** — `triage_and_route` now returns `routed_to_codeql` alongside the existing counts. Callers updated (`tests/test_proposal_triage.py`, miss-review status echo line).
6. **Tests added (5):** `apply_proposal_stages_by_default`, `promote_moves_staged_to_promoted`, `promote_missing_proposal_returns_none` (codeql_extensions); `triage_routes_codeql_target_engine_to_extensions`, `triage_codeql_proposal_without_sink_pattern_falls_back_to_pending` (proposal_triage).

What's still NOT done:
- `engines/codeql.py` does not auto-call `render_codeql_yaml_extensions` during prep. Users still set `AICS_CODEQL_EXTENSIONS_DIR` and pass `--additional-packs <dir>` to `codeql database analyze` themselves. The reason this stayed deferred: it requires per-language pack-name plumbing through the `engines/codeql.py` runner and an integration test that ships a CodeQL toolchain. Phase 11 candidate.
- No live end-to-end eval target proving the CodeQL extension changes a finding (parallel to `python-flask-ssrf-custom-client` for Joern). Adding one needs a small Java/Spring app that exercises a non-stdlib JDBC wrapper.

Why this approach (CLI + triage now, runner integration later):
- The CLI surface is the user-visible contract; without it, the YAML renderer in Phase 9 was unreachable from the proposal flow.
- The triage routing means the single-command `analyze` flow now creates CodeQL extensions automatically when the LLM returns `target_engine="codeql"` — closing the asymmetry where only Semgrep and Joern proposals could be auto-routed.
- Runner integration is a deeper change that needs its own validation gate; doing it under the same change risked the rest of the wiring being blocked behind a flaky CodeQL CI step.

Trade-off note: the staged-by-default change for `apply_proposal_to_codeql` is technically a breaking API change for any caller that relied on the path argument going to the promoted file. Only the Phase 9 tests called it directly and were updated to pass `staged=False`. No production callers existed (the CLI branch is the first one).

## Original Wake-Up Sections (preserved from Phase 9)



## Current Phase — Schema Migration + CI + CodeQL Extension

Three deliverables wrapping up the deferred work from earlier phases:

1. **Schema migration tool** — `model-proposals migrate` walks existing proposal JSONs on disk and moves `sanitizer_pattern` → `receiver_regex` for `target_engine=joern` proposals (Phase 5.1 callout). After migration, the fallback in `apply_proposal_to_joern` can be removed; the migration tool flags whether any proposals still use the legacy field.
2. **CodeQL pack extension** — `aics-codeql-extensions.yml` sidecar, mirroring the Phase 5 Joern extension shape. CodeQL data-extension YAML files are merged into the per-language pack at scan time.
3. **CI workflow + pre-commit** — GitHub Actions workflow running pytest on PR; `prek` hooks (ruff check + format) for local pre-commit. Skips the eval suite in CI (needs Joern + scip-python + CodeQL + ~10 min).

## Schema Migration Tool (`model-proposals migrate`)

Invariants: none (correctness — closes a Phase 5.1 callout).

Implemented change: new module `ai_codescan/proposal_migrate.py` + CLI command `model-proposals migrate [--dry-run]`. Walks the proposals directory, finds Joern-target proposals where `sanitizer_pattern` carries the receiver predicate (the pre-5.1 fallback shape), and rewrites them to use the dedicated `receiver_regex` field. Result counts: migrated / already_migrated / not_joern / skipped_no_legacy_value / files_seen.

The migration is reversible (git restore) and non-destructive on Semgrep proposals — they keep `sanitizer_pattern` because that's its proper meaning there.

Once `migrate` returns 0 migrations on a clean repo (every Joern proposal has `receiver_regex` set), the fallback in `joern_extensions.apply_proposal_to_joern` can safely be removed. Until then, the fallback stays for back-compat.

Relevant for: schema cleanliness, learning-loop hygiene.

## CodeQL Pack Extension (`ai_codescan/codeql_extensions.py`)

Invariants: 5.

Implemented change: new module providing the same shape as Phase 5's Joern extensions, for CodeQL. Sidecar JSON `aics-codeql-extension-packs.json` holds `(language, cwe, package, type_name, method_name)` entries; `render_codeql_yaml_extensions` emits per-language CodeQL data-extension YAML files (`<out_dir>/<language>/extension.yml`) that `codeql database analyze` can pick up via `--additional-packs`.

This closes the third corner of the engine-extension triangle (Semgrep packs + Joern sinks + CodeQL data extensions). Proposals routed via `target_engine="codeql"` would auto-apply to this sidecar, but the CLI surface for that auto-routing is not yet wired (manual `apply --engine codeql` is the path — also not yet wired in cli.py because every codeql query suite expects different pack names, and threading that through `engines/codeql.py` is a substantial change).

What's done in this phase:
- `apply_proposal_to_codeql(proposal, *, extension_path)` — appends an entry. Idempotent. Refuses empty sink_pattern.
- `render_codeql_yaml_extensions(extension_path, *, out_dir)` — emits per-language YAML files keyed on `addsTo.pack=codeql/<language>-all` with rows for `sinkModel`.
- 5 unit tests covering apply / idempotency / empty-refusal / YAML render / missing-input.

What's NOT done in this phase (deferred):
- CLI command `model-proposals apply --engine codeql`. The handler exists in joern's flow; wiring CodeQL is a parallel ~30 lines.
- `engines/codeql.py` integration: the renderer doesn't auto-run during prep, and `codeql database analyze` doesn't get `--additional-packs <out_dir>` automatically. Users invoke the renderer manually for now.
- `triage_and_route` routing for `target_engine="codeql"` proposals.

Why deferred: each of these is straightforward but the CodeQL test surface is heavyweight (real codeql + a target codebase). Phase 9's scope was scaffolding the modules + tests; production wiring is a Phase 10 task.

Relevant for: CodeQL extensibility, future learning-loop coverage.

## CI Workflow (`.github/workflows/ci.yml`)

Invariants: none (operational hardening).

Implemented change: new GitHub Actions workflow runs `ruff check` + `ruff format --check` + `pytest -q` on every PR and push-to-main. Eval suite deliberately excluded — needs Joern, scip-python, CodeQL, and ~10 minutes of runtime. CI guards code quality; eval runs locally via `scripts/test-joern-upgrade.sh` or manual `python -m ai_codescan eval run`.

Implementation choices:

1. **Pinned actions** (`actions/checkout@<SHA>`, `astral-sh/setup-uv@<SHA>`) per the global standards in CLAUDE.md. SHA pins prevent silent upstream changes; version comments keep upgrade paths reviewable.
2. **`persist-credentials: false`** on checkout — minimises blast radius if anything in the workflow gets compromised.
3. **`uv` for venv + deps** — matches the project's Python tooling. Faster than pip and the lockfile resolution is reproducible.
4. **Hard-coded PATH** in the test step. Strips dev-machine PATH pollution from causing flakes between CI and local.
5. **Eval suite excluded.** Skipping eval makes CI ~5 minutes instead of ~15. The trade-off: a Joern/Semgrep regression that pytest can't see won't be caught by CI. `scripts/test-joern-upgrade.sh` and the user's local eval runs cover this gap.

Cons:
- No eval = CI can miss eval-only regressions. Mitigate by running eval locally before merging significant scoring/sink/mitigation changes.
- No coverage report. `pytest --cov` is one flag away; defer until the test-quality bar needs it.


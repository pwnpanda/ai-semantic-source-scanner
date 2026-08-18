# TODO: Build A Ghost-Inspired, Static-First Scanner

Status: approved for implementation. Optimize for recall first: false negatives are critical, while some false positives are acceptable if they stay explainable and reviewable.

Goal: make `ai-codescan` more complete and effective than Ghost by stealing the useful shape of Ghost's workflow without depending on Ghost at runtime.

Core strategy:

1. Run deterministic tooling first: project detection, entrypoints, AST/SCIP, CodeQL, Semgrep, Joern, storage taint, sidecars.
2. Score and rank the resulting evidence for review priority, not for early suppression.
3. Feed LLMs compact evidence bundles, not whole repos or arbitrary files.
4. Add a Ghost-style exploratory miss-finder only for areas deterministic tooling does not cover well.
5. Convert every useful miss into an eval target, rule, model, score signal, or heuristic so the same class gets cheaper next time.

## Recall-First Invariants (Non-Negotiable)

Every implementation pass must obey these. If an existing implementation drifts, it is a bug, not a tradeoff.

1. **No hidden candidates.** A candidate that the deterministic engine, miss-finder, or LLM produces must remain queryable via `ai-codescan candidates` and the candidate audit artifact. The only suppression allowed is for clearly synthetic paths (vendor, generated, test, build) tagged via the `_LOW_SIGNAL_PARTS` penalty.
2. **Mitigations demote, never drop.** Any mitigation signal — parameterization, canonicalization+containment, allowlists, escapes, owner checks — must surface as a negative `mitigation_signal` score factor with a visible `kind`. Hard suppression at ingest is forbidden until ≥3 positive and ≥3 negative eval targets across ≥2 languages have validated the suppression rule, AND the suppression itself is logged on the candidate audit row.
3. **Overlap is a score factor, not a drop.** If a miss-finder candidate sits near a same-CWE deterministic flow, the miss-finder candidate must still be emitted with an `overlap_with_deterministic` negative score factor. The deterministic flow may itself be wrong; the miss-finder candidate must remain reviewable.
4. **Cost limits are opt-in, off by default.** `--max-llm-candidates`, `--min-score`, and `--max-bundle-bytes` are user-set caps. None of them may have a recall-reducing default. When the size cap is set and a bundle exceeds it, the bundle is truncated, not skipped; the candidate is still queued.
5. **Every model expansion ships with a negative eval target.** A new sink class, source pattern, or fallback enabled in `joern_queries.sc` (or any other engine extension) must land with a negative eval target in the same change. Eval precision is the precision guardrail; narrow models are not.
6. **Co-location fallback is always on; its score is downward.** Fallback-derived candidates must carry `flow_type: co-location` (or equivalent) and a strong negative score factor. Class-by-class fallback deny lists are forbidden.

## Current Extension Points

Existing pieces to reuse:

- CLI orchestration: `ai_codescan/cli.py`, `ai_codescan/runs/orchestrator.py`
- Persistent run state: `ai_codescan/runs/state.py`
- Flow storage: `ai_codescan/index/duckdb_schema.py`
- Hybrid engine/dedupe: `ai_codescan/engines/hybrid.py`
- Joern query models: `ai_codescan/engines/joern_queries.sc`
- Entrypoints: `ai_codescan/entrypoints/`
- Sidecars: `ai_codescan/sidecars.py`
- Slice extraction: `ai_codescan/slice.py`
- Current LLM stages: `ai_codescan/nominator.py`, `ai_codescan/analyzer.py`, `ai_codescan/validator.py`
- Skill prompts/loops: `ai_codescan/skills/wide_nominator/`, `ai_codescan/skills/deep_analyzer/`, `ai_codescan/skills/validator/`
- Eval seed already added: `eval-targets/aspnet-minimal-sqli`

Important design constraint: avoid adding a second Ghost clone beside the scanner. The Ghost-inspired pass must consume the scanner's richer precomputed context.

## Phase 0: Eval Baseline And Ground Truth

Purpose: make effectiveness measurable before changing scanner behavior.

Deliverables:

- [x] Add a standalone benchmark layer, not a new normal `run` pipeline phase.
- [x] Add `eval-targets/manifest.yml` with target path, language, expected findings, allowed false positives, and expected scanner mode.
- [x] Add optional per-target `eval.yaml` files when a target needs local metadata close to the source.
- [x] Add `ai_codescan/eval.py` with manifest loading, scanner invocation helpers, result matching, and TP/FP/FN calculation.
- [x] Add a top-level Typer sub-app or command group, for example `ai-codescan eval run --targets eval-targets --engine hybrid --out ...`.
- [x] Add `ai-codescan eval summarize <results>` or simple summary output from `eval run`.
- [x] Store scanner cache under the existing `<cache>/<repo_id>/` convention.
- [x] Store benchmark outputs separately, for example `<cache>/evals/<timestamp>/results.jsonl`, `summary.json`, and `report.md`.
- [x] Support a manual Ghost-result import format, for example `eval-results/ghost/*.json`, without requiring Ghost at runtime.
- [x] Add the ASP.NET minimal SQLi target to the manifest.

Implementation notes:

- Start with deterministic/Joern result matching. Do not block Phase 0 on full end-to-end LLM runs.
- Match expected findings by CWE plus source/sink file and approximate line, not exact engine-specific IDs.
- Treat "partial" as a first-class result when CWE is correct but source/sink precision is weak.
- Successful hybrid runs with no flows should produce warnings, not `error` results.

Tests:

- [x] Unit tests for manifest parsing.
- [x] Unit tests for result matching: pass, partial, miss, false positive.
- [x] Unit tests for no-flow warning behavior.
- [x] Unit tests for imported Ghost result comparison.
- [x] Integration-style test using a tiny synthetic result set, not full Joern.

Validation:

- [x] Run eval against `eval-targets/aspnet-minimal-sqli`.
- [x] Expected result: one true positive, zero false positives for `ai-codescan` after the recent Joern C# fix.

Implementation gate:

- No LLM workflow changes until this phase can produce a repeatable baseline.

## Phase 1: Candidate Scoring

Purpose: reduce LLM spend and improve prioritization.

Deliverables:

- [x] Add `ai_codescan/scoring.py`.
- [x] Add a `candidate_scores` table with score, label, processing bucket, score factors, scorer version, stream, and optional flow ID.
- [x] Score every candidate after `nominator.build_queue()` and before `nominator._stage_inputs()`.
- [x] Expose `ai-codescan candidates --repo-id ...` to list top candidates and reasons.
- [x] Add `ai-codescan candidates --all` and display filters for label, processing bucket, stream, and minimum score.
- [x] Feed score metadata into nominations and later evidence bundles.
- [x] Preserve score metadata in `queue.jsonl`.
- [x] Add sidecar enrichment for score records where useful.

Suggested schema:

```sql
CREATE TABLE IF NOT EXISTS candidate_scores (
  candidate_id VARCHAR PRIMARY KEY,
  flow_id VARCHAR,
  stream VARCHAR,
  score DOUBLE,
  label VARCHAR,
  processing_bucket VARCHAR,
  factors_json VARCHAR,
  scorer VARCHAR,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

Internal processing buckets:

- `report`: high-confidence deterministic finding, likely safe to report or send to light LLM validation.
- `llm-review`: plausible but needs semantic review.
- `explore`: no complete flow but strong hotspot/risk signal.
- `audit`: likely false positive or not security-relevant, but still visible in audit/debug output.

Human-facing labels remain `high`, `medium`, `low`, and `probably-safe`.

Initial scoring signals:

- [x] Multi-engine agreement: strong positive.
- [x] Exact static source-to-sink flow: strong positive.
- [x] Remote route/public API reachability: strong positive.
- [x] Dangerous sink class: positive.
- [x] Unknown parameterization: positive for injection classes.
- [x] Explicit parameterization/sanitization/allowlist: strong negative.
- [x] Test, fixture, example, generated, vendor path: strong negative.
- [x] Single-engine heuristic-only flow: mild positive or neutral, depending on engine.

Tests:

- [x] Unit tests for score math and reason output.
- [x] Unit tests for processing bucket persistence and old table migration.
- [x] Regression test for C# `connection.Open()` style false positives staying suppressed.
- [x] Tests for multi-engine confidence boosting aligning with `hybrid.dedupe_flows`.

Validation:

- [x] Existing Joern runner test remains green.
- [x] Eval target still passes; scoring is non-destructive and has no `suppress` bucket.

Implementation gate:

- Candidate scoring can be merged before LLM prompt changes, but it must not silently drop plausible findings. In early versions, scoring ranks and annotates; it does not suppress except for clearly irrelevant paths such as vendor/generated/test artifacts.

## Phase 2: Evidence Bundles

Purpose: make LLM analysis cheaper and more reliable than Ghost's file-level analysis.

Deliverables:

- [x] Add `ai_codescan/evidence.py` rather than overloading the current minimal `slice.py` API.
- [x] Build one evidence bundle per scored flow candidate.
- [x] Build generalized bundles for Stream B / miss-finder candidates that do not have a flow ID.
- [x] Include route/entrypoint match, source, sink, flow steps, code excerpts, score reasons, engine provenance, parameterization, and mitigation search results.
- [x] Render both JSON and compact markdown.
- [x] Write bundles under `<run_dir>/bundles/`.
- [x] Stage bundles during nomination, not only during analyzer, so nominator/analyzer prompts can both consume the same artifact.
- [x] Update analyzer staging to prefer bundle IDs over loose nomination file locations.
- [x] Fix the wide-nominator loop's stale source-root path: it currently points at `$RUN_DIR/inputs/source/`, but the snapshot is under `<repo_dir>/source`.

Bundle contents:

- Candidate ID and flow ID.
- CWE and bug-class label.
- Engine provenance and confidence.
- Source file/line/name.
- Sink file/line/name/class/parameterization.
- Entrypoint/route evidence if available.
- Code excerpts around source, sink, and intermediate steps.
- Mitigation scan summary.
- Score and reason list.
- Questions for LLM reviewer.

Tests:

- [x] Unit tests for bundle rendering.
- [x] Tests for missing files and sparse flow steps.
- [x] Tests that absolute snapshot paths are handled consistently.
- [x] Regression test that Stream B candidates can be analyzed with a generalized bundle instead of being skipped for missing flow slices.

Validation:

- [x] Bundle tests cover source/sink/entrypoint evidence.
- [x] Bundle size stays bounded and predictable via local context excerpts.

Implementation gate:

- Do not remove the existing analyzer path until bundle-first analysis is working with fallback.

## Phase 3: Bundle-First LLM Review

Purpose: replace Ghost-style broad file reads for deterministic findings with focused review.

Deliverables:

- [x] Add a `review` stage or adapt `analyze` to consume evidence bundles first.
- [x] Update `ai_codescan/skills/deep_analyzer/prompts/analyzer.md` for bundle-first verdicts.
- [x] Add verdicts: `true-positive`, `false-positive`, `inconclusive`, `needs-model-extension`.
- [x] Record verdicts in a structured table or sidecar.
- [x] Add review controls: max candidates, min score, max bundle bytes.
- [x] Add `--deterministic-only`, `--max-llm-candidates`, and `--min-score` options where appropriate.
- [x] Keep current queue/slice analyzer path as a compatibility fallback until bundle review is stable.

Prompt behavior:

- The LLM gets one bundle.
- It may request or inspect at most a small number of additional files.
- It must explicitly answer every evidence criterion.
- It must not produce a finding when mitigation evidence is clear.
- It must mark `needs-model-extension` when the bug is real but the deterministic model is incomplete.

Tests:

- [x] Unit tests for verdict parsing.
- [x] Analyzer staging tests that bundles are generated and queued.
- [x] No-LLM path still writes deterministic artifacts and exits cleanly.

Implemented so far:

- `ai-codescan analyze --max-candidates` caps automatic LLM review work.
- `ai-codescan analyze --max-llm-candidates` is the clearer alias for that cap.
- `ai-codescan analyze --min-score` filters scored candidates for LLM review while retaining unscored candidates.
- `ai-codescan analyze --max-bundle-bytes` truncates oversized bundles down to the cap, keeping the candidate in the LLM review queue. Default is `None` (no cap). Skipping oversized bundles is forbidden by Invariant 4.
- `ai-codescan analyze --deterministic-only` stages queues/bundles and skips LLM execution.
- Candidate recording and `ai-codescan candidates` remain recall-first and unfiltered by default.

Validation:

- [x] Run deterministic-only eval.
- [x] Run bundle-review eval with LLM unavailable and confirm graceful skip.
- [ ] When an LLM CLI is available, run one candidate on the eval target and inspect verdict output (manual user task; Phase 8 auto-invocation lands the candidate but live verification requires the user's LLM provider).

Implementation gate:

- Keep the existing `nominate -> gate -> analyze` commands working while introducing bundle-first behavior.

## Phase 4: Mitigation And False-Positive Filters

Purpose: cut false positives before LLM spend.

Deliverables:

- [x] Add `ai_codescan/mitigations.py`.
- [x] Add language-aware checks for common mitigations.
- [x] Feed mitigation findings into scoring and bundles.
- [x] Add negative eval targets for mitigated variants.

Initial mitigation checks:

- SQLi: parameterized APIs, command parameters, ORM safe APIs.
- Command injection: argument arrays, shell disabled, command allowlist.
- Path traversal: canonicalization plus root containment.
- XSS: escaping/encoding and safe template rendering.
- SSRF: URL allowlists and fixed host construction.
- Authz: owner/tenant scoping near storage access.
- Mass assignment: explicit DTO/allowlist mapping.

Tests:

- [x] Positive and negative tests for each mitigation helper.
- [x] Eval targets for at least SQLi parameterization and path containment.

Validation:

- [x] False-positive count does not increase on existing fixtures.
- [x] Lower-priority mitigation candidates retain explainable reasons.

Implementation gate:

- Mitigations annotate and lower confidence; they MUST NOT hide candidates. Hard suppression at ingest time is forbidden by Invariant 2. The mitigation list is documented inside `mitigations.py` so the rule set is reviewable.

## Phase 5: Deterministic Miss-Finder

Purpose: steal Ghost's broad nomination strength without paying for fully open-ended scanning.

Deliverables:

- [x] Add `ai_codescan/miss_finder.py`.
- [x] Build an initial risk map from routes, nearby auth calls, and existing flows.
- [x] Generate initial exploratory candidates for classes static source/sink flows miss.
- [x] Annotate candidates that overlap with a same-CWE deterministic flow nearby and apply an `overlap_with_deterministic` score factor. Never drop them (Invariant 3).
- [x] Rank candidates and write `<repo>/miss_candidates.jsonl`.
- [x] Add `ai-codescan miss-finder --repo-id ...` command or a `nominate --mode miss-finder` flag.
- [x] Defer adding a new orchestrator phase until standalone command behavior is measured.

Initial miss-finder rules:

- BOLA/IDOR: route has resource ID and no owner/tenant/authz-looking signal nearby. Storage-query correlation is still pending.
- BFLA: admin/manage/delete/export/import route lacks role/policy check.
- Missing authn: sensitive/state-changing route lacks auth middleware/decorator.
- Mass assignment: request body binds directly into persistence model with sensitive fields nearby.
- SSRF: request-controlled URL/host reaches HTTP client.
- Sensitive logging/errors: request/user/secret data reaches logs or error responses.
- Business workflow: status-changing operation lacks state/permission checks.

Tests:

- [x] Unit tests for candidate generation from seeded symbols/entrypoints/xrefs.
- [x] Fixture tests for one positive and one clean BOLA-like shape.

Validation:

- [x] Miss-finder produces bounded candidates on the ASP.NET eval target cache.
- [x] It does not duplicate known same-CWE flow candidates.

Implementation gate:

- Miss-finder is allowed to be noisy at first; rank candidates, but preserve them for audit. Candidate limits should apply to automatic LLM review, not to recorded miss candidates.

## Phase 6: Exploratory LLM Review

Purpose: use Ghost-style reasoning where it helps most: uncovered semantic candidates.

Deliverables:

- [x] Add an exploratory bundle renderer for miss candidates.
- [x] Add or update a skill prompt for `miss_reviewer`.
- [x] Require concrete code evidence and a reachable path before producing a finding.
- [x] Classify outputs as `new-finding`, `covered-by-static`, `false-positive`, `needs-model-extension`, or `needs-human-context`.
- [x] Convert `new-finding` and `needs-model-extension` outputs into follow-up artifacts.

LLM constraints:

- Review top-ranked miss candidates only.
- Read bounded extra context.
- Prefer "needs-human-context" over speculative findings.
- Emit structured evidence so results can become deterministic rules later.

Tests:

- [x] Prompt harness tests for sentinel parsing.
- [x] No-LLM graceful skip.
- [x] Unit tests for output classification parsing.

Validation:

- [x] Run against at least one authorization-heavy target or fixture.
- [ ] Compare with any manually collected Ghost result on the same target.

Implementation gate:

- Exploratory mode should be opt-in or candidate-capped for automatic review until precision is measured, but candidate generation should favor recall.

Open work for this phase:

- [x] Wire live LLM execution end-to-end for the miss_reviewer skill (§16, Phase 6); integrated with `review_verdicts` and `findings/` for reporting. Mirror the deep_analyzer loop shape; skip gracefully when no LLM CLI is on `PATH`.

## Phase 7: Model-Extension Feedback Loop

Purpose: make the scanner learn from misses.

Deliverables:

- [x] Add structured model proposal files under `<run_dir>/model_proposals/`.
- [x] Add `ai-codescan model-proposals list`.
- [x] Add `ai-codescan model-proposals accept` to stage Semgrep, Joern, CodeQL extension, or internal heuristic updates. *(Currently dry-run only — Phase 3 fills in Semgrep rule generation.)*
- [x] Require a minimal eval target before accepting a proposal. *(Phase 3 hardens this into a paired positive+negative target gate.)*
- [x] Link proposals back to the miss/LLM verdict that caused them.
- [x] Phase 3: generate Semgrep rules from accepted proposals and stage under `.semgrep/rules.staged/`.
- [x] Phase 3: paired-target gate (refuse `apply` without a linked positive AND negative eval target).
- [x] Phase 3: `proposal_decisions` DuckDB table for pending/applied/rejected bookkeeping.
- [x] Phase 5: Joern model patching via `aics-joern-extension-packs.json` sidecar that `joern_queries.sc` merges at scan time.
- [x] Phase 5.1: staged/promoted distinction for Joern extensions; `model-proposals promote` + `model-proposals clone` CLI.
- [x] Phase 10/11: CodeQL pack extension — `apply --engine codeql`, triage routing, and `engines/codeql.py` auto-render at scan time. Requires `codeql` on PATH for full integration testing; unit tests cover renderer + prep helper.
- [x] Phase 14: removed the `sanitizer_pattern`→`receiver_regex` back-compat fallback in `apply_proposal_to_joern` and the one-shot `model-proposals migrate` tool. No pre-5.1 proposals exist, so the bridge was dead code; `receiver_regex` is now the sole Joern receiver-predicate field. `sanitizer_pattern` keeps its Semgrep `pattern-not` meaning.
- [x] Phase 7: LLM-assisted `clone --engine X` that rewrites `sink_pattern` for the destination engine's syntax (Semgrep pattern ↔ Joern call-name regex) — opt-in via `--rewrite-with-llm`.
- [x] Phase 9: CodeQL pack extension scaffolding (`codeql_extensions.py` + YAML renderer). CLI surface (`apply --engine codeql`) + auto-routing in `triage_and_route` + `engines/codeql.py` integration are still pending.

Proposal fields:

- Language/framework.
- CWE/bug class.
- Source pattern.
- Sink pattern.
- Sanitizer/mitigation pattern.
- Example vulnerable snippet.
- Example safe snippet.
- Target engine to update.

Tests:

- [x] Proposal serialization tests.
- [x] Acceptance command dry-run tests.

Validation:

- [x] One proposal can be created from a synthetic verdict and listed.

Implementation gate:

- Automatic rule promotion should start as dry-run only.

## Phase 8: Reporting And Comparison UX

Purpose: make results more defensible than Ghost output.

Deliverables:

- [x] Update reports to include evidence bundle summary, score reasons, engine provenance, mitigation search, and LLM verdict.
- [x] Allow `report.py` to render from `EvidenceBundle | None` while preserving the current `Finding.body` fallback.
- [x] Add suppressed-candidate reporting for auditability.
- [x] Add eval trend summary: target, TP, FP, FN, partial, runtime, and LLM-reviewed candidate count.
- [x] Add Ghost comparison import display: Ghost pass/partial/miss beside `ai-codescan` result.
- [x] Add Ghost comparison import display: Ghost pass/partial/miss beside `ai-codescan` result.

Tests:

- [x] Report rendering tests for scored/bundled findings.
- [x] Eval summary rendering tests.

Validation:

- [x] Generated report for ASP.NET eval target is source/sink precise. (Asserted by the eval suite: `aspnet-minimal-sqli` manifest pins `source_line: 15, sink_line: 19, source_contains: id, sink_contains: ExecuteReader` with `line_tolerance: 1`. Case has passed every full eval since Phase 4.)

Implementation gate:

- Reporting changes should not block core scanner operation.

## Phase 9: Broaden Eval Coverage

Purpose: prevent optimizing for one target. This phase is the precision guardrail for Invariant 5: every model expansion lands with at least one negative eval target.

Deliverables:

- [x] Add small positive/negative targets for command injection, SSRF, XSS, BOLA, BFLA, mass assignment, missing authn, and sensitive logging (JS/Express done in prior pass; C# SQLi done; SSRF allowlist and logging-redacted negatives added with the §7 sink expansion).
- [x] Cover at least C#, JS/TS, Python, Java/Kotlin, Go, PHP/Ruby where practical. (C# + JS/TS Phase 1; Python Phase 2; Java/Spring + Go Phase 6; Kotlin/PHP/Ruby Phase 12 — targets shipped but currently miss due to Joern frontend limitations: rubysrc2cpg is beta, kotlin2cpg under-models Spring annotations, php2cpg needs php on PATH.)
- [ ] Add a few realistic small apps after tiny fixtures are stable.
- [ ] Periodically run Ghost manually on the same targets and import results for comparison. (Tooling is in place: `ai-codescan eval compare --ai-results ... --ghost-results ...` accepts Ghost JSON/JSONL — see `docs/ghost-comparison-eval.md`. The recurring task is the manual Ghost run itself, which is process not code.)

Tests:

- [x] Eval manifest validation catches missing target files and malformed expected findings.

Validation:

- [x] Track trend over time. Improvements should show either better recall, lower false positives, lower LLM spend, or better source/sink precision.

Implementation gate:

- Do not expand source/sink models aggressively without positive and negative eval targets.

## Phase 13: Adversarial Multi-Stage Validation (complete)

Purpose: upgrade the ghost-derived single-pass LLM validation (`validator`, `deep_analyzer`, `miss_reviewer` skills) to match the current best practice demonstrated by `evilsocket/audit` (https://github.com/evilsocket/audit). The current flow asks one model to review one bundle; audit's design treats LLM output as an unreliable signal needing independent verification, which cuts false positives.

Reference methodology (audit's 8-stage pipeline):

1. Recon — narrowly-scoped hunt tasks; mine git history for past security patches, then hunt sibling files sharing the same idiom.
2. Hunt — one attack class per agent with explicit trust boundaries.
3. Validation — adversarial: a *second agent on a different model* tries to disprove each finding.
4. Deduplication.
5. Reachability gating — a trace stage proves attacker-controlled input reaches the sink.
6. Live-target verification — reproduce findings against a running deployment when one exists.
7. Feedback loop — confirmed reachable bugs seed new hunts for the same pattern elsewhere.
8. Schema-driven JSON output at every stage.

Deliverables:

- [x] Adversarial validation stage (`ai_codescan/adversarial_validator.py` + `adversarial-review` CLI): a second LLM provider challenges each decisive `review_verdicts` row. Disputed verdicts land in `adversarial_challenges` — never a silent drop. Disputed false-positives (recall-critical: a dismissed finding a second model thinks is real) are surfaced loudly. Schema-driven JSON output. Verified live against claude/gemini/codex.
- [x] Reachability as a verdict input: `reachability_note` / `with_reachability_evidence` prepend a data-flow-proven vs co-location-only note to the verdict evidence before the challenge, so the challenger argues with reachability in hand. Recall-first — it informs the challenge, never drops the finding.
- [x] Adversarial result wired into `scoring.py` as a score factor (`adversarial_disputed` demotes a disputed TP, `adversarial_recall_flag` re-elevates a disputed FP, `adversarial_corroborated` boosts a confirmed TP). `adversarial-review` runs a re-score pass so the dispute shifts ranking immediately.
- [x] Multi-challenger consensus: `ChallengeConsensus` / `challenge_consensus_all` aggregate every challenger's row per finding into a majority verdict; the score factor reads the consensus, not a single challenger.
- [x] Git-history recon + feedback loop (`ai_codescan/recon.py` + `recon` CLI): mines past security-fix commits and confirmed-finding files, then nominates their sibling files for a second scan. Writes `recon_hints.jsonl`.

Deferred (small, documented): wiring `recon_hints.jsonl` into the nominator/miss-finder queue so re-hunt files are auto-prioritised — the hints file is produced; consuming it is a one-line queue-ordering change left for when the single-command runner lands.

Open design tension: audit drops unproven findings; ai-codescan's Recall-First Invariants forbid silent drops. Resolution: every audit "drop" becomes an ai-codescan "demote + visible verdict". Document this divergence in REVIEW.md when the phase starts.

Gate: this is a multi-LLM-spend phase — keep adversarial re-runs opt-in (Invariant 4: cost limits are opt-in only).

## Phase 20: XXE + prototype pollution + response splitting (complete)

Three classes the taxonomy already declared but the engine never emitted.

- [x] XXE (CWE-611, `xml.parse`) across Java/Kotlin/Python/PHP/C#/Ruby.
- [x] Prototype pollution (CWE-1321, `proto.pollute`) — JS deep-merge family unfiltered; `set`/`setWith` gated by `protoPolluteReceiver` to avoid colliding with the Firestore CWE-915 sink.
- [x] HTTP response splitting (CWE-93, `header.write`) across JS/Java/Kotlin/C#/PHP/Ruby/Go.
- [x] Scoring weights for all three sink classes.
- [x] Eval targets: `express-proto-pollution` + `-safe`, `python-flask-xxe` + `-safe`. Eval 40→44 pass / 47.

Remaining classes from the audit — **cleared in Phase 21 below.**

## Phase 21: Remaining audit classes + Firestore precision gate (complete)

- [x] NoSQL operator injection (CWE-943, `nosql.query`) — JS + Python. Canonical Mongo `find` is receiver/type-gated so Array/string `find` calls remain safe near-misses.
- [x] SSTI for non-Python (CWE-1336) — JS Handlebars/lodash, Java Velocity/FreeMarker, Ruby ERB, Go text/template.
- [x] LDAP (CWE-90, `ldap.query`) + XPath (CWE-643, `xpath.query`) — Java/Kotlin/Python/PHP/C#.
- [x] Sensitive logging (CWE-532) extended beyond JS to Python/Java/Kotlin/Ruby/C#.
- [x] Email header injection (CWE-93) extended to Ruby/PHP/Go.
- [x] ReDoS (CWE-1333, `redos`) — JS/Python/C#. Python models only `re.compile`; Go standard `regexp` is excluded because it guarantees linear-time matching.
- [x] Firestore receiver gate — fixes `Object.create(null)` being reported as a Firestore write. Verified: mass-assignment target still passes, spurious flows on proto-pollution-safe went 2 → 0.
- [x] Eval targets `express-nosql-injection` + `-safe`. Eval 44 → 46 pass / 49.
- [x] Phase 22 generalized regression audit: exact language matrix for all Phase 20/21 sinks,
  direct receiver-gate positives/negatives, and paired JS/Python/Java/C# Joern eval repositories.
- [x] Phase 22 semantic corrections: canonical Mongo `find`, actual JS/C# constructor call names, receiver/argument-aware non-Python SSTI/XPath/LDAP, Kotlin parameter sources, and removal of the invalid Go ReDoS mapping.

Still open:

- [ ] Kotlin's current `kotlin2cpg` build skips reaching-definition edges for the tested Spring
  methods. Annotated request parameters are now discovered correctly, but cross-statement Joern
  flows remain a frontend limitation; do not replace them with file-wide co-location matches.
- [ ] Format-string (CWE-134): needs receiver-taint support — the vulnerable shape is a tainted *format string*, not a tainted argument. Bare `format` as a sink would be pure noise.
- [ ] Java `JavaMailSender.send`: bare `send` too generic on the JVM; needs a receiver gate like the Firestore one.
- [ ] Judgement-call classes pending user direction: insecure randomness (CWE-330/338), CORS misconfiguration. TOCTOU/races judged not statically detectable — skip.

## Phase 19: CSPT (Client-Side Path Traversal) (complete)

CSPT detection per the user's design call: client-side only, classified as CWE-22 (path traversal — the user's words: "mirrors path traversal closer than SSRF"). Discriminator: user input lands in the URL's path section, BEFORE any `?`/`#`/`&` separator.

Deliverables:

- [x] JS-only post-loop block in `joern_queries.sc` — regex-matches the call's source text for a literal `/`-prefix + concat/template-substitution shape with no query/fragment separator before the substitution point. Runs `reachableByFlows` against the call args, emits CWE-22 with `sink_class=cspt`.
- [x] Scoring weight `cspt: 0.12` in `_DANGEROUS_SINK_CLASSES`.
- [x] Eval targets: `cspt-fetch-path` (positive — path-section concat fires) + `cspt-fetch-querystring-safe` (negative — `?`-before-`${}` suppresses).

## Phase 18: Open redirect + SSTI distinct + email injection + fixpoint in scan (complete)

Plugs three of the four real gaps the vuln-class audit surfaced.

- [x] Open redirect (CWE-601) sinks across JS/Python/Java/Ruby/C#/Go/Kotlin.
- [x] SSTI (CWE-1336) distinguished from XSS — Python `render_template_string` now also CWE-1336 alongside CWE-79.
- [x] Email/SMTP injection (CWE-93) sinks — JS sendMail/sendEmail, Python send_message/send_mail/sendmail.
- [x] `taint-schema` (storage_taint fixpoint) runs as part of `secscan` so Phase 17 stored XSS fires by default. Closes Phase 17 follow-up A.
- [x] Eval targets: `express-open-redirect` (positive + safe). Updated `python-flask-xss` to expect both CWE-79 and CWE-1336.

Open follow-ups (next pass — sinks are well-defined, additive):

- [ ] XXE (CWE-611) sinks: `DocumentBuilder.parse` (Java), `lxml.etree.parse` / `xml.sax.parse` (Python), `simplexml_load_string` (PHP), `XmlDocument.LoadXml` (C#).
- [ ] HTTP response splitting (CWE-93/444): `setHeader` / `addHeader` with CRLF — Java/Python/Go.
- [ ] Prototype pollution (CWE-1321): JS `lodash.merge` / `_.set` / recursive merge.
- [ ] NoSQL injection: Mongo operator objects in query filters; use observation-only probes.
- [ ] LDAP / XPath injection (CWE-90 / CWE-643).
- [ ] SSTI for non-Python: Java Velocity / FreeMarker, Ruby ERB, JS Handlebars.
- [ ] Sensitive logging beyond JS (Python/Java/Ruby).
- [ ] Email sinks beyond JS/Python (Java/Ruby/PHP/Go).
- [ ] CSPT — design call needed (CSPT vs SSRF discriminator).

## Phase 17: Stored + reflected XSS coverage (complete)

Closes the user's follow-up to Phase 16. Adds stored-XSS synthesis on top of the existing storage_taint pipeline (new `ai_codescan/stored_xss.py` + wired into `run_full_fixpoint`) and reflected-XSS sink gap-fill per language.

Deliverables:

- [x] `synthesize_stored_xss_flows` — proximity-based detector: tainted `storage_id` × `storage_reads` × nearby CWE-79 html.write flow → synthetic CWE-79 stored-XSS flow with `engine="stored-xss-r3"`. Idempotent.
- [x] Wired into `storage_taint.run_full_fixpoint` (step 5 of each round). Auto-runs whenever `taint-schema` runs.
- [x] Reflected sinks per language: Python `make_response` / `HttpResponse` (Flask + Django), C# `Raw` / `HtmlString` (Razor), Ruby `send_data` (Rails).
- [x] 6 unit tests for `stored_xss` module.

Follow-ups (intentionally deferred):
- [ ] Stored-XSS eval target. Needs a JS/Python target whose DB-write pattern `storage_taint.run_fixpoint` already understands; building one + tuning the pattern is its own debugging cycle.
- [ ] Wire `run_full_fixpoint` into `analyze` / `scan` so stored XSS runs by default. Today only `taint-schema` triggers it.
- [ ] Tighter same-function (not same-file) proximity gate once the call graph is wired into the heuristic.
- [ ] Template-engine bypass detection (Jinja2 `|safe`, Django `autoescape off`, JSP `<%= %>`).

## Phase 16: Pure-JS DOM-XSS coverage (complete)

Closes the user's call-out: "we are not good at checking for DOM-XSS or other sinks in pure JS." Adds DOM-XSS sources, DOM call-shaped sinks, and a property-assignment scan for `innerHTML`/`outerHTML`/`dangerouslySetInnerHTML` to `joern_queries.sc`. Ships 2 positive eval targets (`dom-xss-innerhtml`, `dom-xss-eval`) and 1 negative (`dom-xss-textcontent-safe`); all three pass with real Joern flows. Eval went from 33→36 pass / 39. See REVIEW.md Phase 16.

Follow-ups intentionally deferred (low priority):
- jQuery `.html()` — generic name; needs a receiver filter (`\$(...).html(`) to avoid over-matching arbitrary `.html` properties.
- A Semgrep pack for browser-side JS could complement Joern — `_PACK_MAP` in `proposal_triage.py` currently only carries the Express pack for (CWE-79, javascript).

## Phase 15: Single-command runner + HTML report (complete)

Purpose: one command (`secscan .`) runs the whole pipeline unattended, producing a consumable HTML report.

Deliverables:

- [x] Call-graph extraction (`ai_codescan/call_graph.py`) — whole-repo caller→callee graph from the DuckDB `symbols`/`xrefs` tables, finding-path nodes flagged.
- [x] HTML report (`ai_codescan/html_report.py` + `ai-codescan report --html`) — self-contained `report.html` (findings cards: title+criticality, 2–4 line summary, full detail behind a `<details>` toggle, link to flow graph) + `call-graph.html` / `flow-<id>.html` / `entrypoints.html` (React Flow via esm.sh).
- [x] `secscan` one-shot command + console-script entry point — `ai-codescan scan <path>` / `secscan .` chains `prep → nominate → gate-1 → analyze → gate-2 → validate → gate-3 → report --html` unattended (subprocess-per-stage).
- [x] HITL `$EDITOR` gates — three pause points (nominations, findings, sign-off); each opens in `$EDITOR` then waits for Enter. `--skip-hitl` runs every gate with `--yes`.
- [ ] Browser-test the React Flow graph pages (the user's testing pass).
- [ ] Optional follow-up: let the HTML report show `unverified` findings when the validator could not run (Docker-less host currently gets an empty report).

## Implementation Order

Milestones 1–4, Recall-First Realignment, and Phase-2 cleanup are complete. The current milestone is **Phase 3: Model-Extension Feedback Loop**.

Recall-First Realignment (complete 2026-05-15):

1. [x] Remove the `--max-bundle-bytes` default skip; truncate instead (§1, Invariant 4).
2. [x] Remove the hard CWE-22 path-containment suppression in `engines/hybrid.py`; demote to `mitigation_signal` (§3, Invariant 2).
3. [x] Remove the same-CWE drop in `miss_finder.py`; emit `overlap_with_deterministic` score factor (§4, Invariant 3).
4. [x] Broaden JS sinks for SSRF (axios/http/https) and add 2 negative eval targets — `express-ssrf-allowlist`, `express-sensitive-logging-redacted` (§7, Invariant 5).
5. [x] Re-enable Joern co-location fallback for CWE-79 and CWE-639; tag fallback flows; downscore (§8, Invariant 6).
6. [x] Allow CWE-79 on `express-ssrf` fixture (consistent with §10 CSRF-allow precedent) — resolves the last eval false positive.

Phase-2 cleanup (complete 2026-05-16):

1. [x] Wire live LLM execution for `miss_reviewer` skill (§16, Phase 6).
2. [x] Stable content-addressed miss-finder candidate IDs (`B-miss-{sha1(file+line+vector)[:12]}`) so verdicts survive re-indexing.
3. [x] Python SSRF sinks (`requests`/`httpx`/`urllib3`/`urlopen`) with receiver filter + `python-flask-ssrf-allowlist` negative target.
4. [x] Dynamic severity calculation in `report.derive_meta(score_factors=...)` — ±1 tier per matching score factor.
5. [x] `scip-python` in `scripts/install.sh`.
6. [x] Python eval manifest precision fixes (Joern frontend quirks).
7. [x] Phase 9 partial: extend eval coverage to Python (sqli, ssrf, xss, authz). Java/Kotlin/Go/PHP/Ruby remain deferred until they're learned from real miss-review verdicts.

Phase 3: Model-Extension Feedback Loop (current milestone):

1. Generate Semgrep rules from `new-finding` / `needs-model-extension` proposals; stage under `.semgrep/rules.staged/` (Phase 7 dry-run gate).
2. Paired-target gate: `model-proposals apply` refuses unless the proposal has both a positive and a negative eval target linked (Invariant 5).
3. `proposal_decisions` table — pending/applied/rejected bookkeeping that survives runs.
4. Multi-line `execute(sql,\n  params,\n)` mitigation regex (REVIEW.md Phase-2 callout).
5. Type-aware `pythonSsrfReceiver` for aliased clients (`http_client = httpx.Client(); http_client.get(...)`).
6. Joern model patching and CodeQL pack extension are deferred to a follow-on phase (harder edit surface).

## Reviewed Plan

Strengths:

- Builds measurement before behavior changes.
- Reuses existing scanner artifacts instead of adding a parallel Ghost clone.
- Makes LLM review more evidence-grounded without making cost the primary objective.
- Keeps Ghost-style exploratory reasoning for bug classes static analysis handles poorly.
- Creates a path for misses to become deterministic coverage.

Risks (observed during this pass):

- The first implementation pass drifted toward hard suppression for several FP shapes despite the original recall-first stance (§1 bundle size, §3 path containment, §4 same-CWE drop, §7 narrow sinks, §8 fallback deny list). The Recall-First Invariants block above is the standing fix.
- Eval-driven precision tuning can mask FNs the eval suite doesn't measure. Every model change needs a negative target *in the same commit*.
- Score reasons must remain visible end-to-end — `candidates`, candidate-audit report, evidence bundle. A demoted candidate that the reviewer never sees is functionally suppressed.

Risk controls:

- Recall-First Invariants 1–6 above are non-negotiable.
- Keep existing pipeline fallback paths until bundle-first review is proven.
- Add positive and negative eval targets for every new model.
- Make exploratory mode candidate-capped and initially opt-in for *automatic LLM review*; never for candidate recording.
- Store score reasons end-to-end so any demotion can be audited and reversed.

Deferred work:

- Automatic rule promotion beyond the Phase 3 staged-not-merged dir (a separate `--promote` flag will move staged rules into the active dir after eval review).
- Joern model patching and CodeQL pack extension (Phase 3 covers Semgrep only; the others have a harder edit surface).
- Full Ghost automation. We use Ghost results only as imported comparison data.
- Live DAST validation changes.
- Large realistic benchmark suite before tiny targets prove the harness.
- Java/Kotlin/Go/PHP/Ruby eval coverage — better to land after Phase 3 closes the learning loop so language coverage grows from real miss-review verdicts, not manual curation.
- LLM-judge severity variant (the multi-factor calc covers the common case; only worth adding if a real eval target shows the calc misclassifying findings reviewers care about).

Known cleanup discovered during planning:

- [x] Fix validator hint plumbing before using validation quality as a hard metric. `validator.py` writes per-finding hints, but the validator loop reads a single global hints path.
- [x] Fix wide-nominator source-root path before bundle-first prompts rely on reading source.

Implementation assumptions:

- Phase 0-3 are the first implementation milestone.
- Eval outputs stay local by default, with optional committed summaries later.
- Exploratory miss-finder starts opt-in for automatic LLM review, but deterministic candidate recording should favor recall.

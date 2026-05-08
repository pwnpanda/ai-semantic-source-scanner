---
name: wide-nominator
description: AI-driven SAST wide-pass nominator. Reads ai-codescan prep artefacts (repo.md, entrypoints.md, sidecar JSONL, DuckDB stats) and emits nominations.md with three streams (CodeQL-traced, AI-discovered, model-extension proposals), each carrying a max-2-line plain-English Summary and a y/n: HITL marker.
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
license: apache-2.0
---

# Wide Nominator

Workflow:

1. Read inputs from `$AI_CODESCAN_RUN_DIR/inputs/`:
   - `repo.md`, `entrypoints.md`
   - `flows.jsonl`, `sinks_no_flow.jsonl`, `sources_no_sink.jsonl`, `auth_calls.jsonl`, `hotspots.jsonl`
2. For each existing CodeQL flow in `flows.jsonl`, append a Stream A nomination.
3. For each high-signal hotspot or auth-relevant function lacking a CodeQL flow, append a Stream B AI-discovered nomination — only if a credible bug class applies.
4. For each library detected in `repo.md` that CodeQL doesn't model, propose a model extension as a Stream C nomination.
5. Every nomination has: `- [ ] N-XXX | <project> | <vector> | <file>:<line> | rec: high|med|low | y/n: ` followed by an indented block: `Summary:` (max 2 lines), then the structured fields.
6. Use atomic line claiming: only flip `[ ]` to `[x]`. Never reorder. Never edit other items.

Run with `bash $AI_CODESCAN_SKILL_DIR/scripts/loop.sh`.

Inputs:
- `$AI_CODESCAN_RUN_DIR` — current run directory
- `$AI_CODESCAN_SKILL_DIR` — this skill's directory
- `$AI_CODESCAN_TARGET_BUG_CLASSES` — comma-separated taxonomy names

Outputs:
- `$AI_CODESCAN_RUN_DIR/nominations.md`
- `$AI_CODESCAN_RUN_DIR/extensions/*.model.yml` for any Stream C proposals

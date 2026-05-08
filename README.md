# ai-codescan

AI-driven SAST pipeline. Phase 1 = deterministic prep + wide-pass nominator with HITL gate.

See `docs/superpowers/specs/2026-05-08-ai-codescan-phase1-design.md` for the full design.

## Install (development)

```bash
uv venv
uv sync --all-groups
uv run ai-codescan --help
```

## Phase 1A status

This sub-plan delivers: `ai-codescan prep <target>` produces a snapshot and `repo.md`.

## Smoke test (Phase 1A)

```bash
git clone --depth 1 https://github.com/expressjs/express.git /tmp/tmp-express
uv run ai-codescan prep /tmp/tmp-express
cat ~/.ai_codescan/repos/tmp-express-*/repo.md
uv run ai-codescan cache list
```

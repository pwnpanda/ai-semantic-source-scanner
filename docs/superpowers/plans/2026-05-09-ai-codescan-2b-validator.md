# AI_Codescan 2B — Validator + Gate 3 Implementation Plan

> Use `superpowers:subagent-driven-development` or `superpowers:executing-plans`. Step checkboxes use `- [ ]`.

**Goal:** For each finding still `status: unverified` after Gate 2, run an Opus sub-agent that writes a PoC and executes it inside a hardened Docker sandbox. Findings flip to `verified` (PoC produced clear vulnerability signal), `rejected` (sanitiser fired, exit 0 with no signal), or `poc_inconclusive`. Add `validate` and `gate-3` subcommands.

**Architecture:**

- `sandbox.py` — `run_in_sandbox(cmd, *, work_dir, timeout, image)` returns `SandboxResult(exit_code, stdout, stderr, duration, signal_seen)`. Hardened defaults: `--network=none --cap-drop=ALL --security-opt=no-new-privileges --read-only --tmpfs /tmp:size=128m --memory=512m --cpus=1 --pids-limit=64`. 60s default timeout.
- `validator.py` — orchestrator: for each finding with `status: unverified`, drive the validator skill to produce `poc.py` (or `.sh`), run via `sandbox.py`, parse stdout for the marker `OK_VULN`, update finding frontmatter.
- `validator` skill — prompt + loop.sh (one finding per iteration).
- CLI: `validate` + `gate-3 [--yes]`.

**Sandbox image strategy:**
Per-stack Docker images cached at `<cache>/sandbox/<lang>:<digest>`:
- node → `node:22-alpine`
- python → `python:3.13-alpine`
- generic → `alpine:3.20`

The PoC sub-agent writes the script + a one-liner shell invocation. We pass that to the runner.

**Reference spec:** `docs/superpowers/specs/2026-05-09-ai-codescan-phase2-design.md` §4.2.

**Depends on:** Phase 2A complete.

---

## Tasks

### Task 1: `sandbox.py` (subprocess + Docker wrapper)

**Files:** `ai_codescan/sandbox.py`, `tests/test_sandbox.py`.

Implementation key points:
- Detect Docker availability via `shutil.which("docker")`.
- If no Docker, raise `SandboxUnavailableError`.
- `run_in_sandbox(cmd: list[str], *, image: str, work_dir: Path, timeout: int = 60, signal_pattern: str = "OK_VULN") -> SandboxResult` — runs `docker run --rm` with hardened flags + `-v <work_dir>:/work:ro --workdir /work` + the cmd. Captures stdout/stderr.
- `SandboxResult.signal_seen = signal_pattern in stdout`.

Skip the actual Docker invocation in unit tests by patching `subprocess.run` — only one e2e smoke test that runs an `alpine echo OK_VULN` confirms wiring.

```bash
git add ai_codescan/sandbox.py tests/test_sandbox.py
git commit -m "feat(sandbox): hardened docker runner"
```

### Task 2: Validator skill scaffold

`ai_codescan/skills/validator/{SKILL.md, prompts/validator.md, scripts/loop.sh}`.

Prompt: given a finding markdown, write `poc.py` (or `poc.sh`) that exercises the exact path. Output protocol: one marker `OK_VULN` on stdout if exploit succeeds; otherwise the script must exit non-zero or print `BENIGN`.

Loop reads `findings/*.md`, picks ones with `status: unverified`, calls `invoke_llm` with the finding pre-pended to the prompt, expects the LLM to write `<run>/sandbox/<finding_id>/poc.{py,sh}`, then invokes `sandbox.run_in_sandbox` via a small Python helper.

```bash
git add ai_codescan/skills/validator/
git commit -m "feat(skill): validator scaffold"
```

### Task 3: `validator.py` orchestrator

- Reads findings from `<run>/findings/*.md`.
- For each `status: unverified`: spawn LLM through wrapper (writing into `<run>/sandbox/<fid>/`), run sandbox, update frontmatter.
- Status flip rule:
  - `signal_seen=True` → `verified`
  - `exit_code == 0 AND not signal_seen` → `rejected` (PoC ran clean)
  - else → `poc_inconclusive`
- Writes `validation_log.md` with one row per finding.

```bash
git add ai_codescan/validator.py tests/test_validator.py
git commit -m "feat(validator): orchestrator + status flip"
```

### Task 4: CLI `validate` + `gate-3`

`validate [--repo-id X] [--no-sandbox] [--llm-provider P] [--llm-model M]`. `--no-sandbox` runs the PoC locally (dev-mode, NOT recommended). `gate-3 [--yes]` opens the verified-findings list in `$EDITOR` for sign-off, or auto-confirms with `--yes`.

```bash
git add ai_codescan/cli.py tests/test_cli.py
git commit -m "feat(cli): validate + gate-3 subcommands"
```

### Task 5: Quality gate, tag

```bash
make check
git tag -a phase-2b -m "Phase 2B: validator + gate 3"
```

---

## Self-review

- §4.2 sandbox runner with hardened defaults → Task 1
- Validator skill (PoC writer) → Task 2
- Status flip logic → Task 3
- `validate` + `gate-3` → Task 4
- Phase 2 spec §6 CLI surface — covered

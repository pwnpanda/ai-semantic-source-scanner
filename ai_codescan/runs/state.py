"""Run-state JSON: phase, cost ledger, config snapshot."""

from __future__ import annotations

import datetime as _dt
import json
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class RunState:
    run_id: str
    run_dir: Path
    started_at: str
    phase: str
    engine: str
    temperature: float
    target_bug_classes: list[str]
    cost_cap_usd: float | None
    calls: list[dict[str, Any]] = field(default_factory=list)
    total_usd: float = 0.0
    llm_provider: str = "claude"
    llm_model: str | None = None
    # Per-gate overrides keyed by gate name (e.g. "nominate", "gate_1")
    gate_overrides: dict[str, dict[str, str | None]] = field(default_factory=dict)


def _new_run_id() -> str:
    return secrets.token_hex(4)


def load_or_create(  # noqa: PLR0913
    repo_dir: Path,
    *,
    engine: str,
    temperature: float,
    target_bug_classes: list[str],
    cost_cap_usd: float | None = None,
    run_id: str | None = None,
    llm_provider: str = "claude",
    llm_model: str | None = None,
) -> RunState:
    runs_root = repo_dir / "runs"
    runs_root.mkdir(parents=True, exist_ok=True)
    if run_id:
        run_dir = runs_root / run_id
        run_json = run_dir / "run.json"
        if run_json.is_file():
            data = json.loads(run_json.read_text(encoding="utf-8"))
            return RunState(
                run_id=data["run_id"],
                run_dir=run_dir,
                started_at=data["started_at"],
                phase=data["phase"],
                engine=data["engine"],
                temperature=float(data.get("temperature", 0.0)),
                target_bug_classes=list(data.get("target_bug_classes", [])),
                cost_cap_usd=data.get("cost_cap_usd"),
                calls=list(data.get("calls", [])),
                total_usd=float(data.get("total_usd", 0.0)),
                llm_provider=str(data.get("llm_provider", "claude")),
                llm_model=data.get("llm_model"),
                gate_overrides=dict(data.get("gate_overrides", {})),
            )
    new_id = run_id or _new_run_id()
    run_dir = runs_root / new_id
    run_dir.mkdir(parents=True, exist_ok=True)
    state = RunState(
        run_id=new_id,
        run_dir=run_dir,
        started_at=_dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
        phase="prep",
        engine=engine,
        temperature=temperature,
        target_bug_classes=target_bug_classes,
        cost_cap_usd=cost_cap_usd,
        llm_provider=llm_provider,
        llm_model=llm_model,
    )
    save(state)
    return state


def record_call(  # noqa: PLR0913
    state: RunState,
    *,
    step: str,
    model: str,
    input_tokens: int,
    cache_read: int,
    output_tokens: int,
    usd: float,
) -> None:
    state.calls.append(
        {
            "step": step,
            "model": model,
            "input_tokens": input_tokens,
            "cache_read": cache_read,
            "output_tokens": output_tokens,
            "usd": usd,
        }
    )
    state.total_usd = round(state.total_usd + usd, 12)


def save(state: RunState) -> None:
    payload = asdict(state)
    payload["run_dir"] = str(state.run_dir)
    (state.run_dir / "run.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

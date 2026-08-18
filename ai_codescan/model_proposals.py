"""Model-extension proposal artifacts.

Proposals are reviewable JSON files. Accepting a proposal is dry-run first and
requires an eval target so model changes stay tied to regression coverage.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import duckdb
import yaml

_STAGED_DIR_NAME = "rules.staged"
_RULE_ID_SAFE_RE = re.compile(r"[^a-z0-9-]+")


@dataclass(frozen=True, slots=True)
class ModelProposal:
    proposal_id: str
    nomination_id: str
    finding_id: str
    verdict: str
    cwe: str
    language: str
    framework: str
    bug_class: str
    source_pattern: str
    sink_pattern: str
    sanitizer_pattern: str  # Semgrep pattern-not clause; Phase 3
    vulnerable_example: str
    safe_example: str
    target_engine: str
    eval_target: str  # legacy single-target field, kept for back-compat
    rationale: str
    source_path: str
    # Phase 3 paired-target gate (Invariant 5): both must be present before
    # `accept_model_proposal(..., require_paired_targets=True)` succeeds.
    eval_positive: str = ""
    eval_negative: str = ""
    # Dedicated field for the Joern receiver-filter regex (the call-site
    # predicate that restricts a sink to certain receivers). Kept separate
    # from ``sanitizer_pattern`` — that field is the Semgrep negative
    # pattern and means something different.
    receiver_regex: str = ""

    def to_jsonable(self) -> dict[str, str]:
        return asdict(self)


def _proposal_id(*parts: str) -> str:
    blob = "|".join(parts)
    digest = hashlib.sha1(blob.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]
    return f"proposal-{digest}"


def _bug_class_for_cwe(cwe: str) -> str:
    return {
        "CWE-22": "path-traversal",
        "CWE-78": "cmdi",
        "CWE-79": "xss",
        "CWE-89": "sqli",
        "CWE-90": "ldap-injection",
        "CWE-93": "crlf-injection",
        "CWE-287": "missing-authn",
        "CWE-290": "identity-spoofing",
        "CWE-409": "uncontrolled-resource-consumption",
        "CWE-532": "sensitive-logging",
        "CWE-601": "open-redirect",
        "CWE-611": "xxe",
        "CWE-639": "bola",
        "CWE-643": "xpath-injection",
        "CWE-693": "protection-mechanism-bypass",
        "CWE-798": "hardcoded-credentials",
        "CWE-862": "bfla",
        "CWE-863": "incorrect-authorization-state",
        "CWE-915": "mass-assignment",
        "CWE-918": "ssrf",
        "CWE-943": "nosqli",
        "CWE-1321": "prototype-pollution",
        "CWE-1333": "redos",
        "CWE-1336": "ssti",
    }.get(cwe, "unknown")


def proposals_from_verdicts(  # noqa: PLR0913 - optional keyword-only proposal shaping
    conn: duckdb.DuckDBPyConnection,
    *,
    language: str = "",
    framework: str = "",
    target_engine: str = "heuristic",
    nomination_ids: frozenset[str] | None = None,
    proposal_details: Mapping[str, Mapping[str, object]] | None = None,
) -> list[ModelProposal]:
    has_table = conn.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'review_verdicts'"
    ).fetchone()
    if not has_table or int(has_table[0]) == 0:
        return []
    rows = conn.execute(
        """
        SELECT nomination_id, finding_id, verdict, cwe, title, source_path
        FROM review_verdicts
        WHERE verdict = 'needs-model-extension'
        ORDER BY nomination_id
        """
    ).fetchall()
    proposals: list[ModelProposal] = []
    for nomination_id, finding_id, verdict, cwe, title, source_path in rows:
        nomination_id_s = str(nomination_id or "")
        if nomination_ids is not None and nomination_id_s not in nomination_ids:
            continue
        details = (proposal_details or {}).get(nomination_id_s, {})
        cwe_s = str(cwe or "")
        proposals.append(
            ModelProposal(
                proposal_id=_proposal_id(str(nomination_id), str(finding_id), cwe_s),
                nomination_id=nomination_id_s,
                finding_id=str(finding_id or ""),
                verdict=str(verdict or ""),
                cwe=cwe_s,
                language=str(details.get("language") or language),
                framework=str(details.get("framework") or framework),
                bug_class=_bug_class_for_cwe(cwe_s),
                source_pattern=str(details.get("source_pattern") or ""),
                sink_pattern=str(details.get("sink_pattern") or ""),
                sanitizer_pattern=str(details.get("sanitizer_pattern") or ""),
                vulnerable_example=str(details.get("vulnerable_example") or ""),
                safe_example=str(details.get("safe_example") or ""),
                target_engine=str(details.get("target_engine") or target_engine),
                eval_target=str(details.get("eval_target") or ""),
                rationale=str(title or "LLM review marked this as a model-extension gap."),
                source_path=str(source_path or ""),
                eval_positive=str(details.get("eval_positive") or ""),
                eval_negative=str(details.get("eval_negative") or ""),
                receiver_regex=str(details.get("receiver_regex") or ""),
            )
        )
    return proposals


def write_model_proposals(proposals: list[ModelProposal], *, proposals_dir: Path) -> list[Path]:
    proposals_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for proposal in proposals:
        path = proposals_dir / f"{proposal.proposal_id}.json"
        path.write_text(
            json.dumps(proposal.to_jsonable(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        paths.append(path)
    return paths


def load_model_proposal(path: Path) -> ModelProposal:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"model proposal must be an object: {path}")
    return ModelProposal(**{field: str(data.get(field) or "") for field in ModelProposal.__slots__})


def list_model_proposals(proposals_dir: Path) -> list[ModelProposal]:
    if not proposals_dir.is_dir():
        return []
    return [load_model_proposal(path) for path in sorted(proposals_dir.glob("*.json"))]


def accept_model_proposal(
    proposal: ModelProposal,
    *,
    eval_target: Path,
    dry_run: bool = True,
    require_paired_targets: bool = False,
) -> dict[str, Any]:
    """Validate and (when not dry-run) record acceptance of a model proposal.

    Phase 3: ``require_paired_targets=True`` enforces Invariant 5 — the
    proposal must carry both ``eval_positive`` and ``eval_negative`` paths
    before acceptance. The legacy single ``eval_target`` arg is still
    required (it's the "this proposal is regression-tested against ≥1
    target" check from Phase 7).
    """
    if not eval_target.exists():
        raise ValueError(f"eval target does not exist: {eval_target}")
    if require_paired_targets:
        if not (proposal.eval_positive and proposal.eval_negative):
            raise ValueError(
                "paired-target gate: proposal must link both positive AND negative "
                "eval targets before apply (use `model-proposals link-targets`)"
            )
        if not Path(proposal.eval_positive).exists():
            raise ValueError(f"positive eval target missing: {proposal.eval_positive}")
        if not Path(proposal.eval_negative).exists():
            raise ValueError(f"negative eval target missing: {proposal.eval_negative}")
    return {
        "proposal_id": proposal.proposal_id,
        "accepted": not dry_run,
        "dry_run": dry_run,
        "eval_target": str(eval_target),
        "eval_positive": proposal.eval_positive,
        "eval_negative": proposal.eval_negative,
        "target_engine": proposal.target_engine,
        "message": "dry-run only; rule staging is not implemented yet"
        if dry_run
        else "accepted; rule staging is not implemented yet",
    }


def record_proposal_decision(  # noqa: PLR0913 - keyword-only mirror of proposal_decisions columns
    conn: duckdb.DuckDBPyConnection,
    *,
    proposal_id: str,
    decision: str,
    engine: str = "",
    eval_positive: str = "",
    eval_negative: str = "",
    applied_path: str = "",
) -> None:
    """Persist a proposal decision into the `proposal_decisions` DuckDB table.

    `decision` is one of `pending`, `applied`, `rejected`. Re-recording a
    proposal replaces the prior row so the table always reflects the latest
    state. The schema lives in `ai_codescan.index.duckdb_schema`.
    """
    if decision not in {"pending", "applied", "rejected"}:
        raise ValueError(f"decision must be pending|applied|rejected, got {decision!r}")
    conn.execute(
        """
        INSERT OR REPLACE INTO proposal_decisions
          (proposal_id, decision, engine, eval_positive, eval_negative, applied_path)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [proposal_id, decision, engine, eval_positive, eval_negative, applied_path],
    )


def proposal_decision_counts(conn: duckdb.DuckDBPyConnection) -> dict[str, int]:
    """Return {decision: count} for the `proposal_decisions` table."""
    has_table = conn.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'proposal_decisions'"
    ).fetchone()
    if not has_table or int(has_table[0]) == 0:
        return {"pending": 0, "applied": 0, "rejected": 0}
    rows = conn.execute(
        "SELECT decision, COUNT(*) FROM proposal_decisions GROUP BY decision"
    ).fetchall()
    counts = {"pending": 0, "applied": 0, "rejected": 0}
    for decision, count in rows:
        counts[str(decision or "pending")] = int(count or 0)
    return counts


def link_eval_targets(
    proposal: ModelProposal,
    *,
    positive: Path,
    negative: Path,
    proposals_dir: Path,
) -> ModelProposal:
    """Attach positive + negative eval targets to a proposal and persist."""
    if not positive.exists():
        raise ValueError(f"positive eval target does not exist: {positive}")
    if not negative.exists():
        raise ValueError(f"negative eval target does not exist: {negative}")
    updated = ModelProposal(
        proposal_id=proposal.proposal_id,
        nomination_id=proposal.nomination_id,
        finding_id=proposal.finding_id,
        verdict=proposal.verdict,
        cwe=proposal.cwe,
        language=proposal.language,
        framework=proposal.framework,
        bug_class=proposal.bug_class,
        source_pattern=proposal.source_pattern,
        sink_pattern=proposal.sink_pattern,
        sanitizer_pattern=proposal.sanitizer_pattern,
        vulnerable_example=proposal.vulnerable_example,
        safe_example=proposal.safe_example,
        target_engine=proposal.target_engine,
        eval_target=proposal.eval_target,
        eval_positive=str(positive),
        eval_negative=str(negative),
        rationale=proposal.rationale,
        source_path=proposal.source_path,
    )
    target_path = proposals_dir / f"{proposal.proposal_id}.json"
    target_path.write_text(
        json.dumps(updated.to_jsonable(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return updated


def _semgrep_rule_id(proposal: ModelProposal) -> str:
    """Stable, filename-safe rule id derived from CWE + proposal id."""
    cwe_slug = _RULE_ID_SAFE_RE.sub("-", (proposal.cwe or "unknown").lower())
    return f"aics-{cwe_slug}-{proposal.proposal_id}"


def apply_proposal_to_semgrep(
    proposal: ModelProposal,
    *,
    rules_root: Path,
    staged: bool = True,
) -> Path:
    """Render a Semgrep YAML rule from a model proposal.

    Phase 3 staged-not-merged gate: by default the rule lands under
    ``rules_root / "rules.staged"``. A follow-up `--promote` flow (not in
    Phase 3) will move it to ``rules_root / "rules"`` after a paired eval
    run confirms no recall regression. When ``sink_pattern`` is empty the
    rule still lands but its `pattern` field carries a `TODO:` so a human
    (or another LLM pass) refines it before promotion.
    """
    target_dir = rules_root / (_STAGED_DIR_NAME if staged else "rules")
    target_dir.mkdir(parents=True, exist_ok=True)
    rule_id = _semgrep_rule_id(proposal)
    pattern: Any = (
        proposal.sink_pattern
        if proposal.sink_pattern
        else ("TODO: human/LLM must refine — proposal was emitted without a sink pattern")
    )
    metadata: dict[str, Any] = {
        "cwe": proposal.cwe or "unknown",
        "bug_class": proposal.bug_class or "unknown",
        "proposal_id": proposal.proposal_id,
        "nomination_id": proposal.nomination_id,
        "finding_id": proposal.finding_id,
        "stage": "staged" if staged else "promoted",
        "vulnerable_example": proposal.vulnerable_example,
        "safe_example": proposal.safe_example,
        "rationale": proposal.rationale,
        "eval_target": proposal.eval_target,
    }
    rule: dict[str, Any] = {
        "id": rule_id,
        "message": f"{proposal.cwe} ({proposal.bug_class}): {proposal.rationale}",
        "severity": "ERROR",
        "languages": [proposal.language or "generic"],
        "metadata": metadata,
        "pattern": pattern,
    }
    if proposal.sanitizer_pattern:
        # Semgrep `pattern-not` is the cheapest way to encode a sanitizer
        # hint. For a full taint-mode rule, a follow-up promotion step
        # restructures into pattern-sources/pattern-sinks/pattern-sanitizers.
        rule["pattern-not"] = proposal.sanitizer_pattern
    document = {"rules": [rule]}
    target_path = target_dir / f"{rule_id}.yml"
    target_path.write_text(
        yaml.safe_dump(document, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    return target_path

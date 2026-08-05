"""Lightweight mitigation annotation helpers.

These helpers are deliberately conservative: they add review context and
lower priority, but do not suppress candidates.
"""

from __future__ import annotations

import json
import re
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import duckdb

_MAX_CONTEXT_LINES = 8
_MIN_FLOW_STEP_FIELDS = 2


@dataclass(frozen=True, slots=True)
class MitigationSignal:
    kind: str
    confidence: str
    reason: str
    evidence: str

    def to_jsonable(self) -> dict[str, str]:
        return asdict(self)


def detect_sqli_mitigations(text: str, *, parameterization: str = "") -> list[MitigationSignal]:
    signals: list[MitigationSignal] = []
    param = parameterization.lower()
    if any(token in param for token in ("parameterized", "prepared", "bound")):
        signals.append(
            MitigationSignal(
                "sqli.parameterized-api",
                "high",
                "sink metadata indicates parameterization",
                parameterization,
            )
        )
    if re.search(r"(?i)(parameters\.add|addwithvalue|sqlparameter|sqliteparameter)", text):
        signals.append(
            MitigationSignal(
                "sqli.bound-parameter",
                "high",
                "code uses explicit SQL command parameters",
                "parameter binding call",
            )
        )
    if re.search(r"(?i)\bprepare(?:d)?statement\b|\bprepare\s*\(", text):
        signals.append(
            MitigationSignal(
                "sqli.prepared-statement",
                "medium",
                "code appears to use prepared statements",
                "prepare/prepared statement",
            )
        )
    # Python DB-API parameterized execute: ``cursor.execute(sql, (val,))`` or
    # ``cursor.execute(sql, [val])`` — second arg is a tuple/list of params.
    # Distinguishes the safe form from string-formatted SQL while matching the
    # majority of stdlib/sqlite3/psycopg/MySQLdb usage. The pattern is DOTALL
    # so multi-line call shapes like
    #     cursor.execute(
    #         "SELECT ... ?",
    #         (user_id,),
    #     )
    # still match (Phase 3 callout from the Phase-2 REVIEW.md).
    if re.search(
        r"(?is)\bexecute\s*\([^()]+,\s*[\[\(]",
        text,
    ):
        signals.append(
            MitigationSignal(
                "sqli.python-parameterized-execute",
                "medium",
                "Python DB-API execute() is called with a parameter tuple/list",
                "execute(sql, params)",
            )
        )
    return signals


def detect_command_mitigations(text: str) -> list[MitigationSignal]:
    signals: list[MitigationSignal] = []
    if re.search(r"(?i)shell\s*=\s*false", text):
        signals.append(
            MitigationSignal(
                "cmdi.shell-disabled",
                "medium",
                "command execution disables shell interpretation",
                "shell=False",
            )
        )
    if re.search(r"(?i)(argumentlist|execfile|spawn)\s*\(", text):
        signals.append(
            MitigationSignal(
                "cmdi.argument-array",
                "medium",
                "command appears to pass arguments without shell string expansion",
                "argument-array style call",
            )
        )
    return signals


def detect_path_mitigations(text: str) -> list[MitigationSignal]:
    signals: list[MitigationSignal] = []
    canonical = re.search(r"(?i)(getfullpath|realpath|resolve\s*\(|resolve_path)", text)
    strong_containment = re.search(
        r"(?i)(relative_to|commonpath|is_relative_to|startswith\s*\([^)]*(separator|/))",
        text,
    )
    weak_containment = re.search(r"(?i)startswith", text)
    if canonical and strong_containment:
        signals.append(
            MitigationSignal(
                "path.canonical-root-containment",
                "high",
                "path is canonicalized and checked against an allowed root",
                "canonicalization plus containment check",
            )
        )
    elif canonical and weak_containment:
        signals.append(
            MitigationSignal(
                "path.prefix-check-needs-review",
                "low",
                "path is canonicalized and prefix-checked, but separator safety needs review",
                "canonicalization plus prefix check",
            )
        )
    elif canonical:
        signals.append(
            MitigationSignal(
                "path.canonicalization",
                "medium",
                "path is canonicalized, but root containment needs review",
                "canonicalization call",
            )
        )
    return signals


def detect_xss_mitigations(text: str) -> list[MitigationSignal]:
    if re.search(r"(?i)(htmlencode|escapehtml|dompurify|sanitizehtml|textcontent)", text):
        return [
            MitigationSignal(
                "xss.output-encoding",
                "medium",
                "code appears to encode, sanitize, or assign text-only content",
                "encoding/sanitization call",
            )
        ]
    return []


def detect_ssrf_mitigations(text: str) -> list[MitigationSignal]:
    if re.search(r"(?i)(allowlist|allowedhosts|allowed_hosts|isallowedhost|fixedhost)", text):
        return [
            MitigationSignal(
                "ssrf.host-allowlist",
                "medium",
                "code appears to validate the target host against an allowlist",
                "host allowlist check",
            )
        ]
    return []


def detect_authz_mitigations(text: str) -> list[MitigationSignal]:
    if re.search(
        r"(?i)(requireauthorization|authorize\b|require.*role|hasaccess|isowner|tenant)",
        text,
    ):
        return [
            MitigationSignal(
                "authz.nearby-policy-check",
                "medium",
                "code contains nearby authentication, authorization, owner, or tenant checks",
                "authz-looking check",
            )
        ]
    return []


def detect_mass_assignment_mitigations(text: str) -> list[MitigationSignal]:
    if re.search(r"(?i)(dto\b|bindnever|jsonignore|pick\s*\(|omit\s*\(|allowlist)", text):
        return [
            MitigationSignal(
                "mass-assignment.explicit-binding",
                "medium",
                "code appears to use explicit binding or field allowlisting",
                "explicit binding marker",
            )
        ]
    return []


def detect_logging_mitigations(text: str) -> list[MitigationSignal]:
    """Detect redaction or filtering patterns near a logging sink (CWE-532)."""
    if re.search(
        r"(?i)(redact|sanitize|scrub|filter\s*\(|"
        r"delete\s+\w+\.(?:password|token|secret|authorization|cookie)|"
        r"masklog|pino\b.*redact|winston\b.*redact|bunyan\b.*redact)",
        text,
    ):
        return [
            MitigationSignal(
                "log.redaction",
                "medium",
                "code appears to redact or filter sensitive fields before logging",
                "redaction/sanitization marker",
            )
        ]
    return []


def detect_mitigations(
    text: str,
    *,
    cwe: str = "",
    sink_class: str = "",
    parameterization: str = "",
) -> list[MitigationSignal]:
    """Return mitigation signals relevant to a candidate's vulnerability class."""
    key = f"{cwe} {sink_class}".lower()
    signals: list[MitigationSignal] = []
    if "cwe-89" in key or "sql" in key:
        signals.extend(detect_sqli_mitigations(text, parameterization=parameterization))
    if "cwe-78" in key or "cmd" in key or "command" in key:
        signals.extend(detect_command_mitigations(text))
    if "cwe-22" in key or "fs." in key or "path" in key:
        signals.extend(detect_path_mitigations(text))
    if "cwe-79" in key or "html" in key or "xss" in key:
        signals.extend(detect_xss_mitigations(text))
    if "cwe-918" in key or "ssrf" in key or "http.client" in key:
        signals.extend(detect_ssrf_mitigations(text))
    if "cwe-639" in key or "cwe-862" in key or "auth" in key:
        signals.extend(detect_authz_mitigations(text))
    if "cwe-915" in key or "mass" in key:
        signals.extend(detect_mass_assignment_mitigations(text))
    if "cwe-532" in key or "log.sensitive" in key or "log" in sink_class.lower():
        signals.extend(detect_logging_mitigations(text))
    return signals


def _parse_loc(loc: str) -> tuple[Path, int] | None:
    file, sep, raw_line = loc.rpartition(":")
    if not sep:
        return None
    try:
        return Path(file), int(raw_line)
    except ValueError:
        return None


def _read_context(path: Path, line: int) -> str:
    if not path.is_file():
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, line - _MAX_CONTEXT_LINES)
    end = min(len(lines), line + _MAX_CONTEXT_LINES)
    return "\n".join(lines[start - 1 : end])


def _candidate_context(conn: duckdb.DuckDBPyConnection, candidate: dict[str, Any]) -> str:
    chunks: list[str] = []
    if (loc := str(candidate.get("source_loc") or "")) and (parsed := _parse_loc(loc)):
        chunks.append(_read_context(*parsed))
    if candidate.get("file") and candidate.get("line"):
        with suppress(TypeError, ValueError):
            chunks.append(_read_context(Path(str(candidate["file"])), int(candidate["line"])))
    if candidate.get("fid"):
        row = conn.execute(
            "SELECT steps_json FROM flows WHERE fid = ?",
            [candidate["fid"]],
        ).fetchone()
        if row:
            try:
                steps = json.loads(str(row[0] or "[]"))
            except json.JSONDecodeError:
                steps = []
            for step in steps:
                if not isinstance(step, list) or len(step) < _MIN_FLOW_STEP_FIELDS:
                    continue
                try:
                    chunks.append(_read_context(Path(str(step[0])), int(step[1])))
                except (TypeError, ValueError):
                    continue
    return "\n".join(chunk for chunk in chunks if chunk)


def mitigations_for_candidate(
    conn: duckdb.DuckDBPyConnection,
    candidate: dict[str, Any],
) -> list[dict[str, str]]:
    text = _candidate_context(conn, candidate)
    signals = detect_mitigations(
        text,
        cwe=str(candidate.get("cwe") or ""),
        sink_class=str(candidate.get("sink_class") or ""),
        parameterization=str(candidate.get("parameterization") or ""),
    )
    return [signal.to_jsonable() for signal in signals]

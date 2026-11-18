"""Discover exploit gadgets and link them to compatible findings."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import duckdb

from ai_codescan.findings.model import parse_finding
from ai_codescan.source_paths import SourcePathError, resolve_contained_file

_JS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})
_IDENTIFIER = r"[A-Za-z_$][A-Za-z0-9_$]*"
_PLAIN_OBJECT_RE = re.compile(
    rf"\b(?:const|let|var)\s+(?P<receiver>{_IDENTIFIER})\s*=\s*"
    r"(?:\{\s*\}|Object\.assign\(\s*\{\s*\})"
)
_AUTH_CHECK_RE = re.compile(
    rf"\bif\s*\([^\n]*?\b(?P<receiver>{_IDENTIFIER})(?:\?\.|\.)"
    r"(?P<property>isAdmin|admin|isAuthorized|authorized|isAuthenticated|"
    r"authenticated|role|can[A-Z][A-Za-z0-9_$]*)\b"
)
_OWN_GUARD_TEMPLATES = (
    r"Object\.hasOwn\(\s*{receiver}\s*,\s*['\"]{property}['\"]\s*\)",
    r"hasOwnProperty\.call\(\s*{receiver}\s*,\s*['\"]{property}['\"]\s*\)",
    r"{receiver}\.hasOwnProperty\(\s*['\"]{property}['\"]\s*\)",
)
_GUARD_LOOKBACK_CHARS = 600
_CHILD_PROCESS_METHODS = (
    "exec",
    "execFile",
    "execFileSync",
    "execSync",
    "fork",
    "spawn",
    "spawnSync",
)
_CHILD_PROCESS_IMPORT_RE = re.compile(
    r"(?:\b(?:const|let|var)\s*\{(?P<require_names>[^}]+)\}\s*=\s*"
    r"require\(\s*['\"](?:node:)?child_process['\"]\s*\)|"
    r"\bimport\s*\{(?P<import_names>[^}]+)\}\s*from\s*"
    r"['\"](?:node:)?child_process['\"])"
)
_CHILD_PROCESS_NAMESPACE_RE = re.compile(
    rf"(?:\b(?:const|let|var)\s+(?P<require_name>{_IDENTIFIER})\s*=\s*"
    r"require\(\s*['\"](?:node:)?child_process['\"]\s*\)|"
    rf"\bimport\s*\*\s*as\s+(?P<import_name>{_IDENTIFIER})\s+from\s*"
    r"['\"](?:node:)?child_process['\"])"
)
_GADGET_RELATIONSHIPS = {
    "inherited-authorization-flag": "bypass",
    "inherited-child-process-command": "impact-amplifier",
}


@dataclass(frozen=True, slots=True)
class GadgetCandidate:
    gadget_id: str
    gadget_class: str
    capability: str
    project_id: str
    file: str
    line: int
    evidence: str
    prerequisites: tuple[str, ...]
    detector: str = "js-inherited-auth-flag-v1"

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GadgetLink:
    link_id: str
    gadget_id: str
    relationship: str
    confidence: str
    flow_id: str
    candidate_id: str
    finding_id: str
    connection_basis: str
    evidence: tuple[str, ...]
    unmet_prerequisites: tuple[str, ...]

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GadgetAnalysis:
    candidates: tuple[GadgetCandidate, ...]
    links: tuple[GadgetLink, ...]


@dataclass(frozen=True, slots=True)
class GadgetRunResult:
    analysis: GadgetAnalysis
    candidates_path: Path
    links_path: Path
    markdown_path: Path
    report_path: Path | None


@dataclass(frozen=True, slots=True)
class _PrototypePollutionFlow:
    flow_id: str
    file: str


def _stable_id(prefix: str, *parts: object) -> str:
    material = "\0".join(str(part) for part in parts)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def _has_own_property_guard(text: str, *, receiver: str, property_name: str, offset: int) -> bool:
    start = max(0, offset - _GUARD_LOOKBACK_CHARS)
    context = text[start : text.find("\n", offset) if "\n" in text[offset:] else len(text)]
    values = {"receiver": re.escape(receiver), "property": re.escape(property_name)}
    return any(re.search(template.format(**values), context) for template in _OWN_GUARD_TEMPLATES)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _relative_file(source_root: Path, path: Path) -> str:
    return path.resolve().relative_to(source_root.resolve()).as_posix()


def _auth_flag_gadgets_in_text(
    text: str,
    *,
    file: str,
    project_id: str,
) -> list[GadgetCandidate]:
    initializations = {
        match.group("receiver"): match.start() for match in _PLAIN_OBJECT_RE.finditer(text)
    }
    gadgets: list[GadgetCandidate] = []
    for match in _AUTH_CHECK_RE.finditer(text):
        receiver = match.group("receiver")
        property_name = match.group("property")
        if initializations.get(receiver, match.start() + 1) >= match.start():
            continue
        if _has_own_property_guard(
            text,
            receiver=receiver,
            property_name=property_name,
            offset=match.start(),
        ):
            continue
        line = _line_number(text, match.start())
        evidence = text.splitlines()[line - 1].strip()
        gadgets.append(
            GadgetCandidate(
                gadget_id=_stable_id("G", file, line, receiver, property_name),
                gadget_class="inherited-authorization-flag",
                capability="authorization-bypass",
                project_id=project_id,
                file=file,
                line=line,
                evidence=evidence,
                prerequisites=(
                    f"An attacker can set the inherited {property_name} property.",
                    "The process reaches this authorization branch after the mutation.",
                ),
            )
        )
    return gadgets


def _child_process_call_names(text: str) -> set[str]:
    names: set[str] = set()
    for match in _CHILD_PROCESS_IMPORT_RE.finditer(text):
        imported = match.group("require_names") or match.group("import_names") or ""
        for method in _CHILD_PROCESS_METHODS:
            binding = re.search(
                rf"(?:^|,)\s*{method}\s*(?:(?:as|:)\s*(?P<alias>{_IDENTIFIER}))?\s*(?=,|$)",
                imported,
            )
            if binding:
                names.add(binding.group("alias") or method)
    for match in _CHILD_PROCESS_NAMESPACE_RE.finditer(text):
        namespace = match.group("require_name") or match.group("import_name")
        names.update(f"{namespace}.{method}" for method in _CHILD_PROCESS_METHODS)
    return names


def _sets_own_property(
    text: str,
    *,
    receiver: str,
    property_name: str,
    initialization_offset: int,
    use_offset: int,
) -> bool:
    context = text[initialization_offset:use_offset]
    escaped_receiver = re.escape(receiver)
    escaped_property = re.escape(property_name)
    patterns = (
        rf"\b{escaped_receiver}(?:\.{escaped_property}|"
        rf"\[['\"]{escaped_property}['\"]\])\s*=",
        rf"Object\.defineProperty\(\s*{escaped_receiver}\s*,\s*"
        rf"['\"]{escaped_property}['\"]",
    )
    return any(re.search(pattern, context) for pattern in patterns)


def _child_process_command_gadgets_in_text(
    text: str,
    *,
    file: str,
    project_id: str,
) -> list[GadgetCandidate]:
    initializations = {
        match.group("receiver"): match.start() for match in _PLAIN_OBJECT_RE.finditer(text)
    }
    gadgets: list[GadgetCandidate] = []
    for call_name in sorted(_child_process_call_names(text)):
        call_re = re.compile(
            rf"\b{re.escape(call_name)}\s*\(\s*"
            rf"(?P<receiver>{_IDENTIFIER})(?:\?\.|\.)"
            r"(?P<property>command|file|modulePath)\b"
        )
        for match in call_re.finditer(text):
            receiver = match.group("receiver")
            property_name = match.group("property")
            initialization_offset = initializations.get(receiver, match.start() + 1)
            if initialization_offset >= match.start() or _sets_own_property(
                text,
                receiver=receiver,
                property_name=property_name,
                initialization_offset=initialization_offset,
                use_offset=match.start(),
            ):
                continue
            line = _line_number(text, match.start())
            evidence = text.splitlines()[line - 1].strip()
            gadgets.append(
                GadgetCandidate(
                    gadget_id=_stable_id("G", file, line, call_name, receiver, property_name),
                    gadget_class="inherited-child-process-command",
                    capability="command-execution",
                    project_id=project_id,
                    file=file,
                    line=line,
                    evidence=evidence,
                    prerequisites=(
                        f"An attacker can set the inherited {property_name} property.",
                        "The process reaches this child process call after the mutation.",
                    ),
                    detector="js-inherited-child-process-command-v1",
                )
            )
    return gadgets


def discover_gadgets(
    conn: duckdb.DuckDBPyConnection,
    *,
    source_root: Path,
) -> list[GadgetCandidate]:
    """Find supported gadget classes in indexed JavaScript source files."""
    rows = conn.execute("SELECT path, COALESCE(project_id, '') FROM files ORDER BY path").fetchall()
    gadgets: list[GadgetCandidate] = []
    for raw_path, raw_project_id in rows:
        try:
            path = resolve_contained_file(source_root, str(raw_path))
        except SourcePathError:
            continue
        if path.suffix.lower() not in _JS_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        file = _relative_file(source_root, path)
        project_id = str(raw_project_id or "")
        gadgets.extend(_auth_flag_gadgets_in_text(text, file=file, project_id=project_id))
        gadgets.extend(
            _child_process_command_gadgets_in_text(text, file=file, project_id=project_id)
        )
    return gadgets


def _prototype_pollution_flows(
    conn: duckdb.DuckDBPyConnection,
) -> list[_PrototypePollutionFlow]:
    rows = conn.execute(
        """
        SELECT f.fid, COALESCE(symbol.file, ''), COALESCE(f.steps_json, '[]')
        FROM flows f
        JOIN taint_sinks sink ON sink.sid = f.sid
        LEFT JOIN symbols symbol ON symbol.id = sink.symbol_id
        WHERE f.cwe = 'CWE-1321' OR sink.class = 'proto.pollute'
        ORDER BY f.fid
        """
    ).fetchall()
    flows: list[_PrototypePollutionFlow] = []
    for raw_flow_id, raw_file, raw_steps in rows:
        file = str(raw_file or "")
        if not file:
            try:
                steps = json.loads(str(raw_steps or "[]"))
            except json.JSONDecodeError:
                steps = []
            if steps and isinstance(steps[-1], list) and steps[-1]:
                file = str(steps[-1][0])
        flows.append(
            _PrototypePollutionFlow(
                flow_id=str(raw_flow_id),
                file=file,
            )
        )
    return flows


def _run_references(run_dir: Path) -> tuple[dict[str, str], dict[str, str]]:
    candidate_by_flow: dict[str, str] = {}
    registry_path = run_dir / "candidate_registry.jsonl"
    if registry_path.is_file():
        for line in registry_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            flow_id = str(row.get("fid") or row.get("flow_id") or "")
            candidate_id = str(row.get("candidate_id") or row.get("id") or "")
            if flow_id and candidate_id:
                candidate_by_flow[flow_id] = candidate_id
    finding_by_candidate: dict[str, str] = {}
    for path in sorted((run_dir / "findings").glob("*.md")):
        markdown = path.read_text(encoding="utf-8")
        if not markdown.startswith("---\n"):
            continue
        finding = parse_finding(markdown)
        candidate_id = finding.candidate_id or finding.nomination_id
        if candidate_id:
            finding_by_candidate[candidate_id] = finding.finding_id
    return candidate_by_flow, finding_by_candidate


def link_prototype_pollution_gadgets(
    conn: duckdb.DuckDBPyConnection,
    gadgets: list[GadgetCandidate],
    *,
    run_dir: Path,
) -> list[GadgetLink]:
    """Link compatible gadgets to same-file prototype-pollution flows."""
    candidate_by_flow, finding_by_candidate = _run_references(run_dir)
    links: list[GadgetLink] = []
    for flow in _prototype_pollution_flows(conn):
        for gadget in gadgets:
            same_file = bool(flow.file and flow.file.endswith(gadget.file))
            if not same_file:
                continue
            candidate_id = candidate_by_flow.get(flow.flow_id, "")
            links.append(
                GadgetLink(
                    link_id=_stable_id("GL", flow.flow_id, gadget.gadget_id),
                    gadget_id=gadget.gadget_id,
                    relationship=_GADGET_RELATIONSHIPS[gadget.gadget_class],
                    confidence="low",
                    flow_id=flow.flow_id,
                    candidate_id=candidate_id,
                    finding_id=finding_by_candidate.get(candidate_id, ""),
                    connection_basis="same-file",
                    evidence=(
                        "The prototype-pollution flow and gadget occur in the same source file.",
                        f"The {gadget.gadget_class} gadget provides {gadget.capability} at "
                        f"{gadget.file}:{gadget.line}.",
                    ),
                    unmet_prerequisites=(
                        *gadget.prerequisites,
                        "The detected flow mutates the prototype used by this gadget.",
                        "The prototype mutation and gadget execute in one process.",
                        "The mutation occurs before the gadget.",
                    ),
                )
            )
    return links


def analyze_gadgets(
    conn: duckdb.DuckDBPyConnection,
    *,
    source_root: Path,
    run_dir: Path,
) -> GadgetAnalysis:
    """Discover all gadgets and create evidence-backed compatible links."""
    candidates = discover_gadgets(conn, source_root=source_root)
    links = link_prototype_pollution_gadgets(conn, candidates, run_dir=run_dir)
    return GadgetAnalysis(tuple(candidates), tuple(links))


def _write_jsonl(path: Path, rows: tuple[Any, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row.to_jsonable(), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def render_gadget_report(analysis: GadgetAnalysis) -> str:
    """Render linked and standalone gadgets without promoting them to findings."""
    linked_ids = {link.gadget_id for link in analysis.links}
    lines = [
        "# Exploit gadgets",
        "",
        "A gadget is code that can change impact when another vulnerability is present.",
        "Gadgets are not independent vulnerability findings.",
        "",
        "| gadget | class | capability | location | state |",
        "|---|---|---|---|---|",
    ]
    for gadget in analysis.candidates:
        state = "linked" if gadget.gadget_id in linked_ids else "unpaired"
        lines.append(
            f"| `{gadget.gadget_id}` | {gadget.gadget_class} | {gadget.capability} | "
            f"`{gadget.file}:{gadget.line}` | {state} |"
        )
    if not analysis.candidates:
        lines.append("| - | - | - | - | none found |")
    lines.extend(["", "## Compatible links", ""])
    if not analysis.links:
        lines.append("No compatible vulnerability link was found. Unpaired gadgets remain visible.")
        return "\n".join(lines) + "\n"
    for link in analysis.links:
        target = link.finding_id or link.candidate_id or link.flow_id
        lines.extend(
            [
                f"### {link.link_id}",
                "",
                f"- Gadget: `{link.gadget_id}`",
                f"- Related scanner item: `{target}`",
                f"- Relationship: `{link.relationship}`",
                f"- Confidence: `{link.confidence}`",
                f"- Connection basis: `{link.connection_basis}`",
                "- Evidence:",
                *(f"  - {item}" for item in link.evidence),
                "- Unmet prerequisites:",
                *(f"  - {item}" for item in link.unmet_prerequisites),
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def write_gadget_artifacts(
    analysis: GadgetAnalysis,
    *,
    output_dir: Path,
) -> tuple[Path, Path, Path]:
    """Write machine-readable candidates, links, and a human report."""
    candidates_path = output_dir / "gadget-candidates.jsonl"
    links_path = output_dir / "gadget-links.jsonl"
    markdown_path = output_dir / "gadgets.md"
    _write_jsonl(candidates_path, analysis.candidates)
    _write_jsonl(links_path, analysis.links)
    markdown_path.write_text(render_gadget_report(analysis), encoding="utf-8")
    return candidates_path, links_path, markdown_path


def run_gadget_analysis(
    *,
    db_path: Path,
    source_root: Path,
    run_dir: Path,
    report_dir: Path | None = None,
) -> GadgetRunResult:
    """Discover gadgets and write run and optional report artifacts."""
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        analysis = analyze_gadgets(conn, source_root=source_root, run_dir=run_dir)
    finally:
        conn.close()
    candidates_path, links_path, markdown_path = write_gadget_artifacts(
        analysis,
        output_dir=run_dir,
    )
    report_path = None
    if report_dir is not None:
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "gadgets.md"
        shutil.copyfile(markdown_path, report_path)
    return GadgetRunResult(
        analysis=analysis,
        candidates_path=candidates_path,
        links_path=links_path,
        markdown_path=markdown_path,
        report_path=report_path,
    )

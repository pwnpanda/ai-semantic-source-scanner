"""Source-aware nominations for security defects that are not ordinary taint flows.

The rules in this module deliberately emit reviewable Stream-B hotspots. They do
not claim that a business-logic vulnerability is proven merely because a source
shape matched. The one exception is a literal credential in configuration: the
unsafe storage decision is deterministic even when deployment reachability is
unknown.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import duckdb

SignalStrength = Literal["contextual", "strong", "deterministic"]

_SUPPORTED_SUFFIXES = {".java", ".kt", ".kts", ".yaml", ".yml"}
_APPROVAL_RE = re.compile(r"(?i)\b(?:approv\w*|godkjenn\w*)\b")
_PRINCIPAL_RE = re.compile(
    r"(?i)\b(?:approver|assignee|responsible|owner|godkjenner|ansvarlig|saksbehandler)\w*\b"
)
_REQUEST_INPUT_RE = re.compile(
    r"(?i)\b(?:request|req|input|dto|command|kommando|forespoersel|forespørsel|payload)\w*\b"
)
_OWNER_GUARD_RE = re.compile(
    r"(?is)\b(?:assert|require|check|verify|validate|authoriz)\w*.{0,100}"
    r"(?:owner|responsible|assigned|ansvarlig|saksbehandler)|"
    r"(?:owner|responsible|assigned|ansvarlig|saksbehandler)\w*.{0,100}"
    r"(?:currentUser|caller|authContext|principal)"
)
_PERSIST_RE = re.compile(r"(?i)\b(?:save|update|persist|mutat|assign|tildel|lagre|endre)\w*\b")
_HISTORICAL_APPROVAL_RE = re.compile(
    r"(?is)\b(?:any|exists|ever|previous|histor\w*|tidligere|har)\w*.{0,120}"
    r"(?:approv|godkjenn)|(?:approv|godkjenn)\w*.{0,120}"
    r"(?:any|exists|ever|previous|histor\w*|tidligere|isNotEmpty)|"
    r"(?:everApproved|previouslyApproved|hasBeenApproved|harVaertGodkjent|"
    r"godkjentEllerHarVaertGodkjentTidligere)"
)
_CONTENT_BINDING_RE = re.compile(r"(?i)\b(?:hash|digest|checksum|innhold|content)\w*\b")
_CURRENT_APPROVAL_RE = re.compile(
    r"(?i)\b(?:isCurrentlyApproved|currentApproval|erGodkjent|"
    r"(?:current|gjeldende)\w*(?:hash|digest|approval|godkjenn))\w*\b"
)
_VALIDATION_RE = re.compile(
    r"(?i)\b(?:validat|valider|vurderingsreg|assessmentRule|requirement|"
    r"execute|utfoer|utfør)\w*\b"
)
_SKIP_VALIDATION_RE = re.compile(
    r"(?i)\b(?:skip|bypass|disable|ignore|omit)\w*.{0,50}"
    r"(?:validat|rule|check|vurderingsreg)|"
    r"(?:validat|rule|check|vurderingsreg)\w*.{0,50}"
    r"(?:skip|bypass|disable|ignore|omit)"
)
_NULLABLE_LOOKUP_RE = re.compile(
    r"(?i)\b(?:singleOrNull|firstOrNull|find\w*OrNull|lookup\w*OrNull)\s*(?:\(|\{)"
)
_NULLABLE_POLICY_VALUE_RE = re.compile(
    r"(?is)(?:\b(?:spec|policy|regel|rule)\w*\s*:\s*[^,\n]+\?|"
    r"Map\s*<[^>]*\b(?:Spec|Policy|Regel|Rule)\w*\s*\?>)"
)
_FAIL_OPEN_RE = re.compile(
    r"(?is)(?:\?:\s*return(?:\s+emptyList\s*\(\))?|"
    r"if\s*\([^)]*==\s*null[^)]*\)\s*(?:\{\s*)?return(?:\s+emptyList\s*\(\))?)"
)
_NULL_POLICY_RETURN_RE = re.compile(
    r"(?is)if\s*\(\s*(?:spec|policy|regel|rule)\w*\s*==\s*null\s*\)"
    r"\s*(?:\{\s*)?return"
)
_IDENTITY_SWITCH_RE = re.compile(
    r"(?is)\b(?:withUserId|runAsUser(?:Id)?|impersonate|switchUser)\s*\((?P<arg>.{0,240}?)\)"
)
_MUTATION_MAPPING_RE = re.compile(
    r"(?i)@(?:Post|Put|Patch|Delete)Mapping\b|"
    r"@RequestMapping\s*\([^)]*RequestMethod\.(?:POST|PUT|PATCH|DELETE)"
)
_ADMIN_CONTEXT_RE = re.compile(r"(?i)(?:AdminController|/admin\b|\badmin(?:istrat)?\w*)")
_GUARD_CALL_RE = re.compile(
    r"(?i)\b(?:(?:assert|require|check|verify)\w*"
    r"(?:Authoriz|Permission|Role|Admin|Access)\w*|authoriz\w*|"
    r"hasPermission|hasRole|isAdmin)\s*\("
)
_JAXP_FACTORY_RE = re.compile(r"\bTransformerFactory\b")
_JAXP_IDENTITY_RE = re.compile(r"\bnewTransformer\s*\(\s*\)")
_JAXP_TRANSFORM_RE = re.compile(r"\.\s*transform\s*\(")
_JAXP_HARDENING_RE = re.compile(
    r"(?i)(?:ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_STYLESHEET|FEATURE_SECURE_PROCESSING|"
    r"disallow-doctype-decl|external-general-entities)"
)
_LOG_CALL_RE = re.compile(
    r"(?is)\b(?:log|logger|LOG)\s*\.\s*(?:trace|debug|info|warn|error|fatal)\s*"
    r"\((?P<args>.{0,800}?)\)"
)
_LOG_LAMBDA_CALL_RE = re.compile(
    r"(?im)\b(?:log|logger|LOG)\s*\.\s*(?:trace|debug|info|warn|error|fatal)\s*"
    r"\{(?P<args>[^\n]{0,800})\}"
)
_LOG_REDACTION_RE = re.compile(r"(?i)\b(?:redact|mask|saniti[sz]e|safeForLog|hashForLog)\w*\b")
_SENSITIVE_LOG_VALUE_RE = re.compile(
    r"(?i)\b(?:upload(?:Session)?Url|signedUrl|presignedUrl|authorization|accessToken|"
    r"refreshToken|secret|password|credential|userInfo|messageBody|emailBody|payload|body)\b"
)
_WHOLE_DTO_LOG_RE = re.compile(
    r"(?i)(?:(?:^|[,{$]\s*)\b(?:request|req|dto|command|payload)\b\s*(?:[,}]|$)|"
    r"\$(?:request|req|dto|command|payload)\b)"
)
_ARCHIVE_RE = re.compile(r"(?i)\b(?:ZipInputStream|ZipFile|ZipEntry|GZIPInputStream|Gzip)\b")
_READ_ALL_BYTES_RE = re.compile(r"\.\s*readAllBytes\s*\(")
_CONTENT_DISPOSITION_RE = re.compile(r"(?i)Content(?:-|_)Disposition")
_FILENAME_RE = re.compile(r"(?i)\b(?:(?:stored|original|final)?Filename|fileName|filnavn)\b")
_HEADER_ENCODING_RE = re.compile(
    r"(?i)(?:ContentDisposition\s*\.\s*(?:attachment|inline)|"
    r"URLEncoder|encodeHeader|sanitizeHeader|filename\s*\([^,]+,\s*(?:UTF_8|StandardCharsets))"
)
_USER_INFO_RE = re.compile(r"^(?P<indent>\s*)user-info\s*:\s*(?P<value>.*?)\s*$", re.I)
_REGISTRY_CONTEXT_RE = re.compile(
    r"(?i)(?:schema[-_. ]?registry|basic\.auth\.credentials\.source|kafka)"
)
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:[\"']?\$\{|\{\{|<|redacted\b|changeme\b|example\b|dummy\b|none\b|null\b)"
)
_MIN_PEER_MUTATIONS = 2


@dataclass(frozen=True, slots=True)
class SourceRegion:
    """A function/method range from the language parser."""

    name: str
    start: int
    end: int
    text: str
    context: str


@dataclass(frozen=True, slots=True)
class SemanticHotspot:
    """A source pattern that should become a Stream-B candidate."""

    concern: str
    vector: str
    cwe: str
    file: str
    line: int
    name: str
    heuristic: str
    evidence: str
    signal_strength: SignalStrength = "strong"
    requires_llm_validation: bool = True
    related_lines: tuple[int, ...] = ()


def _first_line(region: SourceRegion, pattern: re.Pattern[str]) -> int:
    match = pattern.search(region.text)
    if match is None:
        return region.start
    return region.start + region.text[: match.start()].count("\n")


def _line_excerpt(lines: list[str], line: int) -> str:
    if line < 1 or line > len(lines):
        return ""
    return re.sub(r"\s+", " ", lines[line - 1]).strip()[:300]


def _regions_for_file(
    text: str,
    symbols: list[tuple[str, int, int]],
) -> list[SourceRegion]:
    lines = text.splitlines()
    regions: list[SourceRegion] = []
    for name, start_raw, end_raw in symbols:
        start = max(1, start_raw)
        end = max(start, min(len(lines), end_raw))
        context_start = max(1, start - 5)
        regions.append(
            SourceRegion(
                name=name,
                start=start,
                end=end,
                text="\n".join(lines[start - 1 : end]),
                context="\n".join(lines[context_start - 1 : end]),
            )
        )
    if regions or not lines:
        return regions
    return [SourceRegion(name="<file>", start=1, end=len(lines), text=text, context=text)]


def _approval_ownership_hotspots(
    path: Path,
    lines: list[str],
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    for region in regions:
        subject = f"{region.name}\n{region.text}"
        signals = (
            _APPROVAL_RE.search(subject),
            _PRINCIPAL_RE.search(region.text),
            _REQUEST_INPUT_RE.search(region.text),
            _PERSIST_RE.search(region.text),
        )
        if not all(signals) or _OWNER_GUARD_RE.search(region.text):
            continue
        line = _first_line(region, _PRINCIPAL_RE)
        found.append(
            SemanticHotspot(
                concern="approval-reassignment-without-owner-check",
                vector="workflow/approval-ownership",
                cwe="CWE-862",
                file=path.as_posix(),
                line=line,
                name=region.name,
                heuristic=(
                    "approval workflow accepts a requested principal and persists reassignment "
                    "without a method-local ownership guard"
                ),
                evidence=_line_excerpt(lines, line),
                related_lines=(
                    _first_line(region, _REQUEST_INPUT_RE),
                    _first_line(region, _PERSIST_RE),
                ),
            )
        )
    return found


def _stale_approval_hotspots(
    path: Path,
    lines: list[str],
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    for region in regions:
        if not _HISTORICAL_APPROVAL_RE.search(region.text):
            continue
        binding_pattern = (
            _CONTENT_BINDING_RE if _CONTENT_BINDING_RE.search(region.text) else _CURRENT_APPROVAL_RE
        )
        if not binding_pattern.search(region.text) or not _VALIDATION_RE.search(region.text):
            continue
        line = _first_line(region, _HISTORICAL_APPROVAL_RE)
        found.append(
            SemanticHotspot(
                concern="historical-approval-used-for-current-validation",
                vector="workflow/stale-approval",
                cwe="CWE-863",
                file=path.as_posix(),
                line=line,
                name=region.name,
                heuristic=(
                    "historical approval presence and content binding occur in the same "
                    "validation/execution path; verify every bypass uses the current digest"
                ),
                evidence=_line_excerpt(lines, line),
                related_lines=(
                    _first_line(region, binding_pattern),
                    _first_line(region, _VALIDATION_RE),
                ),
            )
        )
    return found


def _validation_bypass_hotspots(
    path: Path,
    lines: list[str],
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    for line_no, line_text in enumerate(lines, start=1):
        if _SKIP_VALIDATION_RE.search(line_text):
            found.append(
                SemanticHotspot(
                    concern="caller-selectable-validation-bypass",
                    vector="workflow/validation-bypass",
                    cwe="CWE-693",
                    file=path.as_posix(),
                    line=line_no,
                    name="validation bypass field",
                    heuristic=(
                        "request/config surface exposes a skip/bypass for validation or rules"
                    ),
                    evidence=_line_excerpt(lines, line_no),
                )
            )
    for region in regions:
        policy_pattern = (
            _NULL_POLICY_RETURN_RE
            if _NULL_POLICY_RETURN_RE.search(region.text)
            else _NULLABLE_LOOKUP_RE
        )
        policy_source = policy_pattern.search(region.text) or _NULLABLE_POLICY_VALUE_RE.search(
            region.text
        )
        if not policy_source or not _FAIL_OPEN_RE.search(region.text):
            continue
        if not _VALIDATION_RE.search(region.text):
            continue
        line = _first_line(region, policy_pattern)
        found.append(
            SemanticHotspot(
                concern="missing-policy-specification-fails-open",
                vector="workflow/fail-open-policy-lookup",
                cwe="CWE-693",
                file=path.as_posix(),
                line=line,
                name=region.name,
                heuristic=(
                    "nullable policy/spec lookup returns without enforcing validation; "
                    "verify missing specifications fail closed"
                ),
                evidence=_line_excerpt(lines, line),
                related_lines=(
                    _first_line(region, _FAIL_OPEN_RE),
                    _first_line(region, _VALIDATION_RE),
                ),
            )
        )
    return found


def _request_derived_names(text: str) -> set[str]:
    assignment = re.compile(
        r"(?im)\b(?:val|var|final\s+\w+|\w+)\s+(?P<name>[A-Za-z_]\w*)\s*=\s*"
        r"[^\n;]*(?:request|req|input|dto|command|payload|overstyr|override)"
    )
    return {match.group("name") for match in assignment.finditer(text)}


def _identity_override_hotspots(
    path: Path,
    lines: list[str],
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    for region in regions:
        derived_names = _request_derived_names(region.text)
        for match in _IDENTITY_SWITCH_RE.finditer(region.text):
            argument = match.group("arg")
            request_direct = _REQUEST_INPUT_RE.search(argument) is not None
            derived = any(re.search(rf"\b{re.escape(name)}\b", argument) for name in derived_names)
            if not request_direct and not derived:
                continue
            line = region.start + region.text[: match.start()].count("\n")
            found.append(
                SemanticHotspot(
                    concern="request-controlled-security-context-switch",
                    vector="authn/request-controlled-identity",
                    cwe="CWE-290",
                    file=path.as_posix(),
                    line=line,
                    name=region.name,
                    heuristic=(
                        "request-derived identity reaches a user-context switch; verify "
                        "exact-client delegation and target-user authorization before switching"
                    ),
                    evidence=_line_excerpt(lines, line),
                )
            )
    return found


def _peer_guard_hotspots(
    path: Path,
    lines: list[str],
    text: str,
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    if not _ADMIN_CONTEXT_RE.search(f"{path.name}\n{text}"):
        return []
    mutations = [
        region
        for region in regions
        if _MUTATION_MAPPING_RE.search(region.context) and _PERSIST_RE.search(region.text)
    ]
    if len(mutations) < _MIN_PEER_MUTATIONS or not any(
        _GUARD_CALL_RE.search(region.text) for region in mutations
    ):
        return []
    found: list[SemanticHotspot] = []
    for region in mutations:
        if _GUARD_CALL_RE.search(region.text):
            continue
        found.append(
            SemanticHotspot(
                concern="peer-admin-mutation-omits-expected-guard",
                vector="authz/peer-guard-omission",
                cwe="CWE-862",
                file=path.as_posix(),
                line=region.start,
                name=region.name,
                heuristic=(
                    "state-changing admin peer omits the method-local guard used by sibling routes"
                ),
                evidence=_line_excerpt(lines, region.start),
            )
        )
    return found


def _jaxp_hotspots(
    path: Path,
    lines: list[str],
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    for region in regions:
        required = (
            _JAXP_FACTORY_RE.search(region.text),
            _JAXP_IDENTITY_RE.search(region.text),
            _JAXP_TRANSFORM_RE.search(region.text),
        )
        if not all(required) or _JAXP_HARDENING_RE.search(region.text):
            continue
        line = _first_line(region, _JAXP_IDENTITY_RE)
        found.append(
            SemanticHotspot(
                concern="jaxp-identity-transform-without-external-access-controls",
                vector="xml/unsafe-jaxp-identity-transform",
                cwe="CWE-611",
                file=path.as_posix(),
                line=line,
                name=region.name,
                heuristic=(
                    "JAXP identity transformer is used without external DTD/stylesheet access "
                    "controls; trace whether untrusted XML reaches the Source"
                ),
                evidence=_line_excerpt(lines, line),
                related_lines=(_first_line(region, _JAXP_TRANSFORM_RE),),
            )
        )
    return found


def _sensitive_logging_hotspots(
    path: Path,
    lines: list[str],
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    for region in regions:
        matches = [
            *_LOG_CALL_RE.finditer(region.text),
            *_LOG_LAMBDA_CALL_RE.finditer(region.text),
        ]
        for match in sorted(matches, key=lambda item: item.start()):
            args = match.group("args")
            if _LOG_REDACTION_RE.search(args):
                continue
            if not _SENSITIVE_LOG_VALUE_RE.search(args) and not _WHOLE_DTO_LOG_RE.search(args):
                continue
            line = region.start + region.text[: match.start()].count("\n")
            found.append(
                SemanticHotspot(
                    concern="sensitive-dto-or-capability-logging",
                    vector="logging/sensitive-object",
                    cwe="CWE-532",
                    file=path.as_posix(),
                    line=line,
                    name=region.name,
                    heuristic=(
                        "log call receives a whole request/DTO or a secret/capability-like value "
                        "without a visible redaction boundary"
                    ),
                    evidence=_line_excerpt(lines, line),
                )
            )
    return found


def _archive_hotspots(
    path: Path,
    lines: list[str],
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    for region in regions:
        if not _ARCHIVE_RE.search(region.text) or not _READ_ALL_BYTES_RE.search(region.text):
            continue
        line = _first_line(region, _READ_ALL_BYTES_RE)
        found.append(
            SemanticHotspot(
                concern="archive-entry-expanded-with-unbounded-read-all-bytes",
                vector="dos/unbounded-archive-expansion",
                cwe="CWE-409",
                file=path.as_posix(),
                line=line,
                name=region.name,
                heuristic=(
                    "ZIP/GZIP processing expands input with readAllBytes and no visible byte, "
                    "ratio, entry-count, or time limit"
                ),
                evidence=_line_excerpt(lines, line),
                related_lines=(_first_line(region, _ARCHIVE_RE),),
            )
        )
    return found


def _content_disposition_hotspots(
    path: Path,
    lines: list[str],
    text: str,
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    for match in _CONTENT_DISPOSITION_RE.finditer(text):
        line = text[: match.start()].count("\n") + 1
        start = max(0, line - 3)
        end = min(len(lines), line + 3)
        window = "\n".join(lines[start:end])
        dynamic = "${" in window or "+" in window or "String.format" in window
        if not dynamic or not _FILENAME_RE.search(window) or _HEADER_ENCODING_RE.search(window):
            continue
        found.append(
            SemanticHotspot(
                concern="stored-filename-written-to-content-disposition",
                vector="injection/content-disposition-filename",
                cwe="CWE-93",
                file=path.as_posix(),
                line=line,
                name="Content-Disposition",
                heuristic=(
                    "dynamic filename is interpolated into Content-Disposition without a visible "
                    "standards-compliant filename encoder"
                ),
                evidence=_line_excerpt(lines, line),
            )
        )
    return found


def _literal_user_info_hotspots(
    path: Path,
    lines: list[str],
    text: str,
) -> list[SemanticHotspot]:
    if not _REGISTRY_CONTEXT_RE.search(text):
        return []
    found: list[SemanticHotspot] = []
    for line_no, line_text in enumerate(lines, start=1):
        match = _USER_INFO_RE.match(line_text)
        if match is None:
            continue
        value = match.group("value").strip().strip("\"'")
        if not value or _PLACEHOLDER_RE.search(value):
            continue
        found.append(
            SemanticHotspot(
                concern="literal-schema-registry-user-info-credential",
                vector="secrets/yaml-user-info-literal",
                cwe="CWE-798",
                file=path.as_posix(),
                line=line_no,
                name="user-info",
                heuristic=(
                    "schema-registry user-info contains a committed non-placeholder literal; "
                    "the value is intentionally redacted"
                ),
                evidence="user-info: <redacted literal>",
                signal_strength="deterministic",
                requires_llm_validation=False,
            )
        )
    return found


def scan_source_file(
    path: Path,
    *,
    language: str,
    symbols: list[tuple[str, int, int]],
) -> list[SemanticHotspot]:
    """Return semantic hotspots for one indexed JVM/configuration source file."""
    if path.suffix.lower() not in _SUPPORTED_SUFFIXES or not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    if language.lower() == "yaml" or path.suffix.lower() in {".yaml", ".yml"}:
        return _literal_user_info_hotspots(path, lines, text)
    regions = _regions_for_file(text, symbols)
    found: list[SemanticHotspot] = []
    found.extend(_approval_ownership_hotspots(path, lines, regions))
    found.extend(_stale_approval_hotspots(path, lines, regions))
    found.extend(_validation_bypass_hotspots(path, lines, regions))
    found.extend(_identity_override_hotspots(path, lines, regions))
    found.extend(_peer_guard_hotspots(path, lines, text, regions))
    found.extend(_jaxp_hotspots(path, lines, regions))
    found.extend(_sensitive_logging_hotspots(path, lines, regions))
    found.extend(_archive_hotspots(path, lines, regions))
    found.extend(_content_disposition_hotspots(path, lines, text))
    return found


def discover_semantic_hotspots(conn: duckdb.DuckDBPyConnection) -> list[SemanticHotspot]:
    """Scan source paths already recorded in the project index."""
    symbols_by_file: dict[str, list[tuple[str, int, int]]] = defaultdict(list)
    symbol_rows = conn.execute(
        """
        SELECT file, display_name, range_start, range_end
        FROM symbols
        WHERE kind IN ('function', 'method')
        ORDER BY file, range_start
        """
    ).fetchall()
    for file, name, start, end in symbol_rows:
        symbols_by_file[str(file)].append((str(name or "<anonymous>"), int(start), int(end)))

    found: list[SemanticHotspot] = []
    file_rows = conn.execute("SELECT path, lang FROM files ORDER BY path").fetchall()
    for raw_path, language in file_rows:
        path = Path(str(raw_path))
        found.extend(
            scan_source_file(
                path,
                language=str(language or ""),
                symbols=symbols_by_file.get(path.as_posix(), []),
            )
        )

    unique: dict[tuple[str, int, str], SemanticHotspot] = {}
    for hotspot in found:
        unique[(hotspot.file, hotspot.line, hotspot.vector)] = hotspot
    return sorted(unique.values(), key=lambda item: (item.file, item.line, item.vector))

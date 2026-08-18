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

from ai_codescan.source_paths import SourcePathError, resolve_contained_file

SignalStrength = Literal["contextual", "strong", "deterministic"]

_SUPPORTED_SUFFIXES = {".java", ".kt", ".kts", ".yaml", ".yml"}
_APPROVAL_RE = re.compile(
    r"(?i)\b(?:approv\w*|review\w*|verif\w*|sign[-_ ]?off\w*|attest\w*|godkjenn\w*)\b"
)
_PRINCIPAL_RE = re.compile(
    r"(?i)\b(?:approver|reviewer|verifier|signatory|delegate|assignee|responsible|owner|"
    r"godkjenner|ansvarlig|saksbehandler)\w*\b"
)
_REQUEST_INPUT_RE = re.compile(
    r"(?i)\b(?:request|req|input|dto|command|options|params|form|body|kommando|"
    r"forespoersel|forespørsel|payload)\w*\b"
)
_OWNER_TERM = r"(?:owner|responsible|assigned|member|tenant|ansvarlig|saksbehandler)\w*"
_CURRENT_IDENTITY_TERM = (
    r"(?:currentUser|authenticatedUser|caller|authContext|securityContext|principal)\w*"
)
_OWNER_GUARD_RE = re.compile(
    rf"(?is)(?:\b(?:assert|require|check|verify|validate|authoriz|enforce|ensure)\w*"
    rf"\s*\([^)]{{0,400}}{_OWNER_TERM}[^)]{{0,400}}{_CURRENT_IDENTITY_TERM}|"
    rf"\b(?:assert|require|check|verify|validate|authoriz|enforce|ensure)\w*"
    rf"\s*\([^)]{{0,400}}{_CURRENT_IDENTITY_TERM}(?:\s*\(\s*\))?"
    rf"[^)]{{0,400}}{_OWNER_TERM}|"
    rf"\b(?:assert|require|check|verify|validate|authoriz|enforce|ensure)\w*"
    rf"(?:Owner|Ownership|Responsible|Assignment|Membership|Tenant)\w*\s*\()"
)
_APPROVAL_REASSIGN_GUARD_RE = re.compile(
    r"(?i)\b(?:assert|require|check|verify|authoriz|enforce|ensure)\w*"
    r"(?:Owner|Ownership|Reassign|ApprovalAccess|ManageApproval)\w*\s*\("
)
_PERSIST_RE = re.compile(
    r"(?i)\b(?:save|update|persist|mutat|assign|replace|create|delete|remove|submit|"
    r"publish|cancel|execute|write|tildel|lagre|endre)\w*\b"
)
_HISTORICAL_APPROVAL_RE = re.compile(
    r"(?is)\b(?:any|exists|ever|previous|histor\w*|tidligere|har)\w*.{0,120}"
    r"(?:approv|godkjenn)|(?:approv|godkjenn)\w*.{0,120}"
    r"(?:any|exists|ever|previous|prior|before|histor\w*|tidligere|isNotEmpty)|"
    r"(?:ever|previously|hasBeen|was|harVaert)\w*(?:Approved|Godkjent)"
)
_CONTENT_BINDING_RE = re.compile(
    r"(?i)\b(?:hash|digest|checksum|etag|(?:content|innhold)\w*"
    r"(?:hash|digest|checksum|version|revision))\w*\b"
)
_CURRENT_APPROVAL_RE = re.compile(
    r"(?i)\b(?:isCurrentlyApproved|currentApproval|erGodkjent|"
    r"(?:current|gjeldende)\w*(?:hash|digest|approval|godkjenn))\w*\b"
)
_CURRENT_APPROVAL_GUARD_RE = re.compile(
    r"(?is)(?:\b(?:require|check|assert|verify)\w*\s*\("
    r"(?=[^)]{0,500}(?:approv\w*|godkjenn\w*))"
    r"(?=[^)]{0,500}(?:hash|digest|checksum|etag))"
    r"(?=[^)]{0,500}(?:==|\.equals\s*\(|contentEquals\s*\())[^)]*\)|"
    r"\b(?:is|has|verify|check)\w*(?:Current|Valid|Gjeldende)\w*"
    r"(?:Approval|Godkjenn)\w*\s*\([^)]*(?:hash|digest|checksum|etag)[^)]*\))"
)
_VALIDATION_RE = re.compile(
    r"(?i)\b(?:validat|valider|vurderingsreg|assessmentRule|requirement|"
    r"enforc|execute|utfoer|utfør)\w*\b"
)
_SKIP_VALIDATION_RE = re.compile(
    r"(?i)\b(?:skip|bypass|disable|ignore|omit|suppress|without|unchecked)\w*.{0,50}"
    r"(?:validat|rule|check|policy|vurderingsreg)|"
    r"\bno(?:Validation|Rule|Check|Policy)\w*\b|"
    r"(?:validat|rule|check|vurderingsreg)\w*.{0,50}"
    r"(?:skip|bypass|disable|ignore|omit|suppress|without|unchecked)|"
    r"!\s*[A-Za-z_]\w*\s*\.\s*(?:validate|enforce\w*(?:rule|policy|check))\b"
)
_FEATURE_TOGGLE_DISABLE_RE = re.compile(
    r"(?i)\b(?:"
    r"(?:[A-Za-z_]\w*)?(?:feature|toggle)\w*\s*\.\s*isDisabled\b|"
    r"[A-Za-z_]\w*\s*\.\s*isDisabled\s*\([^)]*\b(?:feature|toggle)\w*"
    r")"
)
_DECLARATION_ONLY_RE = re.compile(
    r"(?ix)^\s*(?:(?:data\s+)?class|record|interface)\b|"
    r"^\s*(?:(?:private|protected|public|internal|static|final|const)\s+)*"
    r"(?:val|var|boolean|Boolean|bool)\s+"
    r"\w*(?:skip|bypass|disable|ignore|omit|suppress|without|unchecked|"
    r"no(?:Validation|Rule|Check|Policy))\w*"
    r"\s*(?::[^;\n]+|=\s*[^;\n]+|;)\s*$|"
    r"^\s*\w*(?:skip|bypass|disable|ignore|omit|suppress|without|unchecked|"
    r"no(?:Validation|Rule|Check|Policy))\w*"
    r"\s*:\s*(?:Boolean|bool)\??\s*(?:=\s*.+)?\s*,?\s*$|"
    r"^\s*(?:boolean|Boolean|bool)\s+"
    r"\w*(?:skip|bypass|disable|ignore|omit|suppress|without|unchecked|"
    r"no(?:Validation|Rule|Check|Policy))\w*\s*,?\s*$"
)
_POLICY_PATTERN = (
    r"(?:spec(?:ification)?s?|polic(?:y|ies)|rules?|requirements?|constraints?|controls?|"
    r"definitions?|criteria|regel(?:verk|sett)?|krav)"
)
_POLICY_PATTERN_TITLE = (
    r"(?:Spec(?:ification)?s?|Policies|Policy|Rules?|Requirements?|Constraints?|Controls?|"
    r"Definitions?|Criteria|Regel(?:verk|sett)?|Krav)"
)
_POLICY_PATTERN_UPPER = r"(?:SPEC|POLICY|RULE|REQUIREMENT|CONSTRAINT|CONTROL|DEFINITION|CRITERIA)"
_POLICY_NAME = (
    rf"(?-i:(?:{_POLICY_PATTERN}|{_POLICY_PATTERN_TITLE})(?=\b|[A-Z0-9_])\w*|"
    rf"{_POLICY_PATTERN_UPPER}(?=\b|_)\w*|"
    rf"[A-Za-z_]\w*{_POLICY_PATTERN_TITLE}(?=\b|[A-Z0-9_])\w*|"
    rf"[A-Za-z_]\w*_{_POLICY_PATTERN}(?=\b|[A-Z0-9_])\w*)"
)
_NULLABLE_POLICY_ASSIGN_RE = re.compile(
    r"(?is)\b(?:val|var|final\s+[\w<>?,. ]+|[\w<>?,.]+)\s+"
    rf"(?P<name>{_POLICY_NAME})\s*=\s*"
    r"(?P<lookup>[^;\n]{0,320}(?:singleOrNull|firstOrNull|find\w*OrNull|"
    r"lookup\w*OrNull|orElse\s*\(\s*null\s*\)|\[[^\]\n]+\]|"
    r"(?:find|load|get|lookup)\w*\s*\([^)]*\)))"
)
_NULLABLE_POLICY_PARAMETER_RE = re.compile(rf"(?i)\b(?P<name>{_POLICY_NAME})\s*:\s*[^,\n]+\?")
_FAIL_OPEN_AFTER_LOOKUP_RE = re.compile(
    r"(?is)^\s*(?:\{[^{}]{0,500}\}\s*)?\?:\s*return(?:\s+emptyList\s*\(\))?"
)
_DESTRUCTURED_POLICY_LAMBDA_RE = re.compile(
    r"(?s)\b(?P<iterator>forEach(?:Indexed)?)\s*"
    r"(?:(?P<label>[A-Za-z_]\w*)@\s*)?"
    r"(?P<open>\{)\s*(?P<bindings>[^{}\n]{1,300}?)\s*->"
)
_POLICY_ENFORCEMENT_TERM = (
    r"(?:rule|require|constraint|field|felt|allow|deny|valid|approv|godkjenn|"
    r"paakrevd|tillat|krav|permission|entitle|control|policy|spec)"
)
_IDENTITY_SWITCH_RE = re.compile(
    r"(?is)\b(?:with(?:User|Identity|Principal|Subject)(?:Id)?|"
    r"runAs(?:User|Identity|Principal|Subject)?(?:Id)?|impersonate(?:User)?|"
    r"switch(?:User|Identity|Principal)|assumeIdentity|actAs(?:User)?|asPrincipal|"
    r"becomeUser|sudoAs|doAs)\s*"
    r"\((?P<arg>.{0,240}?)\)"
)
_WEB_BOUNDARY_RE = re.compile(
    r"(?i)@(?:Request|Get|Post|Put|Patch|Delete)Mapping\b|"
    r"@(?:RequestBody|RequestParam|PathVariable|QueryParam)\b"
)
_TRUSTED_IDENTITY_RE = re.compile(
    r"(?ix)^\s*(?:(?:current|authenticated|system)(?:User|Identity|Principal)(?:Id)?"
    r"(?:\(\))?(?:\.(?:id|userId|principalId))?|"
    r"(?:auth|security)(?:entication)?Context(?:\."
    r"(?:(?:current|authenticated|system)?(?:user|identity|principal)(?:Id)?|"
    r"authentication\.principal(?:\.(?:id|name))?))?|"
    r"principal(?:\.(?:id|name))?)\s*$"
)
_TARGET_IDENTITY_GUARD_RE = re.compile(
    r"(?is)\b(?:assert|require|check|verify|authoriz|enforce|ensure)\w*"
    r"(?:impersonat|delegat|runAs|actAs|switchUser)\w*\s*"
    r"\((?P<guard_arg>[^)]{0,300})\)"
)
_MUTATION_MAPPING_RE = re.compile(
    r"(?i)@(?:Post|Put|Patch|Delete)Mapping\b|"
    r"@RequestMapping\s*\([^)]*RequestMethod\.(?:POST|PUT|PATCH|DELETE)"
)
_ADMIN_CONTEXT_RE = re.compile(
    r"(?i)(?:AdminController|ManagementController|OperationsController|OpsController|"
    r"InternalController|/(?:admin|management|operations|ops|internal)\b|"
    r"\b(?:admin(?:istrat)?|management|privileged|operations)\w*)"
)
_GUARD_CALL_RE = re.compile(
    r"(?i)\b(?:(?:assert|require|check|verify|enforce|ensure)\w*"
    r"(?:Authoriz|Permission|Role|Admin|Access)\w*|authoriz\w*|"
    r"hasPermission|hasRole|isAdmin)\s*\("
)
_SECURITY_ANNOTATION_RE = re.compile(
    r"(?i)@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed|RequiresPermissions?|"
    r"RequiresRoles?|Authorize)\b"
)
_CLASS_DECL_RE = re.compile(r"\b(?:class|object)\s+\w+")
_JAXP_FACTORY_RE = re.compile(r"\bTransformerFactory\b")
_JAXP_NEW_INSTANCE = r"TransformerFactory\s*\.\s*new(?:Default)?Instance\s*\([^)]*\)"
_JAXP_TRANSFORM_RE = re.compile(r"\.\s*transform\s*\(")
_LOG_CALL_START_RE = re.compile(
    r"(?s)\b(?:log|logger|LOG|[A-Za-z_]\w*(?:Log|Logger|LOG|LOGGER))\s*\.\s*"
    r"(?i:trace|debug|info|warn|error|fatal)\s*"
    r"\("
)
_LOG_LAMBDA_CALL_RE = re.compile(
    r"(?m)\b(?:log|logger|LOG|[A-Za-z_]\w*(?:Log|Logger|LOG|LOGGER))\s*\.\s*"
    r"(?i:trace|debug|info|warn|error|fatal)\s*"
    r"\{(?P<args>[^\n]{0,800})\}"
)
_LOG_REDACTION_CALL_START_RE = re.compile(
    r"(?i)\b(?:redact|mask|obfuscat|saniti[sz]e|safeForLog|toSafeLog|hashForLog)\w*"
    r"\s*\("
)
_SENSITIVE_LOG_VALUE_RE = re.compile(
    r"(?i)\b(?:upload(?:Session)?Url|download(?:Session)?Url|signedUrl|presignedUrl|sasUrl|"
    r"magicLink|resetUrl|inviteUrl|verificationUrl|authorization|accessToken|"
    r"refreshToken|idToken|bearerToken|sessionToken|apiKey|clientSecret|privateKey|cookie|"
    r"secret|password|credential|userInfo|messageBody|emailBody|payload|body)\b"
)
_WHOLE_DTO_LOG_RE = re.compile(
    r"(?i)(?:(?:^|[,{$]\s*)\b(?:request|req|dto|command|payload)\b\s*(?:[,}]|$)|"
    r"\$(?:request|req|dto|command|payload)\b)"
)
_ARCHIVE_STREAM = (
    r"(?:ZipInputStream|ZipFile|GZIPInputStream|(?:Zip|Tar)ArchiveInputStream|"
    r"(?:BZip2|XZ)CompressorInputStream)"
)
_ARCHIVE_RE = re.compile(rf"(?i)\b(?:{_ARCHIVE_STREAM}|ZipEntry|Gzip)\b")
_ARCHIVE_VAR_RE = re.compile(
    r"(?is)(?:\b(?:val|var)\s+(?P<kotlin>[A-Za-z_]\w*)"
    rf"(?:\s*:\s*{_ARCHIVE_STREAM})?\s*=\s*(?:new\s+)?{_ARCHIVE_STREAM}\b|"
    rf"\b(?:final\s+)?{_ARCHIVE_STREAM}\s+"
    r"(?P<java>[A-Za-z_]\w*)\s*=)"
)
_UNBOUNDED_READ_RECEIVER_RE = re.compile(
    r"(?i)\b(?P<receiver>[A-Za-z_]\w*)\s*\.\s*(?:readAllBytes|readBytes|copyTo|"
    r"transferTo)\s*\("
)
_DIRECT_ARCHIVE_READ_RE = re.compile(
    rf"(?is){_ARCHIVE_STREAM}\s*"
    r"\((?:[^()]|\([^()]{0,300}\)){0,400}\)\s*\.\s*"
    r"(?:readAllBytes|readBytes|copyTo|transferTo)\s*\("
)
_ZIP_ENTRY_READ_RE = re.compile(
    r"(?is)\b(?P<receiver>[A-Za-z_]\w*)\s*\.\s*getInputStream\s*\([^)]*\)\s*"
    r"\.\s*(?:readAllBytes|readBytes|copyTo|transferTo)\s*\("
)
_IOUTILS_ARCHIVE_READ_RE = re.compile(
    r"(?is)\bIOUtils\s*\.\s*toByteArray\s*\(\s*(?P<receiver>[A-Za-z_]\w*)\s*\)"
)
_CONTENT_DISPOSITION_HEADER_RE = re.compile(
    r"(?is)\b(?:header|addHeader|setHeader|add|set)\s*\(\s*"
    r"(?:[\"']Content(?:-|_)Disposition[\"']|HttpHeaders\.CONTENT_DISPOSITION)\s*,\s*"
)
_FILENAME_PATTERN = (
    r"(?:(?:stored|original|final)?fileName|filename|originalName|storedName|downloadName|"
    r"displayName|attachmentName|name|filnavn)"
)
_FILENAME_RE = re.compile(rf"(?i)\b{_FILENAME_PATTERN}\b")
_DYNAMIC_FILENAME_RE = re.compile(
    rf"(?is)(?:\$\{{[^}}]{{0,200}}\b{_FILENAME_PATTERN}\b[^}}]*\}}|"
    rf"\b{_FILENAME_PATTERN}\b[^\n;]{{0,200}}\+|"
    rf"\+[^\n;]{{0,200}}\b{_FILENAME_PATTERN}\b|"
    r"(?:String\.)?(?:format|formatted)\s*\([^)]{0,500}"
    rf"\b{_FILENAME_PATTERN}\b)"
)
_HEADER_ENCODING_RE = re.compile(
    r"(?is)(?:ContentDisposition\s*\.\s*(?:attachment|inline|builder)\s*\([^)]*\)"
    r".{0,500}?\.\s*filename\s*\(|encodeHeader|sanitizeHeader|"
    r"filename\s*\([^,]+,\s*(?:UTF_8|StandardCharsets))"
)
_RAW_FILENAME_VALUE_RE = re.compile(rf"(?is)^\s*(?:[A-Za-z_]\w*\.)*{_FILENAME_PATTERN}\s*$")
_USER_INFO_RE = re.compile(
    r"^(?P<indent>\s*)(?P<quote>[\"']?)(?P<key>(?:user[-_.]?info|"
    r"basic[-_.]?auth[-_.]?user[-_.]?info|"
    r"[A-Za-z0-9_.-]*schema[-_.]?registry[A-Za-z0-9_.-]*"
    r"basic[-_.]?auth[-_.]?user[-_.]?info))(?P=quote)\s*:\s*"
    r"(?P<value>.*?)\s*$",
    re.I,
)
_PLACEHOLDER_RE = re.compile(
    r"(?ix)^(?:\$\{[A-Za-z_][\w.-]*(?::[-?]?)?\}|\{\{[^}]+\}\}|\*\w+|"
    r"!vault\b.*|ENC\s*\([^)]*\)|env\s*\([^)]*\)|<[^>]+>|redacted\b.*|"
    r"changeme|example|dummy|none|null)$"
)
_YAML_CONTAINER_RE = re.compile(
    r"^(?P<indent>\s*)(?P<quote>[\"']?)(?P<key>[A-Za-z0-9_.-]+)"
    r"(?P=quote)\s*:\s*(?:#.*)?$"
)
_YAML_BLOCK_SCALAR_RE = re.compile(r"^[|>](?:[1-9][+-]?|[+-][1-9]?)?$")
_MIN_PEER_MUTATIONS = 2
_MIN_QUOTED_SCALAR_LENGTH = 2


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
    redacted_lines: tuple[int, ...] = ()


def _first_line(
    region: SourceRegion,
    pattern: re.Pattern[str],
    *,
    text: str | None = None,
) -> int:
    searched = region.text if text is None else text
    match = pattern.search(searched)
    if match is None:
        return region.start
    return region.start + searched[: match.start()].count("\n")


def _first_body_line(
    region: SourceRegion,
    pattern: re.Pattern[str],
    *,
    text: str,
) -> int:
    body_start = text.find("{")
    if body_start < 0:
        return _first_line(region, pattern, text=text)
    body = text[body_start + 1 :]
    match = pattern.search(body)
    if match is None:
        return _first_line(region, pattern, text=text)
    offset = body_start + 1 + match.start()
    return region.start + text[:offset].count("\n")


def _principal_parameter_present(region: SourceRegion) -> bool:
    header = region.text.partition("{")[0]
    opening = header.find("(")
    closing = header.rfind(")")
    if opening < 0 or closing <= opening:
        return False
    return _PRINCIPAL_RE.search(header[opening + 1 : closing]) is not None


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
        code = _code_without_literals(region.text)
        subject = f"{region.name}\n{code}"
        signals = (
            _APPROVAL_RE.search(subject),
            _PRINCIPAL_RE.search(code),
            _REQUEST_INPUT_RE.search(code) or _principal_parameter_present(region),
            _PERSIST_RE.search(code),
        )
        has_guard = _OWNER_GUARD_RE.search(code) or _APPROVAL_REASSIGN_GUARD_RE.search(code)
        if not all(signals) or has_guard:
            continue
        line = _first_body_line(region, _PRINCIPAL_RE, text=code)
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
                    _first_line(region, _REQUEST_INPUT_RE, text=code),
                    _first_line(region, _PERSIST_RE, text=code),
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
        code = _code_without_literals(region.text)
        if not _HISTORICAL_APPROVAL_RE.search(code):
            continue
        if _CURRENT_APPROVAL_GUARD_RE.search(code):
            continue
        binding_pattern = (
            _CONTENT_BINDING_RE if _CONTENT_BINDING_RE.search(code) else _CURRENT_APPROVAL_RE
        )
        if not binding_pattern.search(code) or not _VALIDATION_RE.search(code):
            continue
        line = _first_line(region, _HISTORICAL_APPROVAL_RE, text=code)
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
                    _first_line(region, binding_pattern, text=code),
                    _first_line(region, _VALIDATION_RE, text=code),
                ),
            )
        )
    return found


def _smallest_regions_by_line(
    regions: list[SourceRegion],
    line_count: int,
) -> list[SourceRegion | None]:
    by_line: list[SourceRegion | None] = [None] * (line_count + 1)
    largest_first = sorted(regions, key=lambda region: region.end - region.start, reverse=True)
    for region in largest_first:
        start = max(1, region.start)
        end = min(line_count, region.end)
        for line in range(start, end + 1):
            by_line[line] = region
    return by_line


def _code_without_literals(text: str) -> str:
    without_multiline = re.sub(
        r'(?s)/\*.*?(?:\*/|\Z)|""".*?(?:"""|\Z)',
        lambda match: re.sub(r"[^\n]", " ", match.group(0)),
        text,
    )
    code_lines: list[str] = []
    for line in without_multiline.splitlines():
        without_strings = re.sub(
            r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
            " ",
            line,
        )
        code_lines.append(without_strings.partition("//")[0])
    return "\n".join(code_lines)


def _balanced_brace_end(text: str, opening: int, *, max_chars: int = 30_000) -> int | None:
    depth = 0
    end = min(len(text), opening + max_chars)
    for index in range(opening, end):
        character = text[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _untyped_policy_bindings(bindings: str) -> tuple[str, ...]:
    names: list[str] = []
    for group in re.finditer(r"\((?P<items>[^()\n]*)\)", bindings):
        for item in group.group("items").split(","):
            name = item.strip()
            if not re.fullmatch(r"[A-Za-z_]\w*", name):
                continue
            if re.fullmatch(_POLICY_NAME, name) and name not in names:
                names.append(name)
    return tuple(names)


def _labeled_null_skip(body: str, *, name: str, label: str) -> re.Match[str] | None:
    name_pattern = re.escape(name)
    label_pattern = re.escape(label)
    return re.search(
        rf"(?s)(?:\bif\s*\(\s*(?:{name_pattern}\s*==\s*null|"
        rf"null\s*==\s*{name_pattern})\s*\)\s*(?:\{{\s*)?"
        rf"return@{label_pattern}\b|\b{name_pattern}\s*\?:\s*"
        rf"return@{label_pattern}\b)",
        body,
    )


def _has_downstream_policy_enforcement(text: str, *, name: str) -> bool:
    name_pattern = re.escape(name)
    call = re.compile(
        rf"(?s)\b(?i:validat|valider|enforce|authoriz|check|require|approv|godkjenn)\w*"
        rf"\s*\([^)]{{0,2000}}\b{name_pattern}\b"
    )
    member = re.compile(rf"(?s)\b{name_pattern}\s*\.\s*\w*(?i:{_POLICY_ENFORCEMENT_TERM})\w*\b")
    return call.search(text) is not None or member.search(text) is not None


def _destructured_policy_fail_open_offsets(text: str) -> tuple[int, int] | None:
    for match in _DESTRUCTURED_POLICY_LAMBDA_RE.finditer(text):
        policy_names = _untyped_policy_bindings(match.group("bindings"))
        if not policy_names:
            continue
        closing = _balanced_brace_end(text, match.start("open"))
        if closing is None:
            continue
        body_start = match.end()
        body = text[body_start:closing]
        label = match.group("label") or match.group("iterator")
        for name in policy_names:
            guard = _labeled_null_skip(body, name=name, label=label)
            if guard is None:
                continue
            if not _has_downstream_policy_enforcement(body[guard.end() :], name=name):
                continue
            binding = match.group("bindings").find(name)
            return (match.start("bindings") + binding, body_start + guard.start())
    return None


def _fail_open_policy_offsets(region: SourceRegion) -> tuple[int, int] | None:
    for match in _NULLABLE_POLICY_ASSIGN_RE.finditer(region.text):
        name = match.group("name")
        tail = region.text[match.start() : match.start() + 800]
        after_lookup = region.text[match.end() : match.end() + 600]
        elvis = _FAIL_OPEN_AFTER_LOOKUP_RE.match(after_lookup)
        null_return = re.search(
            rf"(?is)if\s*\(\s*{re.escape(name)}\s*==\s*null\s*\)"
            r"\s*(?:\{\s*)?return(?:\s+emptyList\s*\(\))?",
            tail,
        )
        if elvis is not None:
            return (match.start(), match.end() + elvis.start())
        if null_return is not None:
            return (match.start(), match.start() + null_return.start())
    for match in _NULLABLE_POLICY_PARAMETER_RE.finditer(region.text):
        name = match.group("name")
        tail = region.text[match.end() : match.end() + 800]
        failure = re.search(
            rf"(?is)if\s*\(\s*{re.escape(name)}\s*==\s*null\s*\)"
            r"\s*(?:\{\s*)?return(?:\s+emptyList\s*\(\))?",
            tail,
        )
        if failure is not None:
            return (match.start(), match.end() + failure.start())
    return _destructured_policy_fail_open_offsets(region.text)


def _is_bypass_declaration_line(code_line: str) -> bool:
    if _DECLARATION_ONLY_RE.search(code_line):
        return True
    stripped = code_line.strip()
    if not stripped.endswith((")", "{")):
        return False
    opening = stripped.find("(")
    closing = stripped.rfind(")")
    if opening < 0 or closing <= opening:
        return False
    parameters = stripped[opening + 1 : closing]
    method_prefix = stripped[:opening]
    looks_like_method = "fun " in method_prefix or re.search(
        r"\b[A-Za-z_]\w*(?:<[^>]+>)?\s+[A-Za-z_]\w*\s*$",
        method_prefix,
    )
    return bool(
        looks_like_method
        and re.search(r"(?i)\b(?:Boolean|boolean|bool)\b", parameters)
        and _SKIP_VALIDATION_RE.search(parameters)
    )


def _has_validation_bypass(code_line: str) -> bool:
    without_feature_toggles = _FEATURE_TOGGLE_DISABLE_RE.sub("", code_line)
    return _SKIP_VALIDATION_RE.search(without_feature_toggles) is not None


def _validation_bypass_hotspots(
    path: Path,
    lines: list[str],
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    bypass_scopes: set[tuple[int, int]] = set()
    regions_by_line = _smallest_regions_by_line(regions, len(lines))
    code_lines = _code_without_literals("\n".join(lines)).splitlines()
    for line_no, (line_text, code_line) in enumerate(zip(lines, code_lines, strict=False), start=1):
        if not _has_validation_bypass(code_line) or _is_bypass_declaration_line(code_line):
            continue
        if line_text.lstrip().startswith(("//", "/*", "*")):
            continue
        region = regions_by_line[line_no]
        scope = (region.start, region.end) if region is not None else (line_no, line_no)
        if scope in bypass_scopes:
            continue
        bypass_scopes.add(scope)
        found.append(
            SemanticHotspot(
                concern="caller-selectable-validation-bypass",
                vector="workflow/validation-bypass",
                cwe="CWE-693",
                file=path.as_posix(),
                line=line_no,
                name=region.name if region is not None else "validation bypass control",
                heuristic=(
                    "validation/rule bypass control is consumed by executable code; verify "
                    "the caller cannot select it without privileged authorization"
                ),
                evidence=_line_excerpt(lines, line_no),
            )
        )
    for region in regions:
        code = _code_without_literals(region.text)
        code_region = SourceRegion(
            name=region.name,
            start=region.start,
            end=region.end,
            text=code,
            context=region.context,
        )
        offsets = _fail_open_policy_offsets(code_region)
        if offsets is None:
            continue
        if not _VALIDATION_RE.search(code):
            continue
        policy_offset, failure_offset = offsets
        line = region.start + code[:failure_offset].count("\n")
        related_line = region.start + code[:policy_offset].count("\n")
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
                    related_line,
                    _first_line(region, _VALIDATION_RE, text=code),
                ),
            )
        )
    return found


def _request_derived_names(text: str) -> set[str]:
    assignment = re.compile(
        r"(?im)\b(?:val|var|final\s+\w+|\w+)\s+(?P<name>[A-Za-z_]\w*)\s*=\s*"
        r"[^\n;]*(?:request|req|input|dto|command|options|params|form|body|payload|"
        r"overstyr|override)"
    )
    return {match.group("name") for match in assignment.finditer(text)}


def _argument_looks_caller_controlled(argument: str, region: SourceRegion) -> bool:
    if _REQUEST_INPUT_RE.search(argument):
        return True
    if _TRUSTED_IDENTITY_RE.search(argument):
        return False
    identifiers = re.findall(r"\b[A-Za-z_]\w*\b", argument)
    identity_argument = any(
        re.search(r"(?i)(?:user|account|identity|principal|subject|actor).*id|targetUser", name)
        for name in identifiers
    )
    return (
        identity_argument
        and _WEB_BOUNDARY_RE.search(_method_declaration_context(region)) is not None
    )


def _has_target_identity_guard(before_switch: str, argument: str) -> bool:
    compact_argument = re.sub(r"\s+", "", argument)
    if not compact_argument:
        return False
    exact_target = re.compile(rf"(?<![A-Za-z0-9_.]){re.escape(compact_argument)}(?![A-Za-z0-9_])")
    return any(
        exact_target.search(re.sub(r"\s+", "", match.group("guard_arg"))) is not None
        for match in _TARGET_IDENTITY_GUARD_RE.finditer(before_switch)
    )


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
            request_direct = _argument_looks_caller_controlled(argument, region)
            derived = any(re.search(rf"\b{re.escape(name)}\b", argument) for name in derived_names)
            if not request_direct and not derived:
                continue
            before_switch = region.text[: match.start()]
            if _has_target_identity_guard(before_switch, argument):
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


def _method_declaration_context(region: SourceRegion) -> str:
    header = region.text.partition("{")[0]
    context_lines = region.context.splitlines()
    region_lines = region.text.splitlines()
    prefix_count = max(0, len(context_lines) - len(region_lines))
    prefix = context_lines[:prefix_count]
    boundary = max((index for index, line in enumerate(prefix) if "}" in line), default=-1)
    return "\n".join(prefix[boundary + 1 :] + [header])


def _method_has_security_guard(region: SourceRegion) -> bool:
    if _GUARD_CALL_RE.search(_code_without_literals(region.text)):
        return True
    declaration = _code_without_literals(_method_declaration_context(region))
    return _SECURITY_ANNOTATION_RE.search(declaration) is not None


def _class_security_guards(lines: list[str], method_lines: list[int]) -> dict[int, bool]:
    class_lines = [index for index, line in enumerate(lines) if _CLASS_DECL_RE.search(line)]
    guards: dict[int, bool] = {}
    class_cursor = -1
    current_class = -1
    current_guard = False
    for method_line in sorted(method_lines):
        method_index = method_line - 1
        while class_cursor + 1 < len(class_lines) and class_lines[class_cursor + 1] <= method_index:
            class_cursor += 1
            current_class = class_lines[class_cursor]
            header_start = max(0, current_class - 10)
            prefix = lines[header_start:current_class]
            boundary = max(
                (
                    index
                    for index, line in enumerate(prefix)
                    if "}" in line or _CLASS_DECL_RE.search(line)
                ),
                default=-1,
            )
            class_header = "\n".join(prefix[boundary + 1 :] + [lines[current_class]])
            current_guard = (
                _SECURITY_ANNOTATION_RE.search(_code_without_literals(class_header)) is not None
            )
        guards[method_line] = current_class >= 0 and current_guard
    return guards


def _peer_guard_hotspots(
    path: Path,
    lines: list[str],
    text: str,
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    if not _ADMIN_CONTEXT_RE.search(f"{path.name}\n{_code_without_literals(text)}"):
        return []
    mutations = [
        region
        for region in regions
        if _MUTATION_MAPPING_RE.search(_method_declaration_context(region))
    ]
    class_guards = _class_security_guards(lines, [region.start for region in mutations])
    if len(mutations) < _MIN_PEER_MUTATIONS or not any(
        _method_has_security_guard(region) or class_guards.get(region.start, False)
        for region in mutations
    ):
        return []
    found: list[SemanticHotspot] = []
    for region in mutations:
        if _method_has_security_guard(region) or class_guards.get(region.start, False):
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


def _jaxp_factory_variables(text: str) -> set[str]:
    assignment = re.compile(
        r"(?is)(?:\b(?:val|var)\s+(?P<kotlin>[A-Za-z_]\w*)"
        r"(?:\s*:\s*TransformerFactory)?\s*=\s*|"
        r"\bTransformerFactory\s+(?P<java>[A-Za-z_]\w*)\s*=\s*|"
        r"\b(?P<assigned>[A-Za-z_]\w*)\s*=\s*)"
        rf"{_JAXP_NEW_INSTANCE}"
    )
    return {
        str(match.group("kotlin") or match.group("java") or match.group("assigned"))
        for match in assignment.finditer(text)
    }


def _jaxp_factory_is_hardened(text: str, variable: str) -> bool:
    variable = re.escape(variable)
    dtd_property = r"(?:ACCESS_EXTERNAL_DTD|[\"'][^\"']*accessExternalDTD[\"'])"
    stylesheet_property = (
        r"(?:ACCESS_EXTERNAL_STYLESHEET|[\"'][^\"']*accessExternalStylesheet[\"'])"
    )
    dtd = re.search(
        rf"(?is)\b{variable}\s*\.\s*setAttribute\s*\("
        rf"[^)]*{dtd_property}\s*,\s*(?:\"\"|'')\s*\)",
        text,
    )
    stylesheet = re.search(
        rf"(?is)\b{variable}\s*\.\s*setAttribute\s*"
        rf"\([^)]*{stylesheet_property}\s*,\s*(?:\"\"|'')\s*\)",
        text,
    )
    return dtd is not None and stylesheet is not None


def _jaxp_template_factories(text: str) -> dict[str, tuple[str, int]]:
    assignment = re.compile(
        r"(?is)(?:\b(?:val|var)\s+|\bTemplates\s+)"
        r"(?P<template>[A-Za-z_]\w*)\s*=\s*"
        r"(?P<factory>[A-Za-z_]\w*)\s*\.\s*newTemplates\s*\("
    )
    return {
        match.group("template"): (match.group("factory"), match.start())
        for match in assignment.finditer(text)
    }


def _unsafe_jaxp_transformer_offsets(text: str) -> list[int]:
    factory_variables = _jaxp_factory_variables(text)
    template_factories = _jaxp_template_factories(text)
    new_transformer = re.compile(
        r"(?is)(?P<receiver>[A-Za-z_]\w*)\s*\.\s*newTransformer\s*\(\s*\)|"
        rf"{_JAXP_NEW_INSTANCE}\s*\.\s*"
        r"newTransformer\s*\(\s*\)"
    )
    offsets: list[int] = []
    for match in new_transformer.finditer(text):
        receiver = match.group("receiver")
        if receiver in template_factories:
            factory, creation_offset = template_factories[receiver]
            if factory in factory_variables and _jaxp_factory_is_hardened(
                text[:creation_offset], factory
            ):
                continue
            offsets.append(creation_offset)
            continue
        if receiver is not None and receiver not in factory_variables:
            continue
        if receiver in factory_variables and _jaxp_factory_is_hardened(
            text[: match.start()], receiver
        ):
            continue
        offsets.append(match.start())
    return sorted(set(offsets))


def _jaxp_hotspots(
    path: Path,
    lines: list[str],
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    for region in regions:
        if not _JAXP_FACTORY_RE.search(region.text) or not _JAXP_TRANSFORM_RE.search(region.text):
            continue
        for offset in _unsafe_jaxp_transformer_offsets(region.text):
            line = region.start + region.text[:offset].count("\n")
            found.append(
                SemanticHotspot(
                    concern="jaxp-identity-transform-without-external-access-controls",
                    vector="xml/unsafe-jaxp-identity-transform",
                    cwe="CWE-611",
                    file=path.as_posix(),
                    line=line,
                    name=region.name,
                    heuristic=(
                        "JAXP identity transformer is used without external DTD and stylesheet "
                        "access controls on the same factory; trace whether untrusted XML "
                        "reaches the Source"
                    ),
                    evidence=_line_excerpt(lines, line),
                    related_lines=(_first_line(region, _JAXP_TRANSFORM_RE),),
                )
            )
    return found


def _without_redacted_log_values(arguments: str) -> str:
    chunks: list[str] = []
    cursor = 0
    search_from = 0
    while match := _LOG_REDACTION_CALL_START_RE.search(arguments, search_from):
        nested_arguments = _balanced_log_arguments(arguments, match.end())
        if nested_arguments is None:
            search_from = match.end()
            continue
        closing = match.end() + len(nested_arguments)
        chunks.extend((arguments[cursor : match.start()], "<redacted>"))
        cursor = closing + 1
        search_from = cursor
    chunks.append(arguments[cursor:])
    return "".join(chunks)


def _without_static_log_text(arguments: str) -> str:
    interpolation = re.compile(r"(?<!\\)\$(?:[A-Za-z_]\w*|\{[^{}]{0,500}\})")

    def keep_interpolation(match: re.Match[str]) -> str:
        return " ".join(interpolation.findall(match.group(0)))

    return re.sub(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        keep_interpolation,
        arguments,
    )


def _advance_quoted_argument_state(
    character: str,
    *,
    quote: str,
    escaped: bool,
) -> tuple[str, bool]:
    if escaped:
        return quote, False
    if character == "\\":
        return quote, True
    if character == quote:
        return "", False
    return quote, False


def _balanced_log_arguments(text: str, start: int, *, max_chars: int = 2_000) -> str | None:
    depth = 1
    quote = ""
    escaped = False
    end = min(len(text), start + max_chars)
    for index in range(start, end):
        character = text[index]
        if quote:
            quote, escaped = _advance_quoted_argument_state(
                character,
                quote=quote,
                escaped=escaped,
            )
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return text[start:index]
    return None


def _log_calls(text: str) -> list[tuple[int, str]]:
    calls: list[tuple[int, str]] = []
    for match in _LOG_CALL_START_RE.finditer(text):
        arguments = _balanced_log_arguments(text, match.end())
        if arguments is not None:
            calls.append((match.start(), arguments))
    calls.extend(
        (match.start(), match.group("args")) for match in _LOG_LAMBDA_CALL_RE.finditer(text)
    )
    return sorted(calls)


def _sensitive_logging_hotspots(
    path: Path,
    lines: list[str],
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    for region in regions:
        for offset, args in _log_calls(region.text):
            unredacted_args = _without_redacted_log_values(args)
            data_expressions = _without_static_log_text(unredacted_args)
            if not _SENSITIVE_LOG_VALUE_RE.search(
                data_expressions
            ) and not _WHOLE_DTO_LOG_RE.search(data_expressions):
                continue
            line = region.start + region.text[:offset].count("\n")
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


def _archive_variables(text: str) -> set[str]:
    return {
        str(match.group("kotlin") or match.group("java"))
        for match in _ARCHIVE_VAR_RE.finditer(text)
    }


def _unbounded_archive_read_offsets(text: str) -> list[int]:
    archive_variables = _archive_variables(text)
    offsets = [match.start() for match in _DIRECT_ARCHIVE_READ_RE.finditer(text)]
    offsets.extend(
        match.start()
        for match in _ZIP_ENTRY_READ_RE.finditer(text)
        if match.group("receiver") in archive_variables
    )
    offsets.extend(
        match.start()
        for match in _IOUTILS_ARCHIVE_READ_RE.finditer(text)
        if match.group("receiver") in archive_variables
    )
    for match in _UNBOUNDED_READ_RECEIVER_RE.finditer(text):
        receiver = match.group("receiver")
        if receiver in archive_variables:
            offsets.append(match.start())
    return sorted(set(offsets))


def _archive_hotspots(
    path: Path,
    lines: list[str],
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    for region in regions:
        if not _ARCHIVE_RE.search(region.text):
            continue
        for offset in _unbounded_archive_read_offsets(region.text):
            line = region.start + region.text[:offset].count("\n")
            found.append(
                SemanticHotspot(
                    concern="archive-expansion-without-resource-bound",
                    vector="dos/unbounded-archive-expansion",
                    cwe="CWE-409",
                    file=path.as_posix(),
                    line=line,
                    name=region.name,
                    heuristic=(
                        "archive/compression stream is expanded with an unbounded bulk read or "
                        "copy and no visible byte, ratio, entry-count, or time limit"
                    ),
                    evidence=_line_excerpt(lines, line),
                    related_lines=(_first_line(region, _ARCHIVE_RE),),
                )
            )
    return found


def _assigned_header_value(
    text: str,
    value_expression: str,
    *,
    before: int,
) -> tuple[str, int]:
    reference = re.fullmatch(
        r"(?is)\s*(?P<name>[A-Za-z_]\w*)(?:\s*\.\s*toString\s*\(\s*\))?\s*",
        value_expression,
    )
    if reference is None:
        return (value_expression, before)
    name = re.escape(reference.group("name"))
    assignment = re.compile(
        rf"(?im)^\s*(?:(?:val|var|final)\s+|[A-Za-z_]\w*(?:<[^>]+>)?\s+)?"
        rf"{name}\s*=\s*(?P<value>[^\n]*(?:\n\s*\.[^\n]*)*)"
    )
    matches = list(assignment.finditer(text[:before]))
    if not matches:
        return (value_expression, before)
    match = matches[-1]
    return (match.group("value"), match.start("value"))


def _dynamic_content_disposition_values(text: str) -> list[tuple[int, int]]:
    dynamic_values: list[tuple[int, int]] = []
    for header in _CONTENT_DISPOSITION_HEADER_RE.finditer(text):
        value_expression = _balanced_log_arguments(text, header.end())
        if value_expression is None:
            continue
        value, value_offset = _assigned_header_value(
            text,
            value_expression,
            before=header.start(),
        )
        if _HEADER_ENCODING_RE.search(value):
            continue
        filename = _FILENAME_RE.search(value)
        if filename is None:
            continue
        if (
            _DYNAMIC_FILENAME_RE.search(value) is None
            and _RAW_FILENAME_VALUE_RE.match(value) is None
        ):
            continue
        dynamic_values.append((header.start(), value_offset + filename.start()))
    return dynamic_values


def _content_disposition_hotspots(
    path: Path,
    lines: list[str],
    regions: list[SourceRegion],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    for region in regions:
        for header_offset, filename_offset in _dynamic_content_disposition_values(region.text):
            line = region.start + region.text[:header_offset].count("\n")
            filename_line = region.start + region.text[:filename_offset].count("\n")
            found.append(
                SemanticHotspot(
                    concern="stored-filename-written-to-content-disposition",
                    vector="injection/content-disposition-filename",
                    cwe="CWE-93",
                    file=path.as_posix(),
                    line=line,
                    name="Content-Disposition",
                    heuristic=(
                        "dynamic filename is interpolated into Content-Disposition without a "
                        "visible standards-compliant filename encoder"
                    ),
                    evidence=_line_excerpt(lines, line),
                    related_lines=(filename_line,),
                )
            )
    return found


def _is_schema_registry_user_info(match: re.Match[str], parents: list[tuple[int, str]]) -> bool:
    key = match.group("key").lower().replace("_", ".").replace("-", ".")
    compact_key = re.sub(r"[^a-z0-9]", "", key)
    if "basicauthuserinfo" in compact_key and "schemaregistry" in compact_key:
        return True
    parent_path = ".".join(key for _indent, key in parents)
    compact_parent = re.sub(r"[^a-z0-9]", "", parent_path.lower())
    return "schemaregistry" in compact_parent


def _yaml_scalar_value(raw_value: str) -> str:
    value = re.split(r"\s+#", raw_value.strip(), maxsplit=1)[0].strip()
    if len(value) >= _MIN_QUOTED_SCALAR_LENGTH and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1].strip()
    return value


def _yaml_block_scalar_value(
    lines: list[str],
    *,
    key_index: int,
    key_indent: int,
) -> tuple[str, tuple[int, ...]]:
    redacted_lines = [key_index + 1]
    body: list[str] = []
    for body_index in range(key_index + 1, len(lines)):
        body_line = lines[body_index]
        if body_line.strip():
            body_indent = len(body_line) - len(body_line.lstrip(" "))
            if body_indent <= key_indent:
                break
            body.append(body_line.strip())
        redacted_lines.append(body_index + 1)
    return "\n".join(body).strip(), tuple(redacted_lines)


def _yaml_user_info_value(
    lines: list[str],
    *,
    line_index: int,
    indent: int,
    raw_value: str,
) -> tuple[str, tuple[int, ...]]:
    value = _yaml_scalar_value(raw_value)
    if _YAML_BLOCK_SCALAR_RE.fullmatch(value) is None:
        return value, (line_index + 1,)
    return _yaml_block_scalar_value(lines, key_index=line_index, key_indent=indent)


def _literal_user_info_hotspots(
    path: Path,
    lines: list[str],
) -> list[SemanticHotspot]:
    found: list[SemanticHotspot] = []
    parents: list[tuple[int, str]] = []
    for line_index, line_text in enumerate(lines):
        if not line_text.strip() or line_text.lstrip().startswith("#"):
            continue
        indent = len(line_text) - len(line_text.lstrip(" "))
        while parents and parents[-1][0] >= indent:
            parents.pop()
        match = _USER_INFO_RE.match(line_text)
        if match is not None and _is_schema_registry_user_info(match, parents):
            value, redacted_lines = _yaml_user_info_value(
                lines,
                line_index=line_index,
                indent=indent,
                raw_value=match.group("value"),
            )
            if value and not _PLACEHOLDER_RE.search(value):
                line_no = line_index + 1
                found.append(
                    SemanticHotspot(
                        concern="literal-schema-registry-user-info-credential",
                        vector="secrets/yaml-user-info-literal",
                        cwe="CWE-798",
                        file=path.as_posix(),
                        line=line_no,
                        name="user-info",
                        heuristic=(
                            "schema-registry user-info contains a committed non-placeholder "
                            "literal; the value is intentionally redacted"
                        ),
                        evidence="user-info: <redacted literal>",
                        signal_strength="deterministic",
                        requires_llm_validation=False,
                        redacted_lines=redacted_lines,
                    )
                )
        container = _YAML_CONTAINER_RE.match(line_text)
        if container is None:
            continue
        parents.append((indent, container.group("key").lower()))
    return found


def scan_source_file(
    path: Path,
    *,
    language: str,
    symbols: list[tuple[str, int, int]],
    source_root: Path | None = None,
) -> list[SemanticHotspot]:
    """Return semantic hotspots for one indexed JVM/configuration source file."""
    if source_root is not None:
        try:
            path = resolve_contained_file(source_root, path)
        except SourcePathError:
            return []
    if path.suffix.lower() not in _SUPPORTED_SUFFIXES or not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    if language.lower() == "yaml" or path.suffix.lower() in {".yaml", ".yml"}:
        return _literal_user_info_hotspots(path, lines)
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
    found.extend(_content_disposition_hotspots(path, lines, regions))
    return found


def discover_semantic_hotspots(
    conn: duckdb.DuckDBPyConnection,
    *,
    source_root: Path,
) -> list[SemanticHotspot]:
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
                source_root=source_root,
            )
        )

    unique: dict[tuple[str, int, str], SemanticHotspot] = {}
    for hotspot in found:
        unique[(hotspot.file, hotspot.line, hotspot.vector)] = hotspot
    return sorted(unique.values(), key=lambda item: (item.file, item.line, item.vector))

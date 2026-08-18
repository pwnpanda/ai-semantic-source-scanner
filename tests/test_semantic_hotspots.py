"""Regression coverage for Kotlin/Spring semantic miss-finder nominations."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from time import perf_counter

import duckdb
import pytest
from typer.testing import CliRunner

from ai_codescan.cli import app
from ai_codescan.config import compute_repo_id
from ai_codescan.eval import load_eval_cases, run_ai_codescan_case
from ai_codescan.index.duckdb_schema import apply_schema
from ai_codescan.miss_finder import (
    _stable_candidate_id,
    build_miss_candidates,
    write_miss_candidates,
)
from ai_codescan.prep import run_prep
from ai_codescan.semantic_hotspots import SemanticHotspot, scan_source_file

EVAL_TARGETS = Path(__file__).parents[1] / "eval-targets"
POSITIVE = EVAL_TARGETS / "kotlin-spring-semantic-hotspots"
NEGATIVE = EVAL_TARGETS / "kotlin-spring-semantic-hotspots-safe"

EXPECTED_VECTORS = {
    "workflow/approval-ownership",
    "workflow/stale-approval",
    "workflow/validation-bypass",
    "workflow/fail-open-policy-lookup",
    "authn/request-controlled-identity",
    "authz/peer-guard-omission",
    "xml/unsafe-jaxp-identity-transform",
    "logging/sensitive-object",
    "dos/unbounded-archive-expansion",
    "injection/content-disposition-filename",
    "secrets/yaml-user-info-literal",
}

runner = CliRunner()


def _has_node() -> bool:
    return shutil.which("node") is not None


def _candidates_for(target: Path, cache_root: Path) -> list[dict[str, object]]:
    _snapshot, db_path = run_prep(
        target,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    conn = duckdb.connect(str(db_path))
    try:
        return build_miss_candidates(conn)
    finally:
        conn.close()


def _scan_source(
    tmp_path: Path,
    source: str,
    *,
    symbols: list[tuple[str, int, int]] | None = None,
    filename: str = "Variant.kt",
) -> list[SemanticHotspot]:
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    line_count = len(source.splitlines())
    return scan_source_file(
        path,
        language="yaml" if path.suffix in {".yml", ".yaml"} else "kotlin",
        symbols=symbols or [("variant", 1, line_count)],
    )


def _vectors(hotspots: list[SemanticHotspot]) -> set[str]:
    return {hotspot.vector for hotspot in hotspots}


@pytest.mark.skipif(not _has_node(), reason="node runtime required for Kotlin AST extraction")
def test_kotlin_semantic_hotspots_cover_reviewed_issue_shapes(tmp_path: Path) -> None:
    candidates = _candidates_for(POSITIVE, tmp_path / "positive-cache")

    vectors = {str(candidate["vector"]) for candidate in candidates}
    assert vectors >= EXPECTED_VECTORS
    for candidate in candidates:
        if candidate["vector"] == "secrets/yaml-user-info-literal":
            assert candidate["requires_llm_validation"] is False
        elif candidate["vector"] in EXPECTED_VECTORS:
            assert candidate["requires_llm_validation"] is True

    serialized = json.dumps(candidates)
    assert "synthetic-password" not in serialized
    assert "<redacted literal>" in serialized


@pytest.mark.skipif(not _has_node(), reason="node runtime required for Kotlin AST extraction")
def test_hardened_kotlin_pair_does_not_emit_semantic_hotspots(tmp_path: Path) -> None:
    candidates = _candidates_for(NEGATIVE, tmp_path / "negative-cache")

    vectors = {str(candidate["vector"]) for candidate in candidates}
    assert EXPECTED_VECTORS.isdisjoint(vectors)


@pytest.mark.skipif(not _has_node(), reason="node runtime required for Kotlin AST extraction")
def test_semantic_hotspots_are_ranked_before_contextual_route_smells(tmp_path: Path) -> None:
    cache_root = tmp_path / "rank-cache"
    _snapshot, db_path = run_prep(
        POSITIVE,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    out_path = tmp_path / "candidates.jsonl"
    conn = duckdb.connect(str(db_path))
    try:
        written = write_miss_candidates(conn, out_path=out_path)
    finally:
        conn.close()

    scores = [float(candidate["score"]) for candidate in written]
    assert scores == sorted(scores, reverse=True)
    first_contextual = next(
        (
            index
            for index, candidate in enumerate(written)
            if candidate["signal_strength"] == "contextual"
        ),
        len(written),
    )
    assert all(
        candidate["signal_strength"] in {"strong", "deterministic"}
        for candidate in written[:first_contextual]
    )


@pytest.mark.skipif(not _has_node(), reason="node runtime required for Kotlin AST extraction")
def test_yaml_credential_is_redacted_from_evidence_bundles(tmp_path: Path) -> None:
    cache_root = tmp_path / "redaction-cache"
    _snapshot, db_path = run_prep(
        POSITIVE,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    bundles_dir = tmp_path / "bundles"
    conn = duckdb.connect(str(db_path))
    try:
        write_miss_candidates(
            conn,
            out_path=tmp_path / "candidates.jsonl",
            bundles_dir=bundles_dir,
        )
    finally:
        conn.close()

    rendered_bundles = "\n".join(path.read_text(encoding="utf-8") for path in bundles_dir.iterdir())
    assert "synthetic-password" not in rendered_bundles
    assert "user-info: <redacted>" in rendered_bundles


@pytest.mark.skipif(not _has_node(), reason="node runtime required for Kotlin AST extraction")
def test_analyze_command_stages_semantic_hotspots_in_normal_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_root = tmp_path / "workflow-cache"
    _snapshot, _db_path = run_prep(
        POSITIVE,
        cache_root=cache_root,
        engine="none",
        bug_classes=[],
        quiet=True,
    )
    repo_id = compute_repo_id(POSITIVE)
    run_dir = cache_root / repo_id / "runs" / "test-run"
    run_dir.mkdir(parents=True)
    (run_dir / "nominations.md").write_text("# Nominations\n", encoding="utf-8")
    monkeypatch.setenv("PATH", "/nonexistent")

    result = runner.invoke(
        app,
        ["--cache-dir", str(cache_root), "analyze", "--repo-id", repo_id],
    )

    assert result.exit_code == 0, result.output
    candidates_path = cache_root / repo_id / "miss_candidates.jsonl"
    candidates = [
        json.loads(line) for line in candidates_path.read_text(encoding="utf-8").splitlines()
    ]
    vectors = {str(candidate["vector"]) for candidate in candidates}
    assert vectors >= EXPECTED_VECTORS


@pytest.mark.skipif(not _has_node(), reason="node runtime required for Kotlin AST extraction")
def test_semantic_hotspot_eval_pair_passes_miss_finder_engine(tmp_path: Path) -> None:
    cases = {case.id: case for case in load_eval_cases(EVAL_TARGETS)}

    positive = run_ai_codescan_case(
        cases["kotlin-spring-semantic-hotspots"],
        cache_root=tmp_path / "eval-positive",
    )
    negative = run_ai_codescan_case(
        cases["kotlin-spring-semantic-hotspots-safe"],
        cache_root=tmp_path / "eval-negative",
    )

    assert positive.status == "pass", positive.to_jsonable()
    assert negative.status == "pass", negative.to_jsonable()


def test_candidate_ids_ignore_generated_cache_root() -> None:
    first = _stable_candidate_id(
        file="/cache/one/sample-deadbeef/source/src/source/example/Handler.kt",
        line=42,
        vector="authn/request-controlled-identity",
    )
    second = _stable_candidate_id(
        file="/different/cache/sample-deadbeef/source/src/source/example/Handler.kt",
        line=42,
        vector="authn/request-controlled-identity",
    )
    different_nested_source = _stable_candidate_id(
        file="/cache/one/sample-deadbeef/source/other/source/example/Handler.kt",
        line=42,
        vector="authn/request-controlled-identity",
    )

    assert first == second
    assert first != different_nested_source


def test_generic_workflow_and_identity_names_are_nominated(tmp_path: Path) -> None:
    approval = _scan_source(
        tmp_path,
        """fun changeReviewer(command: ReviewCommand) {
    record.reviewer = command.reviewer
    records.update(record)
}
""",
    )
    identity = _scan_source(
        tmp_path,
        """@PostMapping("/delegate")
fun delegate(@RequestBody dto: DelegationDto) {
    assumeIdentity(dto.principalId) { operation.execute() }
}
""",
    )

    assert "workflow/approval-ownership" in _vectors(approval)
    assert "authn/request-controlled-identity" in _vectors(identity)


def test_direct_reviewer_parameter_is_treated_as_caller_input(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun replaceApproval(reviewerId: String) {
    task.reviewer = reviewerId
    repository.update(task)
}
""",
    )
    matches = [item for item in hotspots if item.vector == "workflow/approval-ownership"]

    assert len(matches) == 1
    assert matches[0].line == 2


def test_owner_assignment_is_not_mistaken_for_an_ownership_guard(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun replaceReviewer(command: ReviewCommand) {
    task.owner = currentUser()
    task.reviewer = command.reviewer
    repository.update(task)
}
""",
    )

    assert "workflow/approval-ownership" in _vectors(hotspots)


def test_reversed_owner_comparison_is_a_hardened_negative(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun replaceReviewer(command: ReviewCommand) {
    require(currentUser() == task.owner)
    task.reviewer = command.reviewer
    repository.update(task)
}
""",
    )

    assert "workflow/approval-ownership" not in _vectors(hotspots)


def test_workflow_words_in_comments_and_strings_are_ignored(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun describe(request: Request) {
    // save requested approver assignment after review
    logger.info("owner approver save approval")
}
""",
    )

    assert "workflow/approval-ownership" not in _vectors(hotspots)


def test_workflow_words_in_multiline_string_are_ignored(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        '''fun render(request: Request): String {
    return """
        save requested approver assignment after review
        skip validation checks
    """.trimIndent()
}
''',
    )

    assert not _vectors(hotspots) & {
        "workflow/approval-ownership",
        "workflow/validation-bypass",
    }


def test_request_principal_is_not_mistaken_for_trusted_principal(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun delegate(request: DelegationRequest) {
    runAsUser(request.principalId) { operation.execute() }
}
""",
    )

    assert "authn/request-controlled-identity" in _vectors(hotspots)


def test_exact_authenticated_context_identity_is_a_hardened_negative(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """@PostMapping("/work")
fun execute() {
    runAsUser(authContext.currentPrincipalId) { operation.execute() }
}
""",
    )

    assert "authn/request-controlled-identity" not in _vectors(hotspots)


def test_target_bound_identity_guard_is_a_hardened_negative(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun delegate(request: DelegationRequest) {
    authorizeDelegation(request.principalId)
    runAsUser(request.principalId) { operation.execute() }
}
""",
    )

    assert "authn/request-controlled-identity" not in _vectors(hotspots)


def test_identity_guard_for_different_target_does_not_suppress_candidate(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun delegate(request: DelegationRequest) {
    authorizeDelegation(request.fallbackPrincipalId)
    runAsUser(request.principalId) { operation.execute() }
}
""",
    )

    assert "authn/request-controlled-identity" in _vectors(hotspots)


def test_identity_guard_for_target_prefix_does_not_suppress_candidate(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun delegate(request: DelegationRequest) {
    authorizeDelegation(request.principalIdHash)
    runAsUser(request.principalId) { operation.execute() }
}
""",
    )

    assert "authn/request-controlled-identity" in _vectors(hotspots)


def test_validation_bypass_declaration_does_not_duplicate_operational_use(
    tmp_path: Path,
) -> None:
    hotspots = _scan_source(
        tmp_path,
        """data class ActionOptions(val bypassPolicyChecks: Boolean)

fun execute(options: ActionOptions) {
    if (options.bypassPolicyChecks) service.executeUnchecked()
    audit.record(options.bypassPolicyChecks)
}
""",
    )
    bypasses = [item for item in hotspots if item.vector == "workflow/validation-bypass"]

    assert len(bypasses) == 1
    assert bypasses[0].line == 4


def test_no_validation_declaration_points_to_operational_use(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """data class ActionOptions(
    val noValidation: Boolean,
)

fun execute(options: ActionOptions) {
    if (options.noValidation) service.executeUnchecked()
}
""",
    )
    bypasses = [item for item in hotspots if item.vector == "workflow/validation-bypass"]

    assert len(bypasses) == 1
    assert bypasses[0].line == 6


def test_validation_bypass_words_in_log_text_are_ignored(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun explain() {
    logger.info("operators cannot skip validation checks")
}
""",
    )

    assert "workflow/validation-bypass" not in _vectors(hotspots)


def test_normal_validation_name_is_not_a_bypass_prefix(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun execute(normalValidationRules: List<Rule>) {
    service.execute(normalValidationRules)
}
""",
    )

    assert "workflow/validation-bypass" not in _vectors(hotspots)


def test_validation_bypass_points_to_operational_use_not_method_parameter(
    tmp_path: Path,
) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun execute(skipValidation: Boolean) {
    if (skipValidation) service.executeUnchecked()
}
""",
    )
    matches = [item for item in hotspots if item.vector == "workflow/validation-bypass"]

    assert len(matches) == 1
    assert matches[0].line == 2


def test_unrelated_null_return_does_not_create_fail_open_policy_candidate(
    tmp_path: Path,
) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun validateAction(action: Action, optionalNote: String?): List<String> {
    val policy = policies.firstOrNull { it.kind == action.kind }
    if (optionalNote == null) return emptyList()
    return validateRequirements(policy, action)
}
""",
    )

    assert "workflow/fail-open-policy-lookup" not in _vectors(hotspots)


def test_unrelated_elvis_return_does_not_create_fail_open_policy_candidate(
    tmp_path: Path,
) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun validateAction(action: Action, note: String?): List<String> {
    val policy = policies.firstOrNull { it.kind == action.kind }
    val requiredNote = note ?: return emptyList()
    return validateRequirements(policy, action, requiredNote)
}
""",
    )

    assert "workflow/fail-open-policy-lookup" not in _vectors(hotspots)


def test_direct_missing_policy_elvis_return_is_nominated(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun validateAction(action: Action): List<String> {
    val policy = policies.firstOrNull { it.kind == action.kind } ?: return emptyList()
    return validateRequirements(policy, action)
}
""",
    )

    assert "workflow/fail-open-policy-lookup" in _vectors(hotspots)


def test_qualified_policy_variable_name_is_nominated(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun validateAction(action: Action): List<String> {
    val selectedDefinition = definitions.findOrNull(action.type)
    if (selectedDefinition == null) return emptyList()
    return validateRequirements(selectedDefinition, action)
}
""",
    )

    assert "workflow/fail-open-policy-lookup" in _vectors(hotspots)


def test_unrelated_word_containing_spec_is_not_a_policy_lookup(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun validateReport(report: Report): List<String> {
    val inspection = inspections.firstOrNull { it.reportId == report.id }
    if (inspection == null) return emptyList()
    return validateReportState(inspection, report)
}
""",
    )

    assert "workflow/fail-open-policy-lookup" not in _vectors(hotspots)


def test_current_digest_guard_suppresses_historical_approval_hotspot(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun validateApproval(task: Task, currentDigest: String) {
    val previouslyApproved = task.approvals.any { it.accepted }
    require(task.approvals.any { it.digest == currentDigest && it.accepted })
    validateRequirements(previouslyApproved, currentDigest)
}
""",
    )

    assert "workflow/stale-approval" not in _vectors(hotspots)


def test_unrelated_approval_and_digest_guard_does_not_suppress_stale_state(
    tmp_path: Path,
) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun validateApproval(task: Task, currentDigest: String) {
    val previouslyApproved = task.approvals.any { it.accepted }
    require(approvalService.available && digestService.available)
    validateRequirements(previouslyApproved, currentDigest)
}
""",
    )

    assert "workflow/stale-approval" in _vectors(hotspots)


def test_jaxp_hardening_must_apply_to_same_factory_before_use(tmp_path: Path) -> None:
    source = """fun transform(xml: String) {
    val safeFactory = TransformerFactory.newInstance()
    safeFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
    safeFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
    val unsafeFactory = TransformerFactory.newInstance()
    val transformer = unsafeFactory.newTransformer()
    transformer.transform(StreamSource(StringReader(xml)), output)
}
"""
    hotspots = _scan_source(tmp_path, source)

    matches = [item for item in hotspots if item.vector == "xml/unsafe-jaxp-identity-transform"]
    assert len(matches) == 1
    assert matches[0].line == 6


@pytest.mark.parametrize("permissive_value", ['"all"', '"file"'])
def test_jaxp_permissive_external_access_is_not_hardening(
    tmp_path: Path,
    permissive_value: str,
) -> None:
    hotspots = _scan_source(
        tmp_path,
        f"""fun transform(xml: String) {{
    val factory = TransformerFactory.newInstance()
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, {permissive_value})
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, {permissive_value})
    val transformer = factory.newTransformer()
    transformer.transform(StreamSource(StringReader(xml)), output)
}}
""",
    )

    assert "xml/unsafe-jaxp-identity-transform" in _vectors(hotspots)


def test_jaxp_controls_applied_after_transformer_creation_are_too_late(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun transform(xml: String) {
    val factory = TransformerFactory.newInstance()
    val transformer = factory.newTransformer()
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
    transformer.transform(StreamSource(StringReader(xml)), output)
}
""",
    )

    assert "xml/unsafe-jaxp-identity-transform" in _vectors(hotspots)


def test_jaxp_new_default_instance_variant_is_nominated(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun transform(xml: String) {
    val factory = TransformerFactory.newDefaultInstance()
    val transformer = factory.newTransformer()
    transformer.transform(StreamSource(StringReader(xml)), output)
}
""",
    )

    assert "xml/unsafe-jaxp-identity-transform" in _vectors(hotspots)


def test_jaxp_literal_deny_properties_and_templates_are_hardened(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun transform(source: Source) {
    val factory = TransformerFactory.newInstance()
    factory.setAttribute(
        "http://javax.xml.XMLConstants/property/accessExternalDTD", ""
    )
    factory.setAttribute(
        "http://javax.xml.XMLConstants/property/accessExternalStylesheet", ""
    )
    val templates = factory.newTemplates(source)
    val transformer = templates.newTransformer()
    transformer.transform(source, output)
}
""",
    )

    assert "xml/unsafe-jaxp-identity-transform" not in _vectors(hotspots)


def test_jaxp_templates_from_unhardened_factory_are_nominated(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun transform(source: Source) {
    val factory = TransformerFactory.newInstance()
    val templates = factory.newTemplates(source)
    val transformer = templates.newTransformer()
    transformer.transform(source, output)
}
""",
    )
    matches = [item for item in hotspots if item.vector == "xml/unsafe-jaxp-identity-transform"]

    assert len(matches) == 1
    assert matches[0].line == 3


def test_only_unredacted_sensitive_log_values_are_nominated(tmp_path: Path) -> None:
    mixed = _scan_source(
        tmp_path,
        """fun record(clientSecret: String) {
    securityLogger.info("raw=$clientSecret masked=${redact(clientSecret)}")
}
""",
    )
    redacted = _scan_source(
        tmp_path,
        """fun record(clientSecret: String) {
    securityLogger.info("masked=${redact(clientSecret)}")
}
""",
        filename="Redacted.kt",
    )

    assert "logging/sensitive-object" in _vectors(mixed)
    assert "logging/sensitive-object" not in _vectors(redacted)


def test_nested_redaction_and_static_security_words_are_not_sensitive_logs(
    tmp_path: Path,
) -> None:
    nested_redaction = _scan_source(
        tmp_path,
        """fun record(clientSecret: String) {
    logger.info("masked=${redact(clientSecret.trim())}")
}
""",
    )
    static_message = _scan_source(
        tmp_path,
        """fun recordRotation() {
    logger.info("clientSecret rotation completed")
}
""",
        filename="StaticMessage.kt",
    )

    assert "logging/sensitive-object" not in _vectors(nested_redaction)
    assert "logging/sensitive-object" not in _vectors(static_message)


def test_unrelated_read_all_bytes_is_not_archive_expansion(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun inspect(source: InputStream) {
    val compressed = source.readAllBytes()
    val archive = ZipInputStream(ByteArrayInputStream(compressed))
    archive.close()
}
""",
    )

    assert "dos/unbounded-archive-expansion" not in _vectors(hotspots)


@pytest.mark.parametrize(
    "bulk_read",
    ["archive.readBytes()", "archive.copyTo(output)", "IOUtils.toByteArray(archive)"],
)
def test_archive_bulk_read_variants_are_nominated(tmp_path: Path, bulk_read: str) -> None:
    hotspots = _scan_source(
        tmp_path,
        f"""fun expand(input: InputStream) {{
    val archive = TarArchiveInputStream(input)
    {bulk_read}
}}
""",
    )

    assert "dos/unbounded-archive-expansion" in _vectors(hotspots)


def test_bounded_wrapper_bulk_read_is_a_hardened_negative(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun expand(input: InputStream) {
    val archive = BoundedInputStream(ZipInputStream(input), MAX_EXPANDED_BYTES)
    archive.readAllBytes()
}
""",
    )

    assert "dos/unbounded-archive-expansion" not in _vectors(hotspots)


def test_formatted_filename_in_raw_content_disposition_is_nominated(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun download(storedFileName: String): Response {
    val value = "attachment; filename=\\\"%s\\\"".formatted(storedFileName)
    return response.header("Content-Disposition", value)
}
""",
    )

    assert "injection/content-disposition-filename" in _vectors(hotspots)


def test_generic_name_in_content_disposition_is_nominated(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun download(name: String): Response {
    return response.header("Content-Disposition", "attachment; filename=\\"${name}\\"")
}
""",
    )

    assert "injection/content-disposition-filename" in _vectors(hotspots)


def test_literal_content_disposition_filename_is_a_hardened_negative(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun download(counter: Int): Response {
    metrics.record(counter + 1)
    return response.header("Content-Disposition", "attachment; filename=report.pdf")
}
""",
    )

    assert "injection/content-disposition-filename" not in _vectors(hotspots)


def test_unrelated_filename_expression_does_not_taint_constant_header(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """fun download(fileName: String): Response {
    metrics.tag("display", fileName + ".download")
    return response.header("Content-Disposition", "attachment; filename=report.pdf")
}
""",
    )

    assert "injection/content-disposition-filename" not in _vectors(hotspots)


def test_class_level_authorization_covers_privileged_peer_routes(tmp_path: Path) -> None:
    source = """@PreAuthorize("hasRole('OPS')")
@RequestMapping("/management/jobs")
class JobManagementController {
    @PostMapping("/start")
    fun start() { repository.updateJob() }

    @DeleteMapping("/{id}")
    fun delete() { repository.deleteJob() }
}
"""
    hotspots = _scan_source(tmp_path, source, symbols=[("start", 4, 5), ("delete", 7, 8)])

    assert "authz/peer-guard-omission" not in _vectors(hotspots)


def test_guard_on_previous_class_does_not_cover_next_privileged_class(tmp_path: Path) -> None:
    source = """@PreAuthorize("hasRole('OPS')")
class GuardedController {}

@RequestMapping("/ops/jobs")
class JobOpsController {
    @PostMapping("/start")
    fun start() { assertAuthorized(); repository.updateJob() }

    @DeleteMapping("/{id}")
    fun delete() { repository.deleteJob() }
}
"""
    hotspots = _scan_source(tmp_path, source, symbols=[("start", 6, 7), ("delete", 9, 10)])

    assert "authz/peer-guard-omission" in _vectors(hotspots)


def test_guard_name_in_comment_does_not_cover_privileged_peer_route(tmp_path: Path) -> None:
    source = """@RequestMapping("/ops/jobs")
class JobOpsController {
    @PostMapping("/start")
    fun start() { assertAuthorized(); repository.updateJob() }

    @DeleteMapping("/{id}")
    fun delete() {
        // authorizeAccess() is intentionally absent pending migration
        repository.deleteJob()
    }
}
"""
    hotspots = _scan_source(tmp_path, source, symbols=[("start", 3, 4), ("delete", 6, 10)])

    assert "authz/peer-guard-omission" in _vectors(hotspots)


def test_large_kotlin_controller_scan_stays_bounded(tmp_path: Path) -> None:
    method_count = 8_000
    parts = ['@RequestMapping("/operations/jobs")', "class GeneratedOperationsController {"]
    symbols: list[tuple[str, int, int]] = []
    line = 3
    for index in range(method_count):
        guard = "assertAuthorized(); " if index == 0 else ""
        parts.extend(
            (
                f'    @PostMapping("/{index}")',
                f"    fun mutate{index}() {{ {guard}repository.updateJob() }}",
            )
        )
        symbols.append((f"mutate{index}", line, line + 1))
        line += 2
    parts.append("}")

    started = perf_counter()
    hotspots = _scan_source(tmp_path, "\n".join(parts), symbols=symbols)
    elapsed = perf_counter() - started
    peer_omissions = [item for item in hotspots if item.vector == "authz/peer-guard-omission"]

    assert len(peer_omissions) == method_count - 1
    assert elapsed < 5.0


def test_schema_registry_scope_is_required_for_user_info_secret(tmp_path: Path) -> None:
    unrelated = _scan_source(
        tmp_path,
        """kafka:
  bootstrap-servers: localhost
profile:
  user-info: alice:display-name
""",
        filename="unrelated.yml",
    )
    literal = _scan_source(
        tmp_path,
        "spring.kafka.properties.schema.registry.basic.auth.user.info: user:password\n",
        filename="literal.yml",
    )
    encrypted = _scan_source(
        tmp_path,
        "spring.kafka.properties.schema.registry.basic.auth.user.info: "
        "${SCHEMA_REGISTRY_AUTH} # injected by deployment\n",
        filename="encrypted.yml",
    )
    insecure_default = _scan_source(
        tmp_path,
        "spring.kafka.properties.schema.registry.basic.auth.user.info: "
        "${REGISTRY_AUTH:user:password}\n",
        filename="default.yml",
    )
    camel_case = _scan_source(
        tmp_path,
        """kafka:
  schemaRegistry:
    basicAuthUserInfo: user:password
""",
        filename="camel.yml",
    )

    assert "secrets/yaml-user-info-literal" not in _vectors(unrelated)
    assert "secrets/yaml-user-info-literal" in _vectors(literal)
    assert "secrets/yaml-user-info-literal" not in _vectors(encrypted)
    assert "secrets/yaml-user-info-literal" in _vectors(insecure_default)
    assert "secrets/yaml-user-info-literal" in _vectors(camel_case)


@pytest.mark.parametrize("indicator", ["|", ">-", "|2+", ">+2"])
def test_yaml_block_scalar_credential_marks_the_full_value_range(
    tmp_path: Path,
    indicator: str,
) -> None:
    hotspots = _scan_source(
        tmp_path,
        f"""kafka:
  schema-registry:
    user-info: {indicator}
      audit-user:audit-secret
      continued-secret
    client-id: safe
""",
        filename="block.yml",
    )

    matches = [
        hotspot for hotspot in hotspots if hotspot.vector == "secrets/yaml-user-info-literal"
    ]
    assert len(matches) == 1
    assert matches[0].redacted_lines == (3, 4, 5)


def test_yaml_block_scalar_placeholder_is_not_a_literal_credential(tmp_path: Path) -> None:
    hotspots = _scan_source(
        tmp_path,
        """kafka:
  schema-registry:
    user-info: |
      ${SCHEMA_REGISTRY_AUTH}
""",
        filename="placeholder-block.yml",
    )

    assert "secrets/yaml-user-info-literal" not in _vectors(hotspots)


def test_yaml_block_scalar_credentials_are_absent_from_all_bundles(tmp_path: Path) -> None:
    source = tmp_path / "application.yml"
    source.write_text(
        """kafka:
  schema-registry:
    "user-info": |-
      first-user:first-secret
secondary:
  schemaRegistry:
    basicAuthUserInfo: >2+
      second-user:second-secret
""",
        encoding="utf-8",
    )
    conn = duckdb.connect(str(tmp_path / "index.duckdb"))
    apply_schema(conn)
    conn.execute(
        "INSERT INTO files VALUES (?, 'sha256', 'yaml', 'project', ?)",
        [source.as_posix(), source.stat().st_size],
    )
    bundles_dir = tmp_path / "bundles"

    try:
        candidates = write_miss_candidates(
            conn,
            out_path=tmp_path / "candidates.jsonl",
            bundles_dir=bundles_dir,
        )
    finally:
        conn.close()

    secret_candidates = [
        candidate
        for candidate in candidates
        if candidate["vector"] == "secrets/yaml-user-info-literal"
    ]
    rendered = "\n".join(path.read_text(encoding="utf-8") for path in bundles_dir.iterdir())
    assert len(secret_candidates) == 2
    assert "first-user" not in rendered
    assert "first-secret" not in rendered
    assert "second-user" not in rendered
    assert "second-secret" not in rendered
    assert "<redacted>" in rendered

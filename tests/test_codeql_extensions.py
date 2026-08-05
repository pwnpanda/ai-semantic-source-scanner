"""Tests for ai_codescan.codeql_extensions — Phase 9 CodeQL pack extension."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from ai_codescan.codeql_extensions import (
    apply_proposal_to_codeql,
    promote_codeql_extension,
    render_codeql_yaml_extensions,
    staged_path_for,
)
from ai_codescan.model_proposals import ModelProposal
from ai_codescan.prep import _render_codeql_extension_packs


def _proposal(*, pid: str, cwe: str, language: str, sink: str) -> ModelProposal:
    return ModelProposal(
        proposal_id=pid,
        nomination_id="N-1",
        finding_id="F-1",
        verdict="needs-model-extension",
        cwe=cwe,
        language=language,
        framework="requests",
        bug_class="Session",
        source_pattern="",
        sink_pattern=sink,
        sanitizer_pattern="",
        vulnerable_example="",
        safe_example="",
        target_engine="codeql",
        eval_target="",
        rationale="",
        source_path="",
    )


def test_apply_proposal_creates_codeql_entry(tmp_path: Path) -> None:
    ext_path = tmp_path / "aics-codeql-extension-packs.json"
    apply_proposal_to_codeql(
        _proposal(pid="p-1", cwe="CWE-918", language="python", sink="get"),
        extension_path=ext_path,
        staged=False,
    )
    payload = json.loads(ext_path.read_text(encoding="utf-8"))
    assert payload["sinks"][0]["method_name"] == "get"
    assert payload["sinks"][0]["package"] == "requests"


def test_apply_proposal_is_idempotent(tmp_path: Path) -> None:
    ext_path = tmp_path / "ext.json"
    apply_proposal_to_codeql(
        _proposal(pid="p-1", cwe="CWE-918", language="python", sink="get"),
        extension_path=ext_path,
        staged=False,
    )
    apply_proposal_to_codeql(
        _proposal(pid="p-1", cwe="CWE-918", language="python", sink="get"),
        extension_path=ext_path,
        staged=False,
    )
    payload = json.loads(ext_path.read_text(encoding="utf-8"))
    assert len(payload["sinks"]) == 1


def test_apply_proposal_refuses_empty_sink(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="sink_pattern"):
        apply_proposal_to_codeql(
            _proposal(pid="p-empty", cwe="CWE-918", language="python", sink=""),
            extension_path=tmp_path / "ext.json",
        )


def test_apply_proposal_stages_by_default(tmp_path: Path) -> None:
    """Default ``staged=True`` writes to the staged sibling, not the promoted file."""
    ext_path = tmp_path / "aics-codeql-extension-packs.json"
    apply_proposal_to_codeql(
        _proposal(pid="p-staged", cwe="CWE-918", language="python", sink="get"),
        extension_path=ext_path,
    )
    assert not ext_path.is_file()
    assert staged_path_for(ext_path).is_file()


def test_promote_moves_staged_to_promoted(tmp_path: Path) -> None:
    ext_path = tmp_path / "aics-codeql-extension-packs.json"
    apply_proposal_to_codeql(
        _proposal(pid="p-staged", cwe="CWE-918", language="python", sink="get"),
        extension_path=ext_path,
    )
    moved = promote_codeql_extension("p-staged", extension_path=ext_path)
    assert moved is not None and moved.method_name == "get"
    promoted = json.loads(ext_path.read_text(encoding="utf-8"))
    assert promoted["sinks"][0]["proposal_id"] == "p-staged"
    staged = json.loads(staged_path_for(ext_path).read_text(encoding="utf-8"))
    assert staged["sinks"] == []


def test_promote_missing_proposal_returns_none(tmp_path: Path) -> None:
    ext_path = tmp_path / "aics-codeql-extension-packs.json"
    apply_proposal_to_codeql(
        _proposal(pid="p-keep", cwe="CWE-918", language="python", sink="get"),
        extension_path=ext_path,
    )
    assert promote_codeql_extension("p-nope", extension_path=ext_path) is None


def test_render_yaml_extensions_writes_per_language_file(tmp_path: Path) -> None:
    ext_path = tmp_path / "ext.json"
    apply_proposal_to_codeql(
        _proposal(pid="p-py", cwe="CWE-918", language="python", sink="get"),
        extension_path=ext_path,
        staged=False,
    )
    apply_proposal_to_codeql(
        _proposal(pid="p-java", cwe="CWE-89", language="java", sink="executeQuery"),
        extension_path=ext_path,
        staged=False,
    )

    out_dir = tmp_path / "codeql-extensions"
    written = render_codeql_yaml_extensions(ext_path, out_dir=out_dir)

    assert len(written) == 2
    py_yaml = yaml.safe_load((out_dir / "python" / "extension.yml").read_text(encoding="utf-8"))
    java_yaml = yaml.safe_load((out_dir / "java" / "extension.yml").read_text(encoding="utf-8"))
    assert py_yaml["extensions"][0]["addsTo"]["pack"] == "codeql/python-all"
    assert java_yaml["extensions"][0]["addsTo"]["pack"] == "codeql/java-all"
    # Row shape: [package, type, subtypes, method, signature, ext, input, predicate, kind]
    py_row = py_yaml["extensions"][0]["data"][0]
    assert py_row[0] == "requests"
    assert py_row[3] == "get"
    assert py_row[6] == "Argument[0]"
    assert py_row[7] == "sinkModel"
    # Phase 11: each language dir must also carry a codeql-pack.yml manifest;
    # without it `--model-packs <dir>` is ignored by recent CodeQL CLI versions.
    py_manifest_path = out_dir / "python" / "codeql-pack.yml"
    py_manifest = yaml.safe_load(py_manifest_path.read_text(encoding="utf-8"))
    assert py_manifest["library"] is True
    assert py_manifest["extensionTargets"] == {"codeql/python-all": "*"}
    assert py_manifest["dataExtensions"] == ["extension.yml"]


def test_render_yaml_extensions_empty_when_no_sinks(tmp_path: Path) -> None:
    """Missing extension JSON → no YAML files written."""
    assert render_codeql_yaml_extensions(tmp_path / "nope.json", out_dir=tmp_path / "out") == []


def test_prep_helper_renders_extension_packs_when_sidecar_present(tmp_path: Path) -> None:
    """Phase 11: `_render_codeql_extension_packs` in prep.py renders YAML
    extensions from the promoted JSON sidecar and returns the per-language
    dirs that `run_queries` accepts as `--model-packs`."""
    promoted = tmp_path / "aics-codeql-extension-packs.json"
    apply_proposal_to_codeql(
        _proposal(pid="p-py", cwe="CWE-918", language="python", sink="get"),
        extension_path=promoted,
        staged=False,
    )
    lang_dirs = _render_codeql_extension_packs(tmp_path)
    assert len(lang_dirs) == 1
    assert lang_dirs[0].name == "python"
    assert (lang_dirs[0] / "extension.yml").is_file()
    assert (lang_dirs[0] / "codeql-pack.yml").is_file()


def test_prep_helper_returns_empty_when_no_sidecar(tmp_path: Path) -> None:
    assert _render_codeql_extension_packs(tmp_path) == []

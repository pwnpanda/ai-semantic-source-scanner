"""Render annotated source views from the DuckDB index."""

from __future__ import annotations

from pathlib import Path

import duckdb

_LANG_FENCE_BY_SUFFIX: tuple[tuple[tuple[str, ...], str], ...] = (
    ((".ts", ".tsx"), "typescript"),
    ((".js", ".jsx", ".mjs", ".cjs"), "javascript"),
    ((".py", ".pyi"), "python"),
    ((".java",), "java"),
    ((".kt", ".kts"), "kotlin"),
    ((".go",), "go"),
    ((".rb", ".rake", ".gemspec"), "ruby"),
    ((".php", ".phtml"), "php"),
    ((".cs", ".cshtml", ".razor"), "csharp"),
    ((".sh", ".bash"), "bash"),
    ((".yml", ".yaml"), "yaml"),
    ((".html", ".htm"), "html"),
)


def _lang_fence(file: str) -> str:
    for suffixes, fence in _LANG_FENCE_BY_SUFFIX:
        if file.endswith(suffixes):
            return fence
    return ""


def _comment_marker(fence: str) -> str:
    """Return the inline-comment leader appropriate for ``fence``.

    Used so per-line annotations are emitted as legal comment syntax for
    the highlighted language. Languages with no obvious leader fall back to
    ``//`` to preserve the existing behaviour.
    """
    if fence in {"python", "ruby", "bash", "yaml"}:
        return "#"
    # PHP supports both ``//`` and ``#``; the JS-style ``//`` is universally
    # recognised by syntax highlighters and matches the rest of the C-family
    # languages, so we keep ``//`` as the default.
    return "//"


def _annotations_by_line(conn: duckdb.DuckDBPyConnection, file: str) -> dict[int, list[str]]:
    by_line: dict[int, list[str]] = {}

    for sym_id, range_start, display_name in conn.execute(
        "SELECT id, range_start, display_name FROM symbols WHERE file = ?",
        [file],
    ).fetchall():
        by_line.setdefault(range_start, []).append(f"[{sym_id}] symbol {display_name}")

    for tid, evidence in conn.execute(
        "SELECT tid, evidence_loc FROM taint_sources WHERE evidence_loc LIKE ?",
        [f"{file}:%"],
    ).fetchall():
        line = int(evidence.rsplit(":", 1)[1])
        by_line.setdefault(line, []).append(f"[{tid}] SOURCE")

    for fid, tid, _sid, cwe in conn.execute(
        """
        SELECT f.fid, f.tid, f.sid, f.cwe
        FROM flows f
        JOIN taint_sources s ON s.tid = f.tid
        WHERE s.evidence_loc LIKE ?
        """,
        [f"{file}:%"],
    ).fetchall():
        evidence = conn.execute(
            "SELECT evidence_loc FROM taint_sources WHERE tid = ?", [tid]
        ).fetchone()
        if not evidence:
            continue
        line = int(evidence[0].rsplit(":", 1)[1])
        by_line.setdefault(line, []).append(f"FLOW {fid} ({cwe})")

    return by_line


def render_file_view(conn: duckdb.DuckDBPyConnection, *, file: str) -> str:
    """Return a markdown view of ``file`` with line-anchored annotations."""
    row = conn.execute("SELECT path FROM files WHERE path = ?", [file]).fetchone()
    if not row:
        return f"No data for {file} in the index."
    fp = Path(file)
    if not fp.is_file():
        return f"No data for {file} (file missing)."
    lang = _lang_fence(file)
    text = fp.read_text(encoding="utf-8")
    annotations = _annotations_by_line(conn, file)

    marker = _comment_marker(lang)
    out = [f"# View: {fp.name}", "", f"`{file}`", "", f"```{lang}"]
    for idx, line in enumerate(text.splitlines(), 1):
        markers = annotations.get(idx)
        suffix = f"  {marker} {' | '.join(markers)}" if markers else ""
        out.append(f"{line}{suffix}")
    out.append("```")
    return "\n".join(out) + "\n"

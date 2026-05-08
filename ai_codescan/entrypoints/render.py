"""Render the ``entrypoints.md`` summary."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from ai_codescan.entrypoints.detectors import Entrypoint

_KIND_ORDER = ("http_route", "listener", "cron", "cli", "message_consumer")


def render_entrypoints_md(*, target_name: str, entrypoints: Iterable[Entrypoint]) -> str:
    eps = list(entrypoints)
    lines = [f"# Entrypoints: {target_name}", ""]
    if not eps:
        lines.append("No entrypoints detected.")
        lines.append("")
        return "\n".join(lines)
    by_kind: dict[str, list[Entrypoint]] = defaultdict(list)
    for e in eps:
        by_kind[e.kind].append(e)
    for kind in _KIND_ORDER:
        if kind not in by_kind:
            continue
        lines.append(f"## {kind}")
        lines.append("")
        for e in sorted(by_kind[kind], key=lambda x: (x.file, x.line, x.signature)):
            lines.append(f"- `{e.signature}` at `{e.file}:{e.line}`")
        lines.append("")
    return "\n".join(lines)

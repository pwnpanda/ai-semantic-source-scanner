"""LLM-assisted clone sink_pattern rewrite (Phase 7).

When `model-proposals clone --engine X` forks a Semgrep proposal into a
Joern sibling (or vice versa), the `sink_pattern` field often needs a
syntax shift:

  Semgrep: ``$CLIENT.fetch(...)`` — pattern matching shape
  Joern:   ``(?i)^(fetch)$`` — call.name regex

This module provides an optional LLM rewriter that translates the pattern
for the target engine. Like the other Phase 7 judges:

- Deterministic fallback: if no LLM provided OR the LLM fails, the
  cloned proposal keeps the source pattern as-is (the user edits before
  apply).
- A failing call returns None and the clone proceeds with the original
  pattern. Failures must NEVER block a clone operation.
"""

from __future__ import annotations

import logging
import subprocess

from ai_codescan.llm import LLMConfig, build_argv, is_available

log = logging.getLogger(__name__)

_PROMPT_TEMPLATE = """\
You translate a security-scanner sink pattern between two engines.

Source engine: {source_engine}
Target engine: {target_engine}
Language:      {language}
CWE:           {cwe}
Sink pattern:  {sink_pattern}

Output the equivalent sink pattern for the target engine. The two engines
expect different shapes:

  Semgrep: an AST-pattern string with optional metavariables ($X, $Y, ...).
           Example: $CLIENT.fetch($URL)
  Joern:   a call-name regex (Java Pattern syntax). Example: (?i)^(fetch)$

Output ONLY the translated pattern. No commentary, no markdown fences."""


def parse_rewrite_output(raw: str) -> str | None:
    """Extract the translated pattern from LLM stdout.

    The prompt asks for the bare pattern. We strip leading/trailing
    whitespace and code-fence markers. Empty / pure-whitespace output →
    None (caller keeps the original).
    """
    if not raw:
        return None
    lines = [
        line.strip()
        for line in raw.strip().splitlines()
        if line.strip() and not line.strip().startswith("```")
    ]
    if not lines:
        return None
    # If the LLM produced multiple non-empty non-fence lines, use the
    # first one — the prompt asks for a single line. Multi-line patterns
    # are rare and usually a sign the LLM included commentary.
    return lines[0]


def make_llm_rewriter(llm: LLMConfig, *, timeout_seconds: int = 30):
    """Return a callable suitable for `cli.model_proposals_clone(rewrite=...)`.

    Signature: ``(sink_pattern, source_engine, target_engine, language, cwe) -> str | None``.
    Returns the translated pattern or None on failure. Construction
    raises if the LLM provider isn't on PATH so callers fall back to
    "keep the original pattern".
    """
    if not is_available(llm.provider):
        msg = f"llm provider '{llm.provider}' is not available on PATH"
        raise RuntimeError(msg)

    def _rewrite(
        *,
        sink_pattern: str,
        source_engine: str,
        target_engine: str,
        language: str,
        cwe: str,
    ) -> str | None:
        if not sink_pattern:
            return None
        prompt = _PROMPT_TEMPLATE.format(
            source_engine=source_engine or "unknown",
            target_engine=target_engine or "unknown",
            language=language or "unknown",
            cwe=cwe or "unknown",
            sink_pattern=sink_pattern,
        )
        argv = build_argv(llm, prompt)
        try:
            result = subprocess.run(  # noqa: S603 - argv-only, no shell
                argv,  # noqa: S607
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
                text=True,
            )
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as exc:
            log.warning("clone-rewrite LLM call failed: %s", exc)
            return None
        return parse_rewrite_output(result.stdout)

    return _rewrite

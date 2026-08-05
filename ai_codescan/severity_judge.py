"""LLM-judge severity refinement (Phase 7).

The judge is an optional refinement on top of the deterministic multi-factor
severity calculation. Callers wire it into `report.derive_meta(llm_judge=...)`.
The default implementation shells out to the user's configured LLM CLI with
a narrow prompt that returns one of:

    critical | high | medium | low | informational | UNCHANGED

UNCHANGED means "keep the deterministic verdict". Any other output is
parsed defensively; on parse failure the call returns None and
`derive_meta` keeps the deterministic severity.

Design choices:

- The judge sees ONLY the finding body + CWE + base severity + score
  factors. No source code, no entrypoint context — that would be the
  validator's job. Keeping the input narrow makes the LLM call cheap
  enough to run per-finding without burning context budget.
- Re-runs are NOT cached. Each invocation pays the LLM cost. A future
  cache (proposal_id → severity) is trivial to add when cost matters.
- A judge that crashes or times out returns None, not a raised exception.
  Reports must never fail because the judge had a bad day.
"""

from __future__ import annotations

import logging
import subprocess
from typing import Any

from ai_codescan.llm import LLMConfig, build_argv, is_available

log = logging.getLogger(__name__)

_VALID_TIERS = {"critical", "high", "medium", "low", "informational"}

_PROMPT_TEMPLATE = """\
You are a security severity rater. Given a finding's CWE, vuln class,
deterministic-baseline severity, and supporting score factors, decide the
final severity tier. Output ONE token from:

  critical | high | medium | low | informational | UNCHANGED

UNCHANGED means the deterministic baseline is correct; output that when
nothing in the body changes your mind.

CWE:               {cwe}
Vuln class:        {vuln_class}
Baseline severity: {base_severity}
Score factors:     {score_factors_summary}

Finding body:
{body}

Decision (one token only):"""


def _summarise_factors(factors: list[dict[str, Any]]) -> str:
    if not factors:
        return "(none)"
    parts: list[str] = []
    for f in factors:
        name = str(f.get("name") or "?")
        value = f.get("value")
        parts.append(f"{name}={value}")
    return ", ".join(parts)


def parse_judge_output(raw: str) -> str | None:
    """Extract the tier token from the LLM's stdout.

    The prompt asks for one token; in practice LLMs often add commentary.
    We scan the output for the first valid tier name (case-insensitive)
    and return it. UNCHANGED also passes through (callers know what it
    means). Anything else → None.
    """
    if not raw:
        return None
    for token in raw.replace("\n", " ").split():
        clean = token.strip(",.;:!?\"'`*").lower()
        if clean == "unchanged":
            return None
        if clean in _VALID_TIERS:
            return clean
    return None


def make_llm_judge(llm: LLMConfig, *, timeout_seconds: int = 30):
    """Return a `SeverityJudge` that shells out to the configured LLM CLI.

    Returns a callable suitable for `report.derive_meta(llm_judge=...)`.
    If the configured provider isn't available, the returned callable
    raises immediately so the caller falls back to deterministic.
    """
    if not is_available(llm.provider):
        msg = f"llm provider '{llm.provider}' is not available on PATH"
        raise RuntimeError(msg)

    def _judge(
        *,
        cwe: str,
        vuln_class: str,
        body: str,
        base_severity: str,
        score_factors: list[dict[str, Any]],
    ) -> str | None:
        prompt = _PROMPT_TEMPLATE.format(
            cwe=cwe or "unknown",
            vuln_class=vuln_class or "unknown",
            base_severity=base_severity,
            score_factors_summary=_summarise_factors(score_factors),
            body=body[:2000],  # cap; finding bodies are usually short
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
            log.warning("severity judge LLM call failed: %s", exc)
            return None
        return parse_judge_output(result.stdout)

    return _judge

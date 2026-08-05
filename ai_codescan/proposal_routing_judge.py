"""LLM-assisted proposal routing (Phase 7).

Phase 3's `proposal_triage._PACK_MAP` is a hand-maintained `(cwe, language)`
→ Semgrep pack mapping. It's deterministic and reviewable, but misses
proposals whose shape is non-stdlib. When the deterministic map returns
None, an optional LLM judge can suggest a pack id (or recommend a custom
rule path).

Design choices mirror `severity_judge`:

- Optional callable wired into `triage_and_route(llm_route=...)`. Default
  is None — pure deterministic behaviour.
- Output is one of: `pack:<pack-name>` | `custom-rule` | `joern`.
- A failing call returns None and the deterministic fallback is used.
- The judge sees ONLY the proposal record. No source code, no scan
  context. Keeps the LLM call cheap.
"""

from __future__ import annotations

import logging
import subprocess

from ai_codescan.llm import LLMConfig, build_argv, is_available
from ai_codescan.model_proposals import ModelProposal

log = logging.getLogger(__name__)

_PROMPT_TEMPLATE = """\
You route security-scanner model proposals to the right execution engine.
Given a proposal, output ONE of:

  pack:<semgrep-pack-id>    (when a community Semgrep pack covers this)
  custom-rule               (when a per-repo Semgrep rule is the right shape)
  joern                     (when a Joern data-flow sink is the right shape)
  unknown                   (when none of the above is a clear fit)

Output exactly one token. No commentary.

Proposal:
  cwe:           {cwe}
  language:      {language}
  framework:     {framework}
  bug_class:     {bug_class}
  sink_pattern:  {sink_pattern}
  rationale:     {rationale}

Decision (one token only):"""


def parse_route_output(raw: str) -> str | None:
    """Extract a routing token from LLM stdout.

    Valid forms: ``pack:<id>``, ``custom-rule``, ``joern``. Returns the
    canonical string or None when the LLM doesn't produce a parseable
    token (caller falls back to deterministic).
    """
    if not raw:
        return None
    for token in raw.replace("\n", " ").split():
        clean = token.strip(",.;:!?\"'`*").lower()
        if clean.startswith("pack:") and len(clean) > len("pack:"):
            return clean
        if clean in {"custom-rule", "joern"}:
            return clean
        if clean == "unknown":
            return None
    return None


def make_llm_router(llm: LLMConfig, *, timeout_seconds: int = 30):
    """Return a callable suitable for `triage_and_route(llm_route=...)`.

    The callable's signature is ``(proposal: ModelProposal) -> str | None``.
    When the configured LLM provider isn't on PATH, construction raises
    so the caller falls back to deterministic-only routing.
    """
    if not is_available(llm.provider):
        msg = f"llm provider '{llm.provider}' is not available on PATH"
        raise RuntimeError(msg)

    def _route(proposal: ModelProposal) -> str | None:
        prompt = _PROMPT_TEMPLATE.format(
            cwe=proposal.cwe or "unknown",
            language=proposal.language or "unknown",
            framework=proposal.framework or "any",
            bug_class=proposal.bug_class or "unknown",
            sink_pattern=proposal.sink_pattern or "(empty)",
            rationale=(proposal.rationale or "(none)")[:500],
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
            log.warning("proposal routing LLM call failed: %s", exc)
            return None
        return parse_route_output(result.stdout)

    return _route

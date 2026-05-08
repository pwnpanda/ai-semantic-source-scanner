"""Heuristic entrypoint detection for JS/TS frameworks."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

EntrypointKind = str  # 'http_route' | 'listener' | 'cron' | 'cli' | 'message_consumer'


@dataclass(frozen=True, slots=True)
class Entrypoint:
    symbol_id: str | None
    kind: EntrypointKind
    signature: str
    file: str
    line: int


_HTTP_ROUTE = re.compile(
    r"\b(?:app|router|fastify|server|api)\.(?:get|post|put|patch|delete|options|all|use)$",
    re.IGNORECASE,
)
_LISTENER = re.compile(r"\.(?:on|once|addListener|addEventListener)$")
_CRON = re.compile(r"\b(?:cron|node-cron|node-schedule)\.(?:schedule|job)$|@Cron\(")
_CLI_ARGV = re.compile(r"\bprocess\.argv\b")
_QUEUE_CONSUMER = re.compile(
    r"\b(?:queue|worker|consumer)\.(?:process|consume|subscribe)$|"
    r"\b(?:bullmq|amqplib|kafkajs)\..*?\.(?:process|consume|subscribe)$",
    re.IGNORECASE,
)


def _classify_callee(callee: str) -> EntrypointKind | None:
    if _HTTP_ROUTE.search(callee):
        return "http_route"
    if _LISTENER.search(callee):
        return "listener"
    if _CRON.search(callee):
        return "cron"
    if _CLI_ARGV.search(callee):
        return "cli"
    if _QUEUE_CONSUMER.search(callee):
        return "message_consumer"
    return None


def detect_entrypoints(
    *,
    xrefs: Iterable[dict[str, Any]],
    symbols: Iterable[dict[str, Any]],
) -> list[Entrypoint]:
    """Return all entrypoints found across ``xrefs`` and ``symbols``."""
    del symbols  # currently unused; reserved for future symbol-level detection
    out: list[Entrypoint] = []
    for x in xrefs:
        if x.get("kind") != "call":
            continue
        callee = (x.get("calleeText") or "").strip()
        kind = _classify_callee(callee)
        if not kind:
            continue
        out.append(
            Entrypoint(
                symbol_id=x.get("callerSyntheticId"),
                kind=kind,
                signature=callee,
                file=x.get("file", ""),
                line=int(x.get("line", 0)),
            )
        )
    return out

"""Heuristic entrypoint detection across JS/TS and Python frameworks.

Entrypoints are the exposed boundaries where attacker-controlled data first
enters a process — HTTP route handlers, queue consumers, event listeners,
cron jobs, and CLI argv readers. The detector's contract is intentionally
loose: any callsite or file-path that smells like an entrypoint is emitted
with a coarse ``kind``; downstream taint analysis decides what to do with
each one.

Detection strategies, in order of cost:
  1. **Callee-text patterns** (xrefs) — cheapest, catches Express/Fastify/
     Koa/Flask/FastAPI/Django decorators.
  2. **File-path conventions** — detects framework-specific filename
     conventions (Next.js ``pages/api/*``, Remix ``loader/action`` exports,
     Django ``urls.py``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

EntrypointKind = str  # 'http_route' | 'listener' | 'cron' | 'cli' | 'message_consumer'


@dataclass(frozen=True, slots=True)
class Entrypoint:
    symbol_id: str | None
    kind: EntrypointKind
    signature: str
    file: str
    line: int


# --- JS/TS callee patterns --------------------------------------------------

# Express / Fastify / generic ``app.method`` style. Also matches the chained
# ``.route('/x').get(...)`` form because ``.get|post|...`` is the trailing call.
_HTTP_ROUTE = re.compile(
    r"\b(?:app|router|fastify|server|api|route)\."
    r"(?:get|post|put|patch|delete|options|all|use|head)$",
    re.IGNORECASE,
)
# Standalone ``app.route(...)`` and ``router.route(...)`` chain heads.
_HTTP_ROUTE_CHAIN_HEAD = re.compile(r"\b(?:app|router)\.route$", re.IGNORECASE)
# NestJS decorators (``@Controller('users')`` / ``@Get()`` / ``@Post('/x')``).
_NEST_DECORATOR = re.compile(
    r"^@?(?:Controller|Get|Post|Put|Patch|Delete|Options|All|Head)\b",
)
# Listeners (DOM, EventEmitter, etc.). Anchored on bare method to avoid
# matching ``.on`` style identifiers in other contexts.
_LISTENER = re.compile(r"\.(?:on|once|addListener|addEventListener)$")
_CRON = re.compile(r"\b(?:cron|node-cron|node-schedule)\.(?:schedule|job)$|@Cron\(")
_CLI_ARGV = re.compile(r"\bprocess\.argv\b")
_QUEUE_CONSUMER = re.compile(
    r"\b(?:queue|worker|consumer)\.(?:process|consume|subscribe)$|"
    r"\b(?:bullmq|amqplib|kafkajs)\..*?\.(?:process|consume|subscribe)$",
    re.IGNORECASE,
)

# --- Python callee patterns -------------------------------------------------

# Flask/Quart/aiohttp/Bottle: ``@app.route``, ``@app.get``, ``@bp.post``, etc.
_PY_FLASK_ROUTE = re.compile(
    r"^@?(?:app|api|bp|blueprint|router|admin|ns)\."
    r"(?:route|get|post|put|patch|delete|options|head|websocket)\b",
    re.IGNORECASE,
)
# FastAPI's ``@router.get``, ``@app.post`` (overlap with Flask is fine — same
# kind), plus ``APIRouter().get`` style.
_PY_FASTAPI_ROUTE = re.compile(
    r"^@?(?:app|router|api_router|api)\."
    r"(?:get|post|put|patch|delete|options|head|websocket)\b",
    re.IGNORECASE,
)
# Django: ``path('users/', view)`` / ``re_path('^/users/$', view)`` /
# ``url(r'^users/$', view)`` in a urls.py — match by callee, scoped to the
# urls module via _looks_like_django_urls() at the call site.
_PY_DJANGO_ROUTE = re.compile(r"\b(?:path|re_path|url)\b")
# Celery / RQ / Dramatiq task-defining decorators that *consume* messages.
_PY_QUEUE_CONSUMER = re.compile(
    r"^@?(?:celery|app|broker|rq|dramatiq)\.(?:task|actor|job)\b",
    re.IGNORECASE,
)
# argparse / sys.argv direct reads.
_PY_CLI_ARGV = re.compile(r"\bsys\.argv\b|\bargparse\.ArgumentParser\b")


def _classify_callee_js(callee: str) -> EntrypointKind | None:  # noqa: PLR0911 - one early-return per pattern is the clearest expression
    if _HTTP_ROUTE.search(callee) or _HTTP_ROUTE_CHAIN_HEAD.search(callee):
        return "http_route"
    if _NEST_DECORATOR.search(callee):
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


def _classify_callee_py(callee: str, file: str) -> EntrypointKind | None:
    if _PY_FLASK_ROUTE.search(callee) or _PY_FASTAPI_ROUTE.search(callee):
        return "http_route"
    if _looks_like_django_urls(file) and _PY_DJANGO_ROUTE.search(callee):
        return "http_route"
    if _PY_QUEUE_CONSUMER.search(callee):
        return "message_consumer"
    if _PY_CLI_ARGV.search(callee):
        return "cli"
    return None


def _looks_like_django_urls(file: str) -> bool:
    """Return True for Django-style URL config files (``.../urls.py``)."""
    return file.endswith("urls.py")


def _classify_callee(callee: str, file: str) -> EntrypointKind | None:
    """Return the entrypoint kind for a single callee-text from any language."""
    if file.endswith((".py", ".pyi")):
        return _classify_callee_py(callee, file)
    return _classify_callee_js(callee)


# --- File-path conventions --------------------------------------------------

# Next.js Pages Router: ``pages/api/*.{js,ts,tsx}`` are HTTP handlers.
_NEXT_PAGES_API = re.compile(r"(?:^|/)pages/api/.*\.(?:js|jsx|ts|tsx|mjs|cjs)$")
# Next.js App Router: ``app/<segment>/route.{js,ts}`` are HTTP handlers.
_NEXT_APP_ROUTE = re.compile(r"(?:^|/)app/.*?/route\.(?:js|ts|mjs|cjs)$")
# Remix loaders/actions live alongside route components; the marker is a
# ``loader`` or ``action`` exported symbol within ``app/routes/**``.
_REMIX_ROUTES = re.compile(r"(?:^|/)app/routes/.+\.(?:js|jsx|ts|tsx)$")


def _file_based_entrypoints(symbols: Iterable[dict[str, Any]]) -> list[Entrypoint]:
    """Detect Next.js/Remix-style routes by filename and exported symbols.

    Next.js' file-based router exposes any module under ``pages/api/`` (Pages
    Router) or any ``app/.../route.{ts,js}`` (App Router) as an HTTP handler.
    Remix exposes ``loader`` / ``action`` exports under ``app/routes/`` as
    handlers. Each matching file emits a single ``http_route`` entrypoint at
    line 1 — the precise line is unimportant since the route is determined by
    the path layout, not source position.
    """
    out: list[Entrypoint] = []
    seen_files: set[str] = set()
    remix_files_with_handler: dict[str, int] = {}
    for sym in symbols:
        file = str(sym.get("file") or "")
        if not file:
            continue
        rel = PurePosixPath(file).as_posix()
        if file not in seen_files and (_NEXT_PAGES_API.search(rel) or _NEXT_APP_ROUTE.search(rel)):
            seen_files.add(file)
            out.append(
                Entrypoint(
                    symbol_id=sym.get("syntheticId"),
                    kind="http_route",
                    signature=f"next:{PurePosixPath(rel).name}",
                    file=file,
                    line=1,
                )
            )
        if _REMIX_ROUTES.search(rel) and sym.get("name") in {"loader", "action"}:
            range_val = sym.get("range") or [1, 1]
            line = int(range_val[0]) if range_val else 1
            remix_files_with_handler.setdefault(file, line)
    for file, line in remix_files_with_handler.items():
        out.append(
            Entrypoint(
                symbol_id=None,
                kind="http_route",
                signature=f"remix:{PurePosixPath(file).name}",
                file=file,
                line=line,
            )
        )
    return out


def detect_entrypoints(
    *,
    xrefs: Iterable[dict[str, Any]],
    symbols: Iterable[dict[str, Any]],
) -> list[Entrypoint]:
    """Return all entrypoints found across ``xrefs`` and ``symbols``."""
    symbols_list = list(symbols)
    out: list[Entrypoint] = []
    seen_xref_keys: set[tuple[str, int, str]] = set()
    for x in xrefs:
        if x.get("kind") != "call":
            continue
        callee = (x.get("calleeText") or "").strip()
        file = str(x.get("file") or "")
        kind = _classify_callee(callee, file)
        if not kind:
            continue
        line = int(x.get("line", 0))
        key = (file, line, kind)
        if key in seen_xref_keys:
            continue
        seen_xref_keys.add(key)
        out.append(
            Entrypoint(
                symbol_id=x.get("callerSyntheticId"),
                kind=kind,
                signature=callee,
                file=file,
                line=line,
            )
        )
    out.extend(_file_based_entrypoints(symbols_list))
    return out

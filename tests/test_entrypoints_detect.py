"""Tests for ai_codescan.entrypoints.detectors."""

from ai_codescan.entrypoints.detectors import detect_entrypoints


def test_express_route_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/server.js",
            "line": 5,
            "calleeText": "app.get",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    kinds = [e.kind for e in eps]
    assert "http_route" in kinds


def test_fastify_route_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/x.ts",
            "line": 3,
            "calleeText": "fastify.post",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_event_listener_detected() -> None:
    xrefs = [
        {"type": "xref", "kind": "call", "file": "/abs/x.ts", "line": 9, "calleeText": "emitter.on"}
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "listener" for e in eps)


def test_cli_argv_use_detected() -> None:
    symbols = [
        {
            "type": "symbol",
            "file": "/abs/cli.js",
            "kind": "variable",
            "name": "args",
            "range": [1, 1],
            "syntheticId": "synthetic:111",
        }
    ]
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/cli.js",
            "line": 2,
            "calleeText": "process.argv.slice",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=symbols)
    assert any(e.kind == "cli" for e in eps)


def test_no_match_yields_empty() -> None:
    eps = detect_entrypoints(xrefs=[], symbols=[])
    assert eps == []

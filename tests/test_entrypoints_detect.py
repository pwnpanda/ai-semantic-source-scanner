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


# --- New JS framework patterns ---


def test_express_route_chain_head_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/server.js",
            "line": 5,
            "calleeText": "app.route",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_nestjs_controller_decorator_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/users.controller.ts",
            "line": 4,
            "calleeText": "Controller('users')",
        },
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/users.controller.ts",
            "line": 8,
            "calleeText": "Get('/:id')",
        },
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert sum(1 for e in eps if e.kind == "http_route") == 2


def test_nextjs_pages_api_file_detected() -> None:
    symbols = [
        {
            "type": "symbol",
            "file": "/repo/pages/api/users.ts",
            "kind": "function",
            "name": "default",
            "range": [1, 10],
            "syntheticId": "synthetic:abc",
        }
    ]
    eps = detect_entrypoints(xrefs=[], symbols=symbols)
    assert any(e.kind == "http_route" and "next:" in e.signature for e in eps)


def test_nextjs_app_router_route_file_detected() -> None:
    symbols = [
        {
            "type": "symbol",
            "file": "/repo/app/api/users/route.ts",
            "kind": "function",
            "name": "GET",
            "range": [1, 8],
            "syntheticId": "synthetic:def",
        }
    ]
    eps = detect_entrypoints(xrefs=[], symbols=symbols)
    assert any(e.kind == "http_route" for e in eps)


def test_remix_loader_export_detected() -> None:
    symbols = [
        {
            "type": "symbol",
            "file": "/repo/app/routes/users.tsx",
            "kind": "function",
            "name": "loader",
            "range": [3, 10],
            "syntheticId": "synthetic:rem1",
        }
    ]
    eps = detect_entrypoints(xrefs=[], symbols=symbols)
    assert any(e.kind == "http_route" and "remix:" in e.signature for e in eps)
    # Plain components in app/routes are NOT entrypoints by themselves.
    only_components = [
        {
            "type": "symbol",
            "file": "/repo/app/routes/index.tsx",
            "kind": "function",
            "name": "default",
            "range": [1, 5],
            "syntheticId": "synthetic:rem2",
        }
    ]
    assert detect_entrypoints(xrefs=[], symbols=only_components) == []


# --- Python framework patterns ---


def test_flask_route_decorator_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/app.py",
            "line": 7,
            "calleeText": "app.route('/u')",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_fastapi_router_get_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/api.py",
            "line": 12,
            "calleeText": "router.get('/items/{id}')",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_django_path_in_urls_py_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/myapp/urls.py",
            "line": 5,
            "calleeText": "path('users/', UserView.as_view())",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_django_path_outside_urls_py_skipped() -> None:
    """A bare ``path()`` call outside a urls.py is not an entrypoint."""
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/myapp/views.py",
            "line": 5,
            "calleeText": "path('users/', UserView.as_view())",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert eps == []


def test_celery_task_decorator_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/tasks.py",
            "line": 4,
            "calleeText": "celery.task",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "message_consumer" for e in eps)


def test_python_sys_argv_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/cli.py",
            "line": 2,
            "calleeText": "sys.argv[1:]",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "cli" for e in eps)

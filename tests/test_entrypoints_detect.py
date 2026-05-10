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


# --- Java framework patterns ---


def test_spring_get_mapping_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/UserController.java",
            "line": 25,
            "calleeText": '@GetMapping("/u")',
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_spring_rest_controller_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/UserController.java",
            "line": 19,
            "calleeText": "@RestController",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_jax_rs_path_get_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/UserResource.java",
            "line": 14,
            "calleeText": '@Path("/users")',
        },
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/UserResource.java",
            "line": 16,
            "calleeText": "@GET",
        },
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert sum(1 for e in eps if e.kind == "http_route") == 2


def test_kafka_listener_detected_as_message_consumer() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/Listener.java",
            "line": 11,
            "calleeText": '@KafkaListener(topics = "orders")',
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "message_consumer" for e in eps)


def test_spring_scheduled_detected_as_cron() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/Tasks.java",
            "line": 8,
            "calleeText": '@Scheduled(cron = "0 0 * * * *")',
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "cron" for e in eps)


# --- Go framework patterns ---


def test_go_http_handlefunc_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/main.go",
            "line": 10,
            "calleeText": 'http.HandleFunc("/u", handler)',
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_go_gin_get_route_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/main.go",
            "line": 25,
            "calleeText": 'r.GET("/u", func(c *gin.Context) {...})',
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_go_chi_get_route_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/main.go",
            "line": 12,
            "calleeText": 'r.Get("/api", handler)',
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_go_kafka_consume_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/worker.go",
            "line": 30,
            "calleeText": 'consumer.Consume(ctx, []string{"orders"}, &h)',
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "message_consumer" for e in eps)


def test_go_flag_parse_detected_as_cli() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/abs/cmd.go",
            "line": 7,
            "calleeText": "flag.Parse()",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "cli" for e in eps)


# --- Ruby framework patterns ---


def test_rails_routes_get_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/config/routes.rb",
            "line": 5,
            "calleeText": "get '/users', to: 'users#index'",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_rails_routes_resources_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/config/routes.rb",
            "line": 8,
            "calleeText": "resources :users",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_rails_get_outside_routes_rb_skipped() -> None:
    """A bare ``get`` call outside Rails routes.rb is not an entrypoint."""
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/app/controllers/foo.rb",
            "line": 3,
            "calleeText": "get :index",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert eps == []


def test_sinatra_route_get_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/app.rb",
            "line": 12,
            "calleeText": "get '/u' do",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_sidekiq_worker_include_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/app/workers/foo_worker.rb",
            "line": 2,
            "calleeText": "include Sidekiq::Job",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "message_consumer" for e in eps)


# --- PHP framework patterns ---


def test_laravel_route_static_call_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/routes/web.php",
            "line": 7,
            "calleeText": "Route::get('/u', [UserController::class, 'show'])",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_slim_app_get_route_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/index.php",
            "line": 20,
            "calleeText": "$app->get('/u', $callable)",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_symfony_route_attribute_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/src/Controller/Foo.php",
            "line": 14,
            "calleeText": "#[Route('/foo', methods: ['GET'])]",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_wordpress_add_action_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/wp-content/plugins/p/p.php",
            "line": 11,
            "calleeText": "add_action('wp_ajax_foo', 'my_handler')",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_wp_cli_add_command_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/cli.php",
            "line": 3,
            "calleeText": "WP_CLI::add_command('foo', 'FooCommand')",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "cli" for e in eps)


# --- C# / .NET framework patterns ---


def test_aspnet_attribute_route_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/Controllers/Foo.cs",
            "line": 14,
            "calleeText": '[Route("api/[controller]")]',
        },
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/Controllers/Foo.cs",
            "line": 17,
            "calleeText": "[HttpGet]",
        },
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert sum(1 for e in eps if e.kind == "http_route") == 2


def test_aspnet_minimal_api_mapget_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/Program.cs",
            "line": 15,
            "calleeText": 'app.MapGet("/u", (string id) => Results.Ok(id))',
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_aspnet_apicontroller_attribute_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/Controllers/Foo.cs",
            "line": 11,
            "calleeText": "[ApiController]",
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


def test_azure_function_attribute_detected() -> None:
    xrefs = [
        {
            "type": "xref",
            "kind": "call",
            "file": "/repo/MyFunctions.cs",
            "line": 9,
            "calleeText": '[Function("HttpFoo")]',
        }
    ]
    eps = detect_entrypoints(xrefs=xrefs, symbols=[])
    assert any(e.kind == "http_route" for e in eps)


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

<?php
// Tiny Slim app with a deliberate CWE-89 SQL injection.
//
// Used as a fixture for ai-codescan's PHP pipeline; the handler
// concatenates a request parameter directly into a SQL string, which
// Semgrep should flag (CodeQL does not officially support PHP).

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

$pdo = new PDO('sqlite::memory:');

$app = AppFactory::create();

$app->get('/u', function (Request $request, Response $response) use ($pdo): Response {
    $params = $request->getQueryParams();
    $userId = $params['id'] ?? '';
    // CWE-89: $userId flows unparameterised into the SQL string.
    $sql = "SELECT id, name FROM users WHERE id=" . $userId;
    $stmt = $pdo->query($sql);
    $rows = $stmt ? $stmt->fetchAll() : [];
    $response->getBody()->write(json_encode($rows));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->run();

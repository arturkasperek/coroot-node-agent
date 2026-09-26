<?php
// PHP HTTP/1.1 test service for the e2e suite (HTTP/2 skipped — the built-in
// dev server only speaks HTTP/1.1; a real HTTP/2 PHP server needs swoole or
// nginx+php-fpm, not worth it for this harness).
// Usage: php -S 0.0.0.0:<port> router.php

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if (str_starts_with($path, '/users')) {
    header('Content-Type: application/json');
    echo json_encode([
        ['id' => 1, 'name' => 'alice'],
        ['id' => 2, 'name' => 'bob'],
    ]);
    return;
}

if (str_starts_with($path, '/echo')) {
    echo file_get_contents('php://input');
    return;
}

if (str_starts_with($path, '/error')) {
    http_response_code(500);
    echo 'boom';
    return;
}

if (str_starts_with($path, '/healthz')) {
    http_response_code(200);
    return;
}

http_response_code(404);

// Node.js HTTP/1.1-only test service for the e2e suite, dedicated to
// exercising keep-alive: unlike e2e/services/node's server (which loadgen
// always hits with a fresh connection per request, since that's where an
// earlier eBPF capture bug lived — see e2e/loadgen's h1 vs h1-keepalive
// clients), this service's whole point is being hit repeatedly over ONE
// reused connection, rotating across routes whose response bodies span a
// wide size range (a few bytes up to well past both HTTP1_CAPTURE_MAX and
// MAX_PAYLOAD_SIZE in ebpftracer/ebpf/l7/http1.c, forcing multiple
// http1_flush ring-buffer emissions per response).
// Usage: server.js <port>
'use strict';
const http = require('http');

const port = parseInt(process.argv[2] || '8081', 10);

// Deliberately varied sizes: tiny (well under any framing boundary),
// small/medium (typical API responses), large (crosses the 4096-byte
// HTTP1_CAPTURE_MAX), huge (crosses MAX_PAYLOAD_SIZE, needs several
// ring-buffer slots to capture even a truncated prefix).
const ROUTE_SIZES = {
  '/r/tiny': 8,
  '/r/small': 200,
  '/r/medium': 2000,
  '/r/large': 8000,
  '/r/huge': 100000,
};

function body(n) {
  // JSON so it's a realistic response shape, not just padding.
  const pad = 'x'.repeat(Math.max(0, n - 20));
  return `{"pad":"${pad}"}`;
}

function route(req, res) {
  const url = req.url || '';
  if (url.startsWith('/healthz')) {
    res.writeHead(200);
    res.end();
    return;
  }
  const size = ROUTE_SIZES[url];
  if (size !== undefined) {
    const b = body(size);
    res.writeHead(200, {'content-type': 'application/json', 'content-length': Buffer.byteLength(b)});
    res.end(b);
    return;
  }
  res.writeHead(404);
  res.end();
}

const server = http.createServer(route);
// Keep-alive is Node's default for HTTP/1.1 clients, but pin the server's
// own keepAliveTimeout generously high too — the whole scenario is
// pointless if the server itself decides to close the connection between
// requests.
server.keepAliveTimeout = 60000;
server.listen(port, () => console.log(`node-keepalive-service: http/1.1 on :${port}`));

// Node.js HTTP/1.1 + h2c + HTTPS test service for the e2e suite.
// Usage: node server.js <http1-port> <h2c-port> [https-port]
'use strict';
const fs = require('fs');
const http = require('http');
const https = require('https');
const http2 = require('http2');

const port1 = parseInt(process.argv[2] || '8081', 10);
const port2 = parseInt(process.argv[3] || '8082', 10);
const port3 = process.argv[4] ? parseInt(process.argv[4], 10) : null;

function route(req, res) {
  const url = req.url || '';
  if (url.startsWith('/users')) {
    res.writeHead(200, {'content-type': 'application/json'});
    res.end(JSON.stringify([{id: 1, name: 'alice'}, {id: 2, name: 'bob'}]));
    return;
  }
  if (url.startsWith('/echo')) {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      res.writeHead(200, {'content-type': 'application/octet-stream'});
      res.end(Buffer.concat(chunks));
    });
    return;
  }
  if (url.startsWith('/error')) {
    res.writeHead(500, {'content-type': 'text/plain'});
    res.end('boom');
    return;
  }
  if (url.startsWith('/healthz')) {
    res.writeHead(200);
    res.end();
    return;
  }
  res.writeHead(404);
  res.end();
}

const server1 = http.createServer(route);
server1.listen(port1, () => console.log(`node-service: http/1.1 on :${port1}`));

const server2 = http2.createServer((req, res) => route(req, res));
server2.listen(port2, () => console.log(`node-service: h2c on :${port2}`));

if (port3) {
  // Node embeds its own OpenSSL (statically linked into the node binary),
  // so this exercises ebpftracer/ebpf/l7/openssl.c's SSL_write/SSL_read
  // uprobes exactly like a C/Python/Ruby process linking libssl would —
  // same decrypted-plaintext handoff into trace_enter_tls, same shared
  // http1_tail_emit/http1.c parsing downstream as plaintext HTTP/1.
  const opts = {
    key: fs.readFileSync('/e2e/certs/server.key'),
    cert: fs.readFileSync('/e2e/certs/server.crt'),
  };
  const server3 = https.createServer(opts, route);
  server3.listen(port3, () => console.log(`node-service: https on :${port3}`));
}

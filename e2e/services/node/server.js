// Node.js HTTP/1.1 + h2c test service for the e2e suite.
// Usage: node server.js <http1-port> <h2c-port>
'use strict';
const http = require('http');
const http2 = require('http2');

const port1 = parseInt(process.argv[2] || '8081', 10);
const port2 = parseInt(process.argv[3] || '8082', 10);

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

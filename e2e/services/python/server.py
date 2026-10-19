#!/usr/bin/env python3
"""Python HTTP/1.1 (+ optional HTTPS) test service for the e2e suite
(HTTP/2 skipped — needs the extra hyper-h2/httpx dependencies, not worth
it for this harness).
Usage: server.py <port> [https-port] [--fork]
--fork serves each connection in a process forked after accept, as Postgres
does: the process that accepted the connection is not the one that reads it.
"""
import json
import socketserver
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer


class ForkingHTTPServer(socketserver.ForkingMixIn, HTTPServer):
    pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/healthz"):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/users"):
            body = json.dumps([{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/error"):
            body = b"boom"
            self.send_response(500)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        if self.path.startswith("/echo"):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


if __name__ == "__main__":
    fork = "--fork" in sys.argv[1:]
    args = [arg for arg in sys.argv[1:] if arg != "--fork"]
    port = int(args[0]) if len(args) > 0 else 8081
    https_port = int(args[1]) if len(args) > 1 else None

    if https_port:
        # CPython's ssl module wraps libssl (OpenSSL) via the _ssl C
        # extension, so this exercises the exact same
        # ebpftracer/ebpf/l7/openssl.c SSL_write/SSL_read uprobes as any
        # other libssl-linked process — same shared http1_tail_emit/
        # http1.c parsing downstream once past the TLS layer.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile="/e2e/certs/server.crt", keyfile="/e2e/certs/server.key")
        httpsd = ThreadingHTTPServer(("0.0.0.0", https_port), Handler)
        httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)
        t = threading.Thread(target=httpsd.serve_forever, daemon=True)
        t.start()
        print(f"python-service: https on :{https_port}")

    server_class = ForkingHTTPServer if fork else ThreadingHTTPServer
    httpd = server_class(("0.0.0.0", port), Handler)
    print(f"python-service: http/1.1 on :{port}" + (" (a process forked per connection)" if fork else ""))
    httpd.serve_forever()

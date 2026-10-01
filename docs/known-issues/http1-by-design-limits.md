# HTTP/1 limits that exist by design

**Status:** documented limits, not bugs. Revisit if a real workload hits them.

| Limit | Value | Effect |
|---|---|---|
| Header capture | `HTTP1_CAPTURE_MAX` 4096 bytes per message | Path and status are read from the first 4 KB; longer headers are cut. The e2e `bighdr` scenario (6 KB header) still records, because the request line is early. |
| Payload per ring event | `MAX_PAYLOAD_SIZE` 1 KB | Large bodies are sent as several events and only up to the capture cap. |
| Rounds per buffer | `HTTP1_MAX_ROUNDS` 30 | See [http1-pipelining-depth.md](http1-pipelining-depth.md). |
| Pending request age | `pendingL7RequestMaxAge` 2 s (userspace) | A request whose open event arrives later, or never, is lost. |
| Lazy open | only for connections created after the agent started, with a recorded `skaddr` | Older connections never get a `ConnectionOpen`. |
| Request without Content-Length and not chunked | treated as zero body (RFC 7230 3.3.2) | Invalid on the wire, but the body bytes are then parsed as the next request. |
| Close-delimited response | stays in DATA with unknown length | Fine for a connection used once. **On a reused keep-alive connection it breaks every later request**, because the phase never returns to HEADERS. The e2e `closedelim` scenario uses one connection per request and so does not show this. |

## Ideas

- Test the close-delimited response on a *reused* connection (the server closes
  after the body, so a reuse is not possible in practice; the realistic risk is
  a proxy that mis-frames). Probably low priority.
- Make `pendingL7RequestMaxAge` configurable, or key the pending buffer by
  connection timestamp only.

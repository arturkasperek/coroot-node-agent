# HTTP Body Capture in Traces Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** put the request and response body of an outbound HTTP/1.1 or HTTP/2 call on its span as `http.request.body` and `http.response.body`, behind a flag that is off by default.

**Scope:** the userspace side of `coroot-node-agent`: flags, the HTTP/1 and HTTP/2 parsers in `ebpftracer/l7`, the span creation in `tracing` and the wiring in `containers`. The consumer is `coroot/docs/superpowers/plans/2026-09-17-clickhouse-trace-body-columns.md`, which stores exactly these two attributes in their own columns.

**Non-goals:**
- Kernel changes. The eBPF side already captures body bytes and sends them (see "What already exists"); this plan only stops throwing them away.
- Redaction or any protection of sensitive data in bodies. Out of scope for now, by decision. The flag defaults to off so nothing is captured until someone asks for it.
- Decompression or decoding (gzip, brotli, protobuf, gRPC). Such bodies are skipped, not decoded.
- Bodies of inbound (server-side) requests. The agent creates spans only for outbound calls today; this plan keeps that.
- Bodies larger than the kernel's capture (4 KB per message and direction, see below).

---

## What already exists

The kernel does the hard part. `ebpf/l7/http1.c` and `http2.c` walk every plaintext HTTP buffer (plain sockets, Go `crypto/tls`, OpenSSL) and emit ring-buffer events; nothing in userspace uses the body ones:

| protocol | events carrying the body | what the bytes are | cap |
| --- | --- | --- | --- |
| HTTP/1 | `MethodHttpClientData` (8) after the request headers, `MethodHttpServerData` (10) after the response headers | the body with the framing removed: for `Transfer-Encoding: chunked` only the chunk data is sent, concatenated in order | `HTTP1_CAPTURE_MAX` = 4096 bytes per message and direction, sent in events of at most 1 KB |
| HTTP/2 | `MethodHttp2ClientFrames` / `MethodHttp2ServerFrames`: whole frames, 9-byte header plus body, including DATA | the DATA frame body as written on the wire | 4096 bytes per stream and direction (`HTTP2_STREAM_CAPTURE_MAX`); a DATA frame larger than the event slot is split across events (header first, rest as raw continuation) |

Userspace today:
- `l7.Http1Parser` (`ebpftracer/l7/http1_parser.go`) handles only the two `*Headers` methods. Data events are passed in and ignored.
- `l7.Http2Parser` (`ebpftracer/l7/http2.go`) decodes only HEADERS frames; every other frame type is skipped in `Parse` (`if h.Type != http2.FrameHeaders { continue }`).
- `containers/container.go` (`onL7Request`) calls `Parse` and, when a request/response pair completes, calls `Trace.HttpRequest` / `Trace.Http2Request` (`tracing/tracing.go`), which create the span immediately.

What is missing and drives the design:
1. **There is no end-of-message marker for HTTP/1.** The kernel does not say "the body is complete". Userspace has to infer it (Content-Length, or the next message, or a timeout).
2. **A span is created when the response headers arrive, before the response body.** To carry the response body the span has to be created later.
3. **Inbound parsers share `Http1Parser`/`Http2Parser`** (`observeInboundL7`). They must not start buffering bodies.
4. **`Trace.createSpan` takes its end time from `time.Now()`.** A deferred span would end late by the wait; the real end must be passed in.

---

## Contract

| attribute | content |
| --- | --- |
| `http.request.body` | request body bytes as captured, at most `--http-body-max-bytes` |
| `http.response.body` | response body bytes as captured, at most `--http-body-max-bytes` |
| `http.request.body.size`, `http.response.body.size` (int) | the real size when known (Content-Length), so a reader can tell a truncated body from a short one |

Rules for what is captured (everything else is dropped and counted):
- **Text only.** Captured only when the content type is allowed (`--http-body-content-types`; default `application/json`, `application/*+json`, `application/xml`, `text/*`, `application/x-www-form-urlencoded`, `application/graphql`) or is absent and the bytes are valid UTF-8 with no NUL.
- **Never encoded.** `Content-Encoding` other than `identity` skips the body (it would be compressed bytes).
- **Never gRPC.** `application/grpc*` is protobuf.
- **Cut on a character boundary.** A truncated body never ends in half a UTF-8 sequence.
- **Empty bodies produce no attribute.**

---

## Global Constraints

- Do not git commit; the user drives that.
- No new README or summary documents.
- Tests first for Go; parser tests are plain unit tests (no VM needed).
- The default behaviour with the flag off must be byte-for-byte the current one: same spans, same attributes, no extra buffering, no deferred spans.
- Memory is bounded: per connection and direction at most `--http-body-max-bytes` of body plus a small queue of pending messages, and a global cap on the number of bodies held.

---

## File map

| File | Change |
| --- | --- |
| `flags/flags.go` | `--http-body-capture`, `--http-body-max-bytes`, `--http-body-content-types`, `--http-body-wait` |
| `ebpftracer/l7/bodies.go` (new), `bodies_test.go` (new) | collector, content-type/encoding rules, UTF-8 cut |
| `ebpftracer/l7/http1_parser.go`, `http1_parser_test.go` | optional body collection, deferred completion |
| `ebpftracer/l7/http2.go`, `http2_test.go` | DATA frames per stream, completion on END_STREAM |
| `tracing/tracing.go`, `tracing/tracing_test.go` (new) | optional body attributes; explicit end time |
| `containers/container.go`, `containers/registry.go` | create the parsers with the option; deferred flush; the three emission sites |
| `metrics/metrics.go` | `node_l7_http_bodies_total{result}` |
| `e2e/loadgen`, `e2e/verify` | check the attributes end to end |

---

### Task 1: Flags and the shared collector

**Files:** `flags/flags.go`, `ebpftracer/l7/bodies.go`, `ebpftracer/l7/bodies_test.go`

- [ ] **Step 1: Write the failing tests** for the pieces everything else builds on:

```go
func TestBodyAllowed(t *testing.T) {
	opts := DefaultBodyOptions()
	cases := []struct {
		ct, enc string
		body    string
		want    bool
	}{
		{"application/json", "", `{"a":1}`, true},
		{"application/json; charset=utf-8", "", `{"a":1}`, true},
		{"application/vnd.api+json", "", `{}`, true},
		{"text/plain", "", "hello", true},
		{"application/json", "gzip", "\x1f\x8b", false},
		{"application/json", "identity", `{}`, true},
		{"application/grpc", "", "\x00\x00", false},
		{"image/png", "", "\x89PNG", false},
		{"", "", `{"a":1}`, true},      // no content type: sniff
		{"", "", "\x00\x01\x02", false}, // binary
	}
	for _, c := range cases {
		assert.Equal(t, c.want, opts.Allowed(c.ct, c.enc, []byte(c.body)), "%v", c)
	}
}

func TestCutOnRuneBoundary(t *testing.T) {
	s := "ab" + "ą" // 'ą' is 2 bytes
	assert.Equal(t, "ab", string(cutUTF8([]byte(s), 3)))
	assert.Equal(t, "abą", string(cutUTF8([]byte(s), 4)))
}

func TestBodyCollectorCaps(t *testing.T) {
	c := newBodyCollector(10)
	c.Add([]byte("hello"))
	c.Add([]byte("world!!!"))
	assert.Equal(t, "helloworld", string(c.Bytes()))
	assert.True(t, c.Full())
}
```

- [ ] **Step 2: Run them (expect fail).** `go test ./ebpftracer/l7 -run 'TestBodyAllowed|TestCutOnRune|TestBodyCollector' -count=1`

- [ ] **Step 3: Implement.**
  - `flags/flags.go`, same style as the other flags (`kingpin`, `envar`):
    - `HttpBodyCapture` bool, default false;
    - `HttpBodyMaxBytes` int, default 4096, values above 4096 are clamped (the kernel never sends more);
    - `HttpBodyContentTypes` strings, default as in "Contract";
    - `HttpBodyWait` duration, default 200ms: how long an HTTP/1 message with an unknown end waits for more body before the span is created.
  - `ebpftracer/l7/bodies.go`: `BodyOptions{Enabled bool, MaxBytes int, ContentTypes []string, Wait time.Duration}` with `DefaultBodyOptions()`, `Allowed(contentType, contentEncoding string, sample []byte) bool`, `cutUTF8(b []byte, max int) []byte`, and `bodyCollector` (`Add`, `Bytes`, `Full`, `Len`).
  - `Allowed` matches the content type case-insensitively, ignoring parameters, with `*` suffix/prefix patterns; with no content type it sniffs (valid UTF-8 after cutting an incomplete tail, no NUL byte).

- [ ] **Step 4: Run the package.** `go test ./ebpftracer/l7 -count=1`

---

### Task 2: HTTP/1 bodies

**Files:** `ebpftracer/l7/http1_parser.go`, `ebpftracer/l7/http1_parser_test.go`

`Http1Parser` matches requests and responses strictly in order (`pending` is a FIFO). The change keeps that and adds, per message, the headers needed to judge the body and a collector for its bytes. A completed pair is released when the response body is known to be complete, not when the response headers arrive.

When is a response body complete?
1. **No body:** response to a request with method `HEAD`, status 1xx/204/304, or `Content-Length: 0` → complete as soon as the headers are.
2. **`Content-Length: N`:** complete when the collector holds `min(N, MaxBytes)` bytes. (The kernel stops sending at 4096, so waiting for `N` itself would never finish.)
3. **Chunked or no length:** unknown end. Complete when the next response headers arrive on this connection, when the next request headers arrive (a keep-alive connection that moved on), or after `Wait` (see `Flush` below).

The request body is complete by the time the response arrives (a server does not answer before reading the request in any normal exchange), so it is whatever the client-direction collector holds when the response headers are seen.

- [ ] **Step 1: Write the failing tests** (plain `Parse` calls, no kernel):

```go
func newBodyParser(max int) *Http1Parser {
	return NewHttp1ParserWithBodies(BodyOptions{Enabled: true, MaxBytes: max, ContentTypes: DefaultBodyOptions().ContentTypes, Wait: 200 * time.Millisecond})
}

func TestHttp1BodiesContentLength(t *testing.T) {
	p := newBodyParser(4096)
	p.Parse(MethodHttpClientHeaders, []byte("POST /orders HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n"), 1)
	p.Parse(MethodHttpClientData, []byte(`{"a":1}`), 2)
	assert.Empty(t, p.Parse(MethodHttpServerHeaders, []byte("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n"), 5))
	got := p.Parse(MethodHttpServerData, []byte(`{"id":"ab"}`), 6)
	require.Len(t, got, 1)
	assert.Equal(t, `{"a":1}`, got[0].RequestBody)
	assert.Equal(t, `{"id":"ab"}`, got[0].ResponseBody)
	assert.Equal(t, int64(11), got[0].ResponseBodySize)
}

func TestHttp1NoBodyCompletesOnHeaders(t *testing.T) { /* GET + 204 and HEAD + Content-Length: 10 complete without data */ }
func TestHttp1ChunkedWaitsForNextMessageOrFlush(t *testing.T) { /* chunked response: nothing returned; Flush(after Wait) returns it with the bytes so far */ }
func TestHttp1ChunkedCompletedByNextRequest(t *testing.T)     { /* the next client headers release the previous pair */ }
func TestHttp1BodyTruncatedAtMax(t *testing.T)                { /* CL 5000, max 100: body is 100 bytes, size attr 5000, completes at 100 */ }
func TestHttp1BodyDataSplitAcrossEvents(t *testing.T)         { /* three 1 KB data events assemble in order */ }
func TestHttp1GzipAndBinaryAreSkipped(t *testing.T)           { /* span still produced, bodies empty */ }
func TestHttp1PipelinedBodiesStayWithTheirRequests(t *testing.T) { /* two POSTs back to back, two responses */ }
func TestHttp1DisabledIsUnchanged(t *testing.T)               { /* NewHttp1Parser(): data events ignored, completion on response headers as before */ }
```

Write the elided tests in full; each is a few `Parse` calls like the first one. `Flush` is the function the container's ticker calls (below).

- [ ] **Step 2: Run them (expect fail).** `go test ./ebpftracer/l7 -run TestHttp1 -count=1`

- [ ] **Step 3: Implement.**
  - `Http1Request` gets `RequestBody, ResponseBody string` and `RequestBodySize, ResponseBodySize int64` (-1 when unknown). The existing fields are untouched.
  - `NewHttp1Parser()` stays exactly as is, with bodies off. Add `NewHttp1ParserWithBodies(BodyOptions)`. Inbound parsers keep using `NewHttp1Parser()`.
  - When bodies are on, the client side parses from the finished header block (`clientBuf`/`serverBuf` at the moment of the `\r\n\r\n` check) the values of `Content-Length`, `Transfer-Encoding`, `Content-Type` and `Content-Encoding`, and stores them in `http1PendingRequest`/a new `http1PendingResponse`.
  - `MethodHttpClientData` appends to the collector of the newest pending request; `MethodHttpServerData` to the response being matched. Data that arrives with nothing to attach to (no pending message) is dropped and counted.
  - Release rules as listed above. A pair is held in a `ready` queue until released; `Parse` returns the released pairs, in order.
  - `Flush(now time.Time) []Http1Request` releases pairs waiting longer than `Wait`. `Parse` records the time of the last event per pair using the caller-supplied clock, so tests do not sleep: `Parse` keeps its signature and a separate `ParseAt(method, payload, kernelTime, now)` carries the clock; `Parse` calls it with `time.Now()`.
  - Bound the queues: at most 64 messages held per parser; beyond that the oldest is released without body.

- [ ] **Step 4: Run the package.** `go test ./ebpftracer/l7 -count=1`

---

### Task 3: HTTP/2 bodies

**Files:** `ebpftracer/l7/http2.go`, `ebpftracer/l7/http2_test.go`

HTTP/2 has an exact end marker: `END_STREAM` on the last HEADERS/DATA frame of a stream, carried in the frame flags the kernel preserves. So a request/response pair is complete when the response side of its stream ends, and no timer is needed (a timer still bounds streams that never end).

The existing `Parse` returns a request when the response HEADERS are decoded (`statuses` map). With bodies on it must instead return it when the response stream ends.

- [ ] **Step 1: Write the failing tests** with frames built by `golang.org/x/net/http2` (`http2.Framer` writing to a buffer, the HPACK encoder from `hpack`):
  - `TestHttp2BodiesRequestAndResponse`: HEADERS (no END_STREAM) + DATA (END_STREAM) on the client side, HEADERS + DATA (END_STREAM) on the server side → one request with both bodies after the last frame.
  - `TestHttp2NoBodyResponse`: HEADERS with END_STREAM → complete at once, no body attributes.
  - `TestHttp2DataSplitAcrossEvents`: a 3000-byte DATA frame delivered as header + 1000 bytes + 1000 bytes + 1000 bytes in four `Parse` calls (the kernel's continuation events) → the body is assembled; the existing reassembly limit `http2ReassemblyMax` (1024) must not drop it.
  - `TestHttp2BodyCappedAndEndsStream`: 10 KB of DATA frames with `MaxBytes` 100 → 100 bytes, size attribute from `content-length` when present.
  - `TestHttp2GrpcAndGzipSkipped`: content type `application/grpc` / `content-encoding: gzip` → no bodies, span as before.
  - `TestHttp2InterleavedStreams`: two streams multiplexed, DATA frames alternating → each body goes to its own stream.
  - `TestHttp2PaddedDataSkipped`: a PADDED DATA frame is skipped, not misread.
  - `TestHttp2DisabledIsUnchanged`: `NewHttp2Parser()` returns requests on response HEADERS exactly as today.

- [ ] **Step 2: Run them (expect fail).** `go test ./ebpftracer/l7 -run TestHttp2 -count=1`

- [ ] **Step 3: Implement.**
  - `NewHttp2ParserWithBodies(BodyOptions)`; `NewHttp2Parser()` unchanged.
  - Extend the HEADERS decode callbacks to also read `content-type`, `content-encoding` and `content-length` per stream (request side from the client decoder, response side from the server decoder), and the `END_STREAM` flag of the HEADERS frame.
  - Handle `http2.FrameData` in `Parse`: append the DATA body to the stream's request or response collector; honour `END_STREAM`.
  - DATA frames can be much larger than one event, so stream them into the collector as the bytes arrive instead of requiring the whole frame: keep the frame's remaining length in the partial state and append whatever arrives, for DATA only. HEADERS keep the existing buffered reassembly (a header block must be decoded whole).
  - Skip PADDED DATA frames (flag `0x8`): drop their bytes and mark the stream's body as unavailable.
  - `Http2Request` gets the same body fields as `Http1Request`.
  - Return a request when the server side of its stream has ended (or after `Wait` past the response HEADERS for streams that never end: `Flush(now)`, mirroring HTTP/1). With bodies off, return on response HEADERS as today.
  - Garbage-collect streams that never end together with the existing `activeRequests` GC.

- [ ] **Step 4: Run the package.** `go test ./ebpftracer/l7 -count=1`

---

### Task 4: Span attributes and the real end time

**Files:** `tracing/tracing.go`, `tracing/tracing_test.go` (new)

- [ ] **Step 1: Write the failing tests** with an in-memory span exporter (`sdktrace` has `tracetest.NewInMemoryExporter`):
  - `TestHttpRequestSpanWithBodies`: `HttpRequest` with bodies produces `http.request.body`, `http.response.body` and the two `*.size` attributes; without bodies it produces exactly the attributes it produces today (compare the full attribute set, so a stray empty attribute fails).
  - `TestSpanUsesGivenEndTime`: a span created 300 ms after the response, with `at` set to the response time, ends at `at` and starts at `at - duration`.

- [ ] **Step 2: Run them (expect fail).** `go test ./tracing -count=1`

- [ ] **Step 3: Implement.**
  - A small `HttpBodies{Request, Response string; RequestSize, ResponseSize int64}` value; `HttpRequest` and `Http2Request` take a `*HttpBodies` (nil = none) and an `at time.Time` (zero = now) as their last arguments.
  - `createSpan` uses `at` instead of `time.Now()` when given, so a deferred span keeps its true start and end.
  - Attributes are added only when non-empty; sizes only when known.
  - Update the callers; with `nil, time.Time{}` behaviour is unchanged.

- [ ] **Step 4: Run the package.** `go test ./tracing ./containers -count=1`

---

### Task 5: Wiring and flushing

**Files:** `containers/container.go`, `containers/registry.go`, `metrics/metrics.go`

Spans are created in three places: `onL7Request` (live), `emitPendingHttp1Requests` and `emitPendingHttp2Requests` (replay of events that arrived before the connection was registered, bounded by `pendingL7RequestMaxAge`).

- [ ] **Step 1: Write the failing test** in `containers` (a `Container` with a fake tracer is already constructible in the existing tests; if not, test the helper below directly):
  - `TestFlushReleasesWaitingBodies`: feed a chunked response, call `c.flushHttpBodies(now+Wait)` and see one span with the body.

- [ ] **Step 2: Implement.**
  - Factor the three span-creation sites into one helper (`c.observeHttp(protocol, req, conn, trace)`), so the body attributes are added in one place.
  - Create the outbound parsers (`conn.http1Parser`, `conn.http2Parser` and the pending ones) with `...WithBodies` when `*flags.HttpBodyCapture`; inbound parsers are created as today.
  - `flushHttpBodies(now)`: for each connection with a parser that can hold messages, call `Flush`, then run the released requests through the same helper. Call it from a new 250 ms ticker in `Registry.handleEvents` for containers that have any held message (keep a counter, so idle containers cost nothing). Only start the ticker when the flag is on.
  - Pass the response time (`at`) from the parser to the tracer so a released span keeps its timing.
  - `metrics.go`: `node_l7_http_bodies_total{result}` with results `captured`, `skipped_content_type`, `skipped_encoding`, `skipped_binary`, `truncated`, `dropped_no_message`, `dropped_queue_full`.

- [ ] **Step 3: Run the packages.** `go test ./containers ./ebpftracer/... ./tracing -count=1` (on Linux; `containers` does not build on macOS, run it in the test container, see `make docker-test`).

---

### Task 6: End to end

**Files:** `e2e/loadgen/main.go`, `e2e/verify/main.go`, `e2e/run-agent.sh`

`POST /echo` already sends a deterministic body (`bytes.Repeat([]byte{byte('a' + i%26)}, 200+i%800)`) and the services echo it back, so both bodies are known from the request number `n`.

- [ ] **Step 0: Give the echo a text content type.** The services answer `POST /echo` with different types: Node sets `application/octet-stream` (`e2e/services/node/server.js`), which the text-only rule skips by design, while Go, Python, PHP and Java set none (the body is then sniffed). Make the test deterministic: `loadgen` sends `Content-Type: text/plain` on echo requests, and the Node service echoes the request's `content-type` instead of the fixed one. The other services are left alone, so the "no content type, sniff" path stays covered.
- [ ] **Step 1: Pass the flag.** `run-agent.sh` starts the agent with `--http-body-capture` when `HTTP_BODIES=1`; `e2e/run.sh` passes the variable through.
- [ ] **Step 2: Extend `verify`** with `-bodies`: for every matched `POST /echo` span, `http.request.body` and `http.response.body` must both equal `strings.Repeat(letter, min(200+n%800, MaxBytes))` where `letter` follows from `n`. Report mismatches with the request number, like the existing missing-request list.
- [ ] **Step 3: Run it** for the targets that have `POST /echo`: `HTTP_BODIES=1 ONLY=go-h1,node-h1,python-h1,node-tls,python-tls,go-h2c,node-h2c N_REQUESTS=1000 bash e2e/run.sh`. All bodies must match, for plain HTTP/1, TLS and HTTP/2. Add `STRESS=cpu CONCURRENCY=80` once it passes, as bodies are the first thing a lossy pipeline would cut.
- [ ] **Step 4: Check the flag off.** A normal `bash e2e/run.sh` must be unchanged: no body attribute on any span, the same ratios.
- [ ] **Step 5: Measure the cost.** `make docker-test-latency` with and without `--http-body-capture`; the parsers run in userspace only, so the added latency to the application should be zero and the agent's CPU slightly higher. Record both in `docs/latency-benchmark.md`.

---

## Self-review

1. **Nothing in the kernel changes.** The data is already captured and sent; the plan is the userspace that finally reads it. This keeps the 1M-instruction verifier budget (see `docs/known-issues`) untouched.
2. **The hard problems are named, not assumed away:** there is no end marker for HTTP/1 (so completion is Content-Length, the next message or a timeout), spans are created before the response body (so creation is deferred and carries its real end time), inbound parsers must not buffer (separate constructors), and large HTTP/2 DATA frames arrive in pieces (so DATA is streamed, not reassembled whole).
3. **Behaviour with the flag off is pinned by tests** (`...DisabledIsUnchanged`, the attribute-set comparison in the tracing test, and the plain e2e run).
4. **Bodies the product cannot show usefully are skipped on purpose** (compressed, binary, gRPC), with a metric per reason, so "no body" is explainable.
5. **Memory is bounded** per message, per parser queue and by the flag; the held queue is released oldest-first without a body rather than growing.
6. **The end-to-end check recomputes the expected body from the request number**, so it needs no extra manifest data and catches truncation, mix-ups between pipelined or multiplexed messages, and TLS paths in one run.
7. **Open and deliberate:** there is no redaction. A body can contain credentials or personal data; the flag is off by default and the server stores whatever arrives. Revisit before enabling it on a node that serves such traffic.

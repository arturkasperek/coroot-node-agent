# HTTP/2 TLS Ingress Frame Reassembly Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make coroot-node-agent observe `GET /users`-style HTTP/2 requests on Go `net/http` TLS servers (ingress), not only on clients (egress) or custom large-read test servers.

**Architecture:** eBPF classifies HTTP/2 from a 9-byte frame header (or the client preface). When `tls.Conn.Read`/`Write` returns only the header, a small BPF map keyed by `pid+fd+is_tls+method` (method = client-frames vs server-frames, so an in-flight request read and an in-flight response write on the same socket never collide) stores `remaining` bytes. The next read/write on that socket+direction is sent as HTTP/2 without re-running `looks_like_http2_frame` on the bare payload. This covers both HEADERS and CONTINUATION frames (a header block can legally span several frames); DATA/body is explicitly out of scope. `Http2Parser` stitches chunks into a complete frame — including CONTINUATION continuations of the same header block — then HPACK as today. Do not reassemble a full 8KB request in the kernel.

**Tech Stack:** cilium/ebpf C programs (`ebpf/l7/http2.c`, `ebpf/l7/l7.c`), Go `l7.Http2Parser`, GoTLS uprobes (`gotls.c`), VM tests via `make docker-test`.

## Global Constraints

- Do not git commit unless the user asks.
- Do not add README or extra summary docs beyond this plan.
- Tests first for Go (`l7/http2_test.go`, then `tracer_test.go`). eBPF C has no unit test harness; cover it with parser tests plus `TestHttp2TlsIngressEvents`.
- Keep `MAX_PAYLOAD_SIZE` at 1024 for this work. Future ~8KB-per-request lives in userspace after stream reassembly, not as one 8KB perf event.
- Scope is HEADERS + CONTINUATION only (the two frame types the parser actually reads). DATA/body stays untouched in both kernel and parser — no leftover tracking, no decoding, same as today.
- The progress-map key must disambiguate request-direction vs response-direction state on the same `pid+fd+is_tls` (HTTP/2 is full-duplex; a read and a write can each be mid-frame at the same time). Do not ship Task 2 without this.
- TLS HTTP/2 tests must use stdlib `net/http` (client and server), not a custom Framer with `Read(4096)`.
- Rebuild the embedded BPF blob (`ebpftracer/Makefile` / `ebpf.go`) after changing C.
- Run VM tests with `make docker-test DOCKER_TEST_ARGS='-count=1 -timeout 10m -v github.com/coroot/coroot-node-agent/ebpftracer -run TestHttp2'`.
- **Dependency on `docs/superpowers/plans/2026-09-16-write-syscall-short-write-tracking.md` for the write side.** Task 2's `remaining`/`hdr_have` tracking assumes the `size` passed into `handle_response` (and `handle_request` when called from a write context — HTTP/2 is full-duplex) reflects bytes the kernel/TLS layer **actually accepted** in that call, not what the caller requested. Today `trace_enter_write` (raw syscalls) and `go_crypto_tls_write_enter` (GoTLS) use the *requested* size — a short write would make `http2_progress` compute `remaining` against bytes that, per the sibling plan's own analysis, haven't necessarily reached the wire yet in this call, corrupting the next write's classification. Implement that plan's Task 1 (raw syscalls) and Task 2 (GoTLS write) before or together with this plan's Task 2 — every write-side test here (Task 4, 6, 7, 8's raw h2c clients, and `handle_response` in general) is exposed to this until the write-exit clamp lands. The **read** side of this plan is unaffected: `trace_exit_read`/`go_crypto_tls_read_exit` already clamp to the syscall/function's actual return value, so Task 1's leftover buffer and Task 3's stdlib ingress test do not depend on the sibling plan.

---



## Problem



### What we observe

Go **clients** (`http.Client` / `http.Transport`) over TLS HTTP/2 are visible as egress: `crypto/tls.(*Conn).Write` usually emits a **complete** HTTP/2 frame in one call (`Framer.endWrite`). `TestHttp2TlsEgressEvents` already passes with stdlib.

Go **servers** (`http.Server` + `ServeTLS`) over TLS HTTP/2 are **not** visible as ingress `GET /users`. `TestHttp2TlsIngressEvents` with stdlib timed out. The ring still saw HTTP/2: preface, SETTINGS (`length=0`), and the **response** HEADERS+DATA on `Write` (`:status 200`). The **request** HEADERS (`:method GET`, `:path /users`) never arrived as a complete frame.

### Why (stdlib server)

`net/http` HTTP/2 server builds the framer on the raw `*tls.Conn`, **not** `bufio.Reader`:

```go
// go/src/net/http/h2_bundle.go
fr := http2NewFramer(sc.bw, c) // c is net.Conn / *tls.Conn
```

`ReadFrame` does `io.ReadFull` of **9 bytes** (frame header), then `io.ReadFull` of the payload.

`crypto/tls.Conn.Read(p)` decrypts a full TLS record internally, then copies `min(len(p), available)`. `Read(9)` returns 9 bytes; the rest stays inside `tls.Conn`.

Example: one HEADERS frame, 23 bytes total (`length=14`):

```text
Client process (egress)     TLS record      Server process (ingress)
tls.Conn.Write(23 bytes)  ──────────────►  tls.Conn.Read(9)  → 00 00 0e 01 04 00 00 00 01
                                           tls.Conn.Read(14) → HPACK only (no 9-byte prefix)
```

Same bytes on the wire. Different syscall/uprobe shapes.

### Why eBPF drops it

`looks_like_http2_frame` (`ebpftracer/ebpf/l7/http2.c`) requires the **first** frame in the buffer to be complete: `frame_length + 9 <= size`.

- Read #1 (9 B, `length=14`): `14+9 > 9` → drop. No event.
- Read #2 (14 B HPACK): no HTTP/2 header. Interpreting the first 3 bytes as length/`type` is garbage (`type > 0x9`) → drop.

SETTINGS with `length=0` is exactly 9 bytes, so it still matches. Preface is a dedicated 24-byte `ReadFull`, so it matches. That is why the failed test log showed SETTINGS and preface, not `GET /users`.

The parser never sees client HEADERS. `activeRequests[streamId]` stays empty. Later server HEADERS (`:status 200`) are ignored (`if r == nil { continue }`).

### `looks_like_http2_frame` rejects this exact example too — the fix can't stop at adding a progress map

It's tempting to assume the progress map (below) is the whole fix: keep `looks_like_http2_frame` exactly as it is today, and only add logic for *what happens after* it says "yes, this is HTTP/2." Tracing the motivating 9-byte example through the **unmodified** function shows that assumption is wrong:

```
buf = 00 00 0e 01 04 00 00 00 01   (length=14, type=HEADERS)
size = 9, method = METHOD_HTTP2_CLIENT_FRAMES

size < 9?            9 < 9 → false, continue
frame_length = 14
frame_length+9 > size?   23 > 9 → true → return is_client_preface(buf, 9, method)
is_client_preface:   size < 24 → return 0
looks_like_http2_frame returns 0
```

The function says **no, this does not look like HTTP/2** for the plan's own primary motivating input. `handle_request`'s `else if (looks_like_http2_frame(...))` branch is never entered, no `send_event` happens, and nothing downstream (the progress map, `http2_scan_trailing_incomplete`) ever runs on these bytes — they're dropped exactly as they are today, progress map or not.

The root issue: `looks_like_http2_frame` conflates two different reasons a frame "doesn't fit the buffer" — (a) genuine garbage (`type > 0x9`, or a non-preface buffer under 24 bytes with no valid header) and (b) a well-formed `HEADERS`/`CONTINUATION` header whose declared `length` simply exceeds what's in this buffer *yet* (i.e. exactly the split-read case this whole plan is about). Only (a) should fall back to the preface check and possibly reject; (b) must be accepted as "yes, HTTP/2-shaped, but incomplete" — otherwise there is no event to attach `remaining`/`hdr_have` to in the first place. See "Chosen solution" and Task 2, Step 0 for the fix.

### There is no kernel “this socket is HTTP/2” state today

HTTP/2 path in `handle_request` / `handle_response`: `send_event` then `return 0`. It does **not** store `protocol` in `active_l7_requests` (unlike HTTP/1.1, Redis, Postgres).

`active_connections` is only `timestamp`, byte counters, `is_inbound`. No protocol, no leftover.

Userspace (`containers`) creates `Http2Parser` per conn/fd **after** an event already has `ProtocolHTTP2`. That cannot classify a bare HPACK chunk.

A custom test server that `Read(4096)` hid this: one uprobe saw the whole TLS record. That is not how `net/http` works. Tests must stay on stdlib.

### Bare payload cannot be classified as HTTP/2 vs Redis

HPACK has no HTTP/2 magic. Redis on **another** `fd` is unrelated. The second read is HTTP/2 only because **this** `pid+fd` just saw an incomplete HEADERS header and still owes `length` bytes.

### A request read and a response write can be mid-frame at the same time (same `fd`)

HTTP/2 is full-duplex: on the server's `fd`, `handle_request` (reading the next client HEADERS) and `handle_response` (writing this stream's response HEADERS) run independently and can each have an in-flight partial frame *concurrently*. A progress map keyed only by `pid+fd+is_tls` would let one direction's `remaining` overwrite the other's mid-reassembly, corrupting both (worst case: request HPACK bytes get fed to the response-side decoder, desyncing HPACK's shared dynamic table for the rest of the connection). The key must include a direction/method discriminator (`METHOD_HTTP2_CLIENT_FRAMES` vs `METHOD_HTTP2_SERVER_FRAMES`) — see "Chosen solution".

### A single read/write can contain both the rest of an in-flight frame *and* one or more new frames

A buffer that satisfies `remaining > 0` isn't guaranteed to contain **only** the leftover bytes of the current frame — it can be longer, with the leftover at the front followed by one or more additional complete (or incomplete) frames. This happens whenever the reader/writer on the other end doesn't request exactly `remaining` bytes: e.g. a client-side `bufio.Reader` (used by `golang.org/x/net/http2` Transport) that, on refill, issues one `tls.Conn.Read` for a generic large chunk — which can span "the rest of the frame I was waiting on" + "the next frame(s) already queued on the socket". Naively consuming only `min(size, remaining)` and stopping (as a first draft of the progress-map logic would) silently drops every byte after `remaining` — a second, self-inflicted version of the exact bug this plan fixes. The kernel-side design must fall through to normal classification for `payload[remaining:]` whenever `size > remaining`, not just consume the head and return. See "Chosen solution" and Task 2.

### The incomplete-frame check only ever looks at the *first* frame in a buffer — a trailing incomplete frame after 1+ complete ones is invisible to it, and userspace's leftover can't save it either

A first draft of `http2_incomplete_headers` (see original Task 2) decides complete-vs-incomplete by reading the header at **offset 0** of whatever buffer it's given. That's correct for a buffer that *starts* incomplete, but it silently mis-handles `[complete frame A][complete frame B][incomplete frame C — header only]`: the check sees A (complete) at offset 0, concludes "this buffer is fine", and the whole thing ships as one "complete" event — **no `remaining` entry gets created for C**, even though C genuinely isn't finished.

This is worse than a simple truncation, because of what happens next: the peer's *next* write/read delivers the rest of C — raw HPACK continuation bytes with no 9-byte header in front (that header already went out in the previous event, as part of A+B+C-header). Since no `remaining` entry exists for this key, the kernel treats these bytes as a **brand-new** buffer and runs them through `looks_like_http2_frame` from scratch — which almost certainly rejects them (no valid header at the front, `type > 0x9`) and **drops the event entirely**. Unlike a normal truncation, this isn't something `Http2Parser`'s userspace `leftover` (Task 1) can fix: `leftover` only helps with bytes that actually *reach* userspace as an event payload. If the kernel never forwards C's continuation because it failed classification, `Parse()` never gets a chance to see it, and the `leftover` saved from the previous call sits unfinished until GC times it out.

**Fix:** the "should I set `remaining`" decision must be based on the **last** frame boundary reached while walking the buffer from the front, not the first. See "Chosen solution" and Task 2 for the bounded walk that replaces the offset-0-only check, and Task 6 for the regression test.

### The trailing-frame scan also has to skip the client preface, or it misreads the first 24 bytes as a bogus frame header

A buffer can legally start with the 24-byte client preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) followed by a complete SETTINGS frame *and* an incomplete HEADERS frame, all in one `write()` (a client that flushes preface+SETTINGS+first request together — normal for many non-stdlib HTTP/2 clients). `looks_like_http2_frame` classifies this buffer as HTTP/2 via its `is_client_preface` fallback (the first 3 bytes read as a bogus 24-bit length are huge, so `frame_length + 9 > size` triggers the preface check). But a naive `http2_scan_trailing_incomplete(buf, size, ...)` that starts walking frame headers at **offset 0** doesn't know the first 24 bytes are a preface, not a frame header: it reads `'P','R','I',' '` as `type = 0x20 > 0x9`, decides "not a frame I understand", and **aborts the whole scan immediately** — so the genuinely incomplete HEADERS frame *after* the preface+SETTINGS never gets a `remaining` entry, reproducing the exact bug this plan exists to fix, just triggered by the preface instead of a run of complete frames. See "Chosen solution" and Task 2, Step 2 for the fix (skip 24 bytes when `is_client_preface` matches, before starting the frame walk), and Task 7 for the regression test.

### A trailing frame's own 9-byte header can itself be split mid-syscall — combined with the fall-through, this is silent, not just "out of scope"

`http2_scan_trailing_incomplete`'s bail-out condition — `size - offset < 9` → "header itself split mid-syscall — accepted, out-of-scope edge case" — sounds like a narrow, self-contained corner: don't track `remaining` for these trailing bytes, let the next read/write fail classification and get dropped, same as any other unclassifiable fresh buffer. That would be a normal, bounded loss.

Combined with the Task 2 Step 1 fall-through, it isn't. Example: `[10 bytes finishing a pending HEADERS][complete DATA][complete DATA][complete DATA][8 bytes — one byte short of a brand-new HEADERS frame's 9-byte header]`. Step 1 consumes the first 10 bytes as one event (finishing the pending frame). The fall-through classifies the rest as a second event — one HTTP/2 blob, because the first frame in it (`DATA`) makes `looks_like_http2_frame` accept the whole remainder. `http2_scan_trailing_incomplete` walks past the three DATA frames, then hits its own `size - offset < 9` bail-out on the trailing 8 bytes: no `remaining` and nothing else is recorded. The next read/write's bytes (the header's 9th byte, plus that frame's HPACK payload) arrive with **no complete 9-byte header in front of them anymore** — it went out split across the previous two events — and fail `looks_like_http2_frame` from scratch: the exact "worse than a plain drop" failure mode already documented above for `[complete A][complete B][incomplete C]`, just triggered one level deeper (the header itself, not only its body, is split). The event never reaches userspace, so `Http2Parser`'s `leftover` (Task 1) never gets a chance at it either.

This is not meaningfully rarer than the cases Task 6/7 already fix (a trailing frame with a *complete* header but short body) — it's the same class of TCP/TLS-record boundary landing a few bytes earlier. Leaving it unfixed while fixing Task 6/7 would be an inconsistent scope cut.

**Fix:** extend `http2_progress` to also track a partial **frame header** (distinct from partial frame *body*, which `remaining` already covers) — see "Chosen solution" and Task 2, Step 1b; Task 8 is the regression test.

### An inbound fd can be reused by an unrelated connection before `http2_progress` is cleared

`fd` numbers are recycled by the OS: process A `connect()`s or gets `accept()`ed on `fd=42` speaking HTTP/2, the connection closes, and the OS hands `fd=42` to a brand-new, unrelated connection (possibly a different protocol entirely). Nothing about `pid+fd+is_tls+method` as a key distinguishes "the same fd, still the same connection" from "the same fd, a completely different connection that happens to reuse the number." If `http2_progress` still has a `remaining`/`hdr_have` entry for `fd=42` from the old connection when the new one's first bytes arrive, Step 1/1b would try to consume/splice them as a continuation of the *old* HTTP/2 frame — misclassifying the new connection's first read/write and potentially feeding its bytes into `Http2Parser`'s HPACK decoder.

For **outbound** fds this is already guarded: `sys_exit_connect` deletes all `http2_progress` entries for the fd right after a fresh `connect()` returns, before the new connection's first request goes out (mirroring the existing `active_l7_requests` cleanup there). For **inbound** fds, the map this design is modeled on (`active_l7_requests`) has no equivalent — it relies purely on `BPF_MAP_TYPE_LRU_HASH` eviction, which has no guaranteed timing relative to fd reuse. `http2_progress` closes this gap instead of inheriting it: `handle_accept_exit` (`ebpftracer/ebpf/tcp/state.c`) already receives the newly-`accept()`ed fd at the exact moment the kernel hands it out, before any `read`/`write` can happen on it — the inbound mirror of the `sys_exit_connect` moment. Deleting all four `{is_tls, method}` `http2_progress` entries there is unconditionally safe (a fresh `accept()` fd cannot have a legitimate pending continuation) and closes the window entirely, rather than leaving it to LRU timing. See "Chosen solution" and Task 2, Step 2b.

### Pre-existing gap: `Http2Parser` never handles CONTINUATION frames

Separate from the TLS/ingress bug, but touching the same code: `Http2Parser.Parse` (`ebpftracer/l7/http2.go`) only feeds HPACK bytes to the decoder for `h.Type == http2.FrameHeaders`; every other type, including CONTINUATION (`0x9`), is skipped over (`offset += h.Length; continue`) without checking the `END_HEADERS` flag. A header block that spans HEADERS + CONTINUATION (large cookies, JWT/Bearer tokens, gRPC-web metadata) is silently truncated today, and — because HPACK's dynamic table is shared/stateful across the whole connection — skipping the CONTINUATION bytes can desync the decoder for *all later* requests on that connection. This plan fixes it alongside the TLS-split issue because the kernel-side "incomplete frame" detection needs to treat CONTINUATION the same way it treats HEADERS anyway.

### Future 8KB-per-request (out of this plan, but constrains the design)

“8KB payload per request” is a **stream** (`GET /users` + body), not one syscall. eBPF does not parse HPACK. Do **not** stitch a full request in the kernel or grow a single perf sample to 8KB (128KiB L7 ring ≈ 15 events/CPU). Chunks now, assemble in `Http2Parser` later. This leftover path is the same mechanism.

---



## Chosen solution

**Kernel:** a small BPF map for in-flight HTTP/2 **frame** state, used by the BPF program.

- Key: `pid`, `fd`, `is_tls`, `method` (`METHOD_HTTP2_CLIENT_FRAMES` or `METHOD_HTTP2_SERVER_FRAMES` — same constants already used for `send_event`). The `method` field is required, not optional: `handle_request` (reads) and `handle_response` (writes) can each have an independent in-flight partial frame on the *same* `pid+fd+is_tls` at the same time, since HTTP/2 is full-duplex. Without this field the two directions overwrite each other's `remaining` state (see Problem section). `stream_id` is **not** needed in the key: bytes within one frame (or one HEADERS+CONTINUATION header block) are never interleaved with bytes of another frame in the same direction, so there is at most one in-flight partial frame per `{pid, fd, is_tls, method}` at any time.
- Value: `remaining` (bytes still needed to finish the current frame), `frame_type` (so we only continue HEADERS/CONTINUATION, and so `Http2Parser` still sees the correct type byte on the next chunk).
- **Deciding `remaining` requires walking to the *last* frame boundary in the buffer, not just checking offset 0.** A bounded helper (`http2_scan_trailing_incomplete(buf, size, method, &remaining, &frame_type)`, capped at `MAX_PAYLOAD_SIZE/9 ≈ 113` iterations so the verifier accepts it) takes `method` — same as `looks_like_http2_frame`/`is_client_preface` — because the first thing it must do is check (and skip) a 24-byte client preface at offset 0 (`is_client_preface(buf, size, method)`; only relevant for `METHOD_HTTP2_CLIENT_FRAMES`) **before** starting the frame walk. Skipping this step misreads the preface's `'P','R','I',' '` bytes as a bogus frame header (`type = 0x20 > 0x9`) and aborts the scan immediately, silently losing `remaining` for a genuinely incomplete frame that follows the preface+SETTINGS in the same buffer — see Problem section, "The trailing-frame scan also has to skip the client preface." After that one-time skip, it walks frame-by-frame from wherever it started: while a full 9-byte header is available and its frame fits entirely in what's left, skip past it (`offset += 9 + length`) and check the next one. It stops when either (a) `offset == size` — buffer ends cleanly, no `remaining` needed; (b) fewer than 9 bytes remain — an already-accepted, out-of-scope edge case (the header itself split mid-syscall; same limitation noted for the original single-frame design, not newly introduced here); or (c) a full header is available but its frame doesn't fit (`length + 9 > size - offset`) — **this** is the trailing-incomplete frame, and *its* type (not the first frame's) decides whether to track it: `HEADERS`/`CONTINUATION` → set `remaining = length + 9 - (size - offset)` and `frame_type`; anything else (DATA, SETTINGS, ...) → don't track, same as today's "don't buffer DATA" rule. This helper runs on whatever bytes are about to be `send_event`'d as HTTP/2 — both a fresh buffer and the fall-through tail described below — and *replaces* the old "only look at offset 0" version of `http2_incomplete_headers` (see Task 2).
- **`looks_like_http2_frame` itself must accept this case, or there is nothing to attach `remaining` to.** Today it treats "declared `length` doesn't fit in `size`" as a single bucket and falls back to `is_client_preface` for all of it — which correctly rejects garbage but *also* incorrectly rejects a well-typed, genuinely-in-flight `HEADERS`/`CONTINUATION` header (see Problem section, "`looks_like_http2_frame` rejects this exact example too"). Fix: when `frame_length + 9 > size`, read `type` (byte 3, needs `size >= 9`, which is guaranteed on this branch already since the preface-fallback path is only for `size < 9` or `size >= 9`-but-doesn't-fit) **before** deciding — if `type == HEADERS (0x1)` or `type == CONTINUATION (0x9)`, return `1` (HTTP/2-shaped, just incomplete) instead of falling to `is_client_preface`. Only fall back to the preface check when `type` is neither (DATA/SETTINGS/garbage/etc. that doesn't fit is still not tracked, same "don't buffer DATA" rule as elsewhere). This is a real, one-line-ish change to the function, not a "keep as-is" — see Task 2, Step 0.
- On a valid 9-byte header with `type == HEADERS (0x1)` **or** `type == CONTINUATION (0x9)` and `frame_length + 9 > size`: once the fix above makes `looks_like_http2_frame` accept it, still `send_event` with the 9 bytes; set `remaining = frame_length + 9 - size`. CONTINUATION must be included because a header block can legally span HEADERS + one or more CONTINUATION frames (`END_HEADERS` not set), and CONTINUATION frames are just as likely to be split across `tls.Conn.Read`/`Write` calls as HEADERS. (This bullet describes the buffer-starts-incomplete case; it's a special case the general `http2_scan_trailing_incomplete` walk above also produces, at `offset=0`.)
- **On the next read/write for that key, check `hdr_have` before `remaining`** (Step 1b): if `hdr_have > 0`, try to complete the header first. Let `need = 9 - hdr_have`. If `size < need`, the header is *still* incomplete — append these `size` bytes to `hdr_buf`, add to `hdr_have`, store, `return 0` (nothing new to decide yet; this can repeat across several tiny reads/writes if the header is split into more than two pieces). Otherwise, splice `hdr_buf[0:hdr_have]` and `payload[0:need]` into one 9-byte header on the stack and parse `length`/`type` from it exactly as `looks_like_http2_frame` does. If `type` isn't `HEADERS`/`CONTINUATION`, clear `hdr_have`/`hdr_buf` and drop the state — same "don't track DATA" rule as everywhere else here. Otherwise, treat `payload[need:]` as the start of that frame's body: this collapses into the *same* logic as the `remaining > 0` path below (send the header-completing bytes plus as much body as fits as one event, set `remaining` for whatever body is still missing, clear `hdr_have`/`hdr_buf`, and fall through to normal classification — including a fresh `http2_scan_trailing_incomplete` pass — for anything left over past this frame).
- On the next read/write for that key: if `remaining > 0`, **do not** call `looks_like_http2_frame` on the payload. Copy `min(size, remaining)`, `send_event` as HTTP/2, subtract, delete the entry at 0. **If `size > remaining`** (the buffer has bytes beyond what was needed to finish the current frame), do **not** stop there: advance `payload` by `remaining` and shrink `size` by the same amount, then fall through into the normal classification path (same as a brand-new buffer) for what's left — **and re-run `http2_scan_trailing_incomplete` on that tail** to decide whether *it* ends incomplete (see previous bullet). That tail can be a complete frame, several complete frames, or end in another incomplete frame; only the scan (not the simple first-frame check) tells the three apart correctly.
- Preface and complete frames: unchanged (`looks_like` as today).
- Incomplete **DATA** (and other types): **do not** start leftover. Parser ignores DATA/body entirely (see "Pre-existing gap" note — that's about CONTINUATION, not DATA); emitting 9-byte DATA prefixes would flood the ring on uploads.
- Cap `frame_length` (e.g. default max frame 16KB or `MAX_PAYLOAD_SIZE`) so a random 9-byte blob cannot pin a huge `remaining`.
- **Map type: `BPF_MAP_TYPE_LRU_HASH`**, matching `active_l7_requests`/`active_connections` (`ebpftracer/ebpf/tcp/state.c`) — not a plain `BPF_HASH`. This is the primary defense against leaks (killed processes, fd reuse, peers that never `close()` cleanly); do not rely on explicit deletion alone.
- **Explicit cleanup on *both* ends of a connection's lifecycle — `sys_exit_connect` (outbound) and `handle_accept_exit` (inbound) — not a "connection close" hook.** Checked directly in `tcp/state.c`: `active_l7_requests` is **not** deleted in `sys_enter_close` (that hook only deletes `active_connections`) and **not** deleted in `handle_accept_exit` (inbound `accept()`) at all — inbound relies entirely on LRU eviction today for `active_l7_requests`. The only explicit deletion `active_l7_requests` gets is in `sys_exit_connect` (outbound `connect()` return), which proactively clears both `is_tls` variants for the fd before a new outbound request cycle starts, guarding against a recycled fd inheriting stale state.

  `http2_progress` follows the *outbound* half of that pattern for symmetry (add deletion of all four `{is_tls, method}` combinations in `sys_exit_connect`), but **goes one step further on the inbound side instead of copying `active_l7_requests`'s gap**: `handle_accept_exit` already receives the brand-new fd (`ret`) at the exact moment the kernel hands it out for a fresh inbound connection — the same kind of "this fd is definitely starting a new lifecycle now" moment `sys_exit_connect` is for outbound. Deleting all four `{is_tls, method}` `http2_progress` entries for that fd there, before any `read`/`write` on it, closes the inbound fd-reuse window entirely (see Problem section) instead of leaving it to `BPF_MAP_TYPE_LRU_HASH` alone. This is a deliberate deviation from "mirror `active_l7_requests` exactly" — `active_l7_requests` happens to have this same gap too, but nothing prevents fixing it here since the hook already exists and the delete is unconditionally safe (a freshly-`accept()`ed fd cannot have a legitimate pending HTTP/2 continuation yet). `BPF_MAP_TYPE_LRU_HASH` remains the backstop for everything else (e.g. a connection that never sends another byte after leaving a dangling entry).

**Userspace:** leftover buffer on `Http2Parser` (client leftover and server leftover separately — two HPACK decoders already), plus CONTINUATION support. `Parse` prepends leftover, walks complete frames, keeps an incomplete tail. The frame loop treats `http2.FrameContinuation` the same as `http2.FrameHeaders` (decode into the same `stream_id`'s pending request/status instead of skipping it) — Go's `hpack.Decoder.Write` is designed for exactly this kind of incremental, cross-call feeding, so no extra buffering is needed as long as CONTINUATION bytes reach the same decoder via the same `stream_id` lookup. `feedHTTP2` already calls `Parse` chunk-by-chunk on one parser instance, so tests pick this up.

**Event volume:** about one extra event per stdlib ingress HEADERS (the 9-byte prefix), not hundreds per GET. Writes stay one event per frame.

**New invariant: up to 2 events per `handle_request`/`handle_response` call, not always 1.** Today, every branch in `handle_request`/`handle_response` calls `send_event` at most once and returns immediately — 1 syscall/uprobe call never produces more than 1 event. The Task 2 fall-through breaks that: consuming a pending `remaining` continuation is one `send_event`, and (if `size > copied`) falling through into a fresh classification pass for the rest of the buffer can produce a second, independent `send_event` — e.g. finishing an in-flight HEADERS frame *and* recognizing a brand-new frame packed into the same read/write. This is capped at exactly **2**, never more, regardless of how many frames are packed into that trailing portion: the fall-through's classification pass runs once, and (like every other call to `looks_like_http2_frame`) inspects only the *first* frame header in whatever's left — if it looks complete, the **entire** remainder (multiple complete frames included) ships as one blob in that second event, the same "one blob per buffer" behavior described earlier for ordinary multi-frame buffers; `Http2Parser`'s frame loop is what splits it into individual frames downstream, not the kernel. There is also only ever one pending continuation entry per `{pid,fd,is_tls,method}` at a time — either a `remaining` (known frame, partial body) or an `hdr_have` (unknown frame, partial header), never both — so there's never more than one continuation to resolve before that single fall-through pass, and the "at most 2 events" cap holds for the `hdr_have` path exactly as it does for `remaining` (see "stream_id not needed in the key" above). Implementation note for Task 2: reusing the single-slot `l7_event_heap` (`PERCPU_ARRAY`) for two sequential `send_event` calls in one program run is safe (`bpf_perf_event_output` copies synchronously), but every field (`protocol`, `method`, `payload_size`, etc.) must be freshly repopulated for the second send — do not assume leftover state from the first send is still correct.

### Rejected alternatives


| Approach                                              | Why not                                                                                                                                                                                                          |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Low-level test server with `Read(4096)`               | Masks the production `net/http` bug                                                                                                                                                                              |
| Userspace leftover only                               | eBPF never sends the 9-byte or HPACK chunks                                                                                                                                                                      |
| Kernel stitches full 8KB request                      | No `stream_id` / HPACK in BPF; ring blow-up                                                                                                                                                                      |
| Sticky “all reads on this fd are HTTP/2” forever      | Would emit DATA/Redis-misclassified traffic; leftover `remaining` is tighter                                                                                                                                     |
| Fields on `struct connection`                         | Possible, but a dedicated LRU keeps Redis sockets unchanged                                                                                                                                                      |
| Key without `method`/direction (`pid+fd+is_tls` only) | Request-read and response-write can be mid-frame concurrently on the same socket; they'd clobber each other's `remaining` and can desync HPACK                                                                   |
| `stream_id` in the progress-map key                   | Unnecessary: frame bytes are never interleaved within one direction, so at most one partial frame exists per `{pid,fd,is_tls,method}`; `stream_id` is already handled downstream by `Http2Parser.activeRequests` |
| Skip CONTINUATION support in this plan                | Same kernel code path (`http2_incomplete_headers`) has to special-case frame type anyway; deferring it leaves a known HPACK-desync bug unfixed for no extra cost avoided                                         |
| Always `return 0` right after consuming `remaining` bytes | Silently drops every byte after the completed frame whenever the buffer is longer than `remaining` — reintroduces the same class of bug this plan fixes, one level deeper |
| Deciding `remaining` from the header at offset 0 only | Misses a trailing incomplete HEADERS/CONTINUATION frame that comes after 1+ complete frames in the same buffer; worse than a normal drop, because the peer's next write's continuation bytes then fail the kernel's own classification and never even reach userspace's `leftover` |
| `http2_scan_trailing_incomplete` without a preface check | Misreads the 24-byte client preface's `'P','R','I',' '` bytes as a bogus frame header and aborts the scan immediately, losing `remaining` for a real incomplete frame that follows preface+SETTINGS in the same buffer — same failure class as the offset-0-only bug above, just triggered by the preface instead of complete frames |
| Deleting `http2_progress` on a "connection close" hook | No such hook cleans `active_l7_requests` (the map this is modeled on) either — `sys_enter_close` only touches `active_connections`. Inventing a close-time delete for `http2_progress` that doesn't mirror real, verified behavior of the map it's modeled on; use `BPF_MAP_TYPE_LRU_HASH` + the `sys_exit_connect`/`handle_accept_exit` piggyback instead |
| Leaving inbound `http2_progress` fd-reuse cleanup to LRU only, "because `active_l7_requests` does" | `active_l7_requests` having this gap is not a reason to copy it into `http2_progress` — `handle_accept_exit` already hands us the new fd at exactly the right moment (mirrors `sys_exit_connect` for outbound), and the delete is unconditionally safe there (a fresh `accept()` fd cannot have a legitimate pending continuation). Closing it costs a few `bpf_map_delete_elem` calls in a hook we already touch |
| Leaving "frame header itself split mid-syscall" permanently out of scope | Combined with the Task 2 Step 1 fall-through, this reproduces the exact "worse than a plain drop" failure Task 6/7 already fix for a trailing frame with a *complete* header — just one byte-offset deeper. Not meaningfully rarer than what Task 6/7 cover, so fixing those while leaving this unfixed would be an inconsistent scope cut; `hdr_have`/`hdr_buf` (Task 2 Step 1b, Task 8) closes it with the same bounded, self-healing precision as `remaining`, not a fuzzy fallback |
| A generic per-socket "sticky last-known-protocol" fallback for any unclassifiable buffer | Considered as a broader fix for this and similar gaps; rejected for this plan: unlike `hdr_have`/`remaining` (which only ever act once real byte-accounting is known), a blind "assume unchanged" fallback would mislabel fd-reuse traffic from an unrelated protocol as HTTP/2 and feed it into `Http2Parser`'s HPACK decoder — silent, connection-wide HPACK desync, worse than dropping the event. Also cross-cutting (every protocol's classifier, not just HTTP/2), so out of scope for this plan even if pursued elsewhere |
| Assume production/test writes are always "full" and skip the short-write dependency | `write()`/`crypto/tls.(*Conn).Write` are legally allowed to accept fewer bytes than requested (non-blocking sockets, signal interruption, full send buffer) — exactly the backpressure conditions where accurate tracing matters most. Ignoring this would let `http2_progress` compute `remaining` against a `size` the kernel never actually accepted, corrupting the *next* write's classification. Already scoped as its own plan (`2026-09-16-write-syscall-short-write-tracking.md`) rather than duplicated here, but it's a real prerequisite, not an optional nice-to-have — see Global Constraints |


---



## File map


| File                          | Role                                                                                                    |
| ----------------------------- | ------------------------------------------------------------------------------------------------------- |
| `ebpftracer/ebpf/l7/http2.c`  | Incomplete HEADERS/CONTINUATION detection; helpers to parse length/type                                 |
| `ebpftracer/ebpf/l7/l7.c`     | Map lookup (keyed incl. direction/`method`) before `looks_like`; `send_event` for continuation; cleanup |
| `ebpftracer/ebpf/tcp/state.c` | Delete leftover map entries (both `method` variants) on connection close, same as `active_l7_requests`  |
| `ebpftracer/ebpf.go`          | Regenerated BPF object                                                                                  |
| `ebpftracer/l7/http2.go`      | Parser leftover + CONTINUATION frame handling                                                           |
| `ebpftracer/l7/http2_test.go` | Split HEADERS 9+payload unit tests; HEADERS+CONTINUATION unit tests                                     |
| `ebpftracer/tracer_test.go`   | Keep stdlib TLS client/server; ingress must pass                                                        |


`tracer.go` / `gotls.c` / `containers` stay as-is: they already pass opaque payloads into `Http2Parser`.

---



### Task 1: Parser leftover (userspace)

**Files:**

- Modify: `ebpftracer/l7/http2.go`
- Test: `ebpftracer/l7/http2_test.go`

**Interfaces:**

- Consumes: existing `Parse(method Method, payload []byte, kernelTime uint64) []Http2Request`
- Produces: same signature; parser holds `clientLeftover` / `serverLeftover []byte`

- [ ] **Step 1: Write a failing unit test** that feeds a complete HEADERS frame split as `[9-byte header][HPACK payload]` on sequential `Parse` calls (same parser), then server `:status 200`, and expects `GET /users` + 200.

```go
func TestHttp2ParserSplitHeadersFrame(t *testing.T) {
	// build the same GET /users client buffer as TestHttp2ParserGetUsers
	// skip preface for this case; split the HEADERS frame at offset 9
	p := NewHttp2Parser()
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, headers[:9], 1))
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, headers[9:], 1))
	got := p.Parse(MethodHttp2ServerFrames, server.Bytes(), 2)
	require.Equal(t, "GET", got[0].Method)
	require.Equal(t, "/users", got[0].Path)
	require.Equal(t, Status(http.StatusOK), got[0].Status)
}
```

- [ ] **Step 2: Run the test (expect fail)**

Run: `go test ./ebpftracer/l7 -run TestHttp2ParserSplitHeadersFrame -count=1`  
(On macOS this package is unix-friendly; `http2.go` is not linux-only.)

Expected: empty `got` or missing method/path (truncated frame skipped).

- [ ] **Step 3: Implement leftover in** `Http2Parser.Parse`

At the start of `Parse`, if leftover for this `method` is non-empty, `payload = append(leftover, payload...)`. After the frame loop, if `offset < len(payload)`, save `payload[offset:]` as leftover (cap it, e.g. 16KB). When a full frame is consumed, leftover for that side clears past that frame.

- [ ] **Step 4: Re-run unit tests**

Run: `go test ./ebpftracer/l7 -count=1`  
Expected: PASS including the new split test and `TestHttp2ParserGetUsers`.

- [ ] **Step 5: Write a failing unit test for CONTINUATION** — a HEADERS frame with `END_HEADERS` **not** set, followed by a CONTINUATION frame with `END_HEADERS` set, both for the same `stream_id`, split into separate `Parse` calls (simulating separate perf events).

```go
func TestHttp2ParserHeadersWithContinuation(t *testing.T) {
	// build GET /users HPACK, split so it doesn't fit one frame:
	// frame 1: HEADERS, flags without END_HEADERS, partial HPACK
	// frame 2: CONTINUATION, flags with END_HEADERS, rest of HPACK
	p := NewHttp2Parser()
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, headersFrame, 1))
	require.Empty(t, p.Parse(MethodHttp2ClientFrames, continuationFrame, 1))
	got := p.Parse(MethodHttp2ServerFrames, server.Bytes(), 2)
	require.Equal(t, "GET", got[0].Method)
	require.Equal(t, "/users", got[0].Path)
}
```

Expected (before fix): `got` is empty or missing `Method`/`Path` — today's `Parse` skips `http2.FrameContinuation` (`h.Type != http2.FrameHeaders` branch), so the second half of the HPACK block never reaches the decoder.

- [ ] **Step 6: Implement CONTINUATION support in** `Http2Parser.Parse`

Change the frame-type check so `http2.FrameContinuation` is treated like `http2.FrameHeaders` (decode its bytes with the same `decoder`, looked up by the same `h.StreamId`, using the existing `req`/`statuses` entry instead of creating a new one). Do not gate this on the `END_HEADERS` flag — `hpack.Decoder.Write` already supports being fed HPACK bytes incrementally across multiple calls, which is exactly the HEADERS+CONTINUATION(+CONTINUATION...) case. Leave DATA and all other frame types skipped as today.

- [ ] **Step 7: Re-run unit tests**

Run: `go test ./ebpftracer/l7 -count=1`  
Expected: PASS including `TestHttp2ParserHeadersWithContinuation`, `TestHttp2ParserSplitHeadersFrame`, and `TestHttp2ParserGetUsers`.

---



### Task 2: BPF leftover map + incomplete HEADERS/CONTINUATION emit

**Files:**

- Modify: `ebpftracer/ebpf/l7/http2.c`
- Modify: `ebpftracer/ebpf/l7/l7.c`
- Modify: `ebpftracer/ebpf/tcp/state.c`:
  - `sys_exit_connect`: delete all four `{is_tls, method}` `http2_progress` entries for the fd, same spot and same reasoning as the existing `active_l7_requests` deletion there — **not** a "connection close" hook, which doesn't clean `active_l7_requests` either.
  - `handle_accept_exit`: delete the same four `{is_tls, method}` `http2_progress` entries for the newly-`accept()`ed fd (`ret`), **before** `active_connections` is updated. This closes the inbound fd-reuse window that `active_l7_requests` leaves open (see "Chosen solution" and Problem section's fd-reuse note) — a deliberate improvement over the map this design is modeled on, not a mirror of its gap.
- Regenerate: `ebpftracer/ebpf.go` via `ebpftracer/Makefile`

**Interfaces:**

- Consumes: `looks_like_http2_frame` (**modified** — see Step 0 — to also accept a well-typed `HEADERS`/`CONTINUATION` header that doesn't fit the buffer, not just complete frames/preface; still a first-frame-only check otherwise), `send_event`, `connection_id`
- Produces: map `http2_frame_progress` (name can match existing snake_case maps); new helper `http2_scan_trailing_incomplete` (bounded walk, see Step 2)

Map sketch:

```c
struct http2_progress_key {
    __u64 fd;
    __u32 pid;
    __u16 is_tls;
    __u8  method;  // METHOD_HTTP2_CLIENT_FRAMES or METHOD_HTTP2_SERVER_FRAMES —
                   // REQUIRED so an in-flight request read and an in-flight
                   // response write on the same fd/is_tls never collide.
    __u8  pad;
};

struct http2_progress {
    __u32 remaining;  // bytes still needed for current frame BODY (0 when unused)
    __u8 frame_type;  // HTTP2_HEADERS or HTTP2_CONTINUATION only
    __u8 hdr_have;    // 0 when unused; 1..8 when the frame HEADER itself is split mid-syscall
    __u8 hdr_buf[8];  // raw partial header bytes when hdr_have > 0
    __u8 pad;
    // Exactly one of {remaining > 0, hdr_have > 0} is true at a time for a given key —
    // see "A trailing frame's own 9-byte header can itself be split" in Problem/Chosen solution.
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); // matches active_l7_requests/active_connections — see "Chosen solution"
    __uint(key_size, sizeof(struct http2_progress_key));
    __uint(value_size, sizeof(struct http2_progress));
    __uint(max_entries, 32768); // same order of magnitude as active_l7_requests
} http2_progress SEC(".maps");
```

- [ ] **Step 0: Fix `looks_like_http2_frame` to accept an incomplete-but-well-typed `HEADERS`/`CONTINUATION` header**

Without this, nothing else in this task ever runs on the plan's own motivating input (see Problem section, "`looks_like_http2_frame` rejects this exact example too"): a bare 9-byte header whose declared `length` exceeds `size` is rejected outright today, so `handle_request`/`handle_response` never enter the HTTP/2 branch, never `send_event`, and never get a chance to populate the progress map for it.

In `ebpftracer/ebpf/l7/http2.c`:

```c
static __always_inline
int looks_like_http2_frame(char *buf, __u64 size, __u8 method) {
    if (size < 9) {
        return is_client_preface(buf, size, method);
    }
    __u32 frame_length;
    bpf_read(buf, frame_length);
    frame_length = bpf_htonl(frame_length) >> 8;
    __u8 frame_type;
    bpf_read(buf + 3, frame_type);
    if (frame_length + 9 > size) {
        // Doesn't fit — but a well-typed HEADERS/CONTINUATION header that just needs more
        // bytes is not garbage, it's exactly the split-read case this plan exists to fix.
        // Only fall back to the preface check for anything else (DATA/SETTINGS/garbage).
        if (frame_type == HTTP2_HEADERS || frame_type == HTTP2_CONTINUATION) {
            return 1;
        }
        return is_client_preface(buf, size, method);
    }
    if (frame_type > 0x9) {
        return is_client_preface(buf, size, method);
    }
    return 1;
}
```

Behavior unchanged for: complete frames of any type (still `return 1`), preface (still routed through `is_client_preface`), and genuine garbage that doesn't fit and isn't `HEADERS`/`CONTINUATION` (still rejected, unless it happens to be a preface). The only new `return 1` is exactly the case Task 2 needs: incomplete `HEADERS`/`CONTINUATION` at offset 0.

- [ ] **Step 1: In** `handle_request` **/** `handle_response`**, before protocol detection**

**Placement, precisely:** at the very top of `handle_request`/`handle_response`, **before** the existing `pending`/MySQL-partial-header block (`ebpftracer/ebpf/l7/l7.c` lines ~299–304 in `handle_request`: the `active_l7_requests` lookup that clears a stale `PROTOCOL_UNKNOWN`+`partial==1` entry). That block is about a *different* map (`active_l7_requests`) and a *different* kind of partial state (MySQL's 4-byte length header, not HTTP/2 frames); the `http2_progress` lookup must not be interleaved with it or gated behind it — do the `http2_progress` lookup first, handle it fully (including the Step-1-below fall-through decision), and only fall into the existing `pending`/protocol-detection code below if `http2_progress` had no entry (or if it did and there were leftover bytes after consuming `remaining`, per the fall-through below).

Look up `http2_progress` with `method` set to `METHOD_HTTP2_CLIENT_FRAMES` in `handle_request` and `METHOD_HTTP2_SERVER_FRAMES` in `handle_response` (matching the `method` each function already passes to `send_event`/`looks_like_http2_frame`). If `remaining > 0`: `copied = MIN(size, remaining)`, `COPY_PAYLOAD` / `send_event` with that method for `copied` bytes, `remaining -= copied`, delete the map entry when `remaining` reaches 0. Skip Redis/HTTP1 classifiers **for the `copied` bytes only**. Do **not** share one lookup between the two functions — each has its own direction and must use its own `method` value in the key.

**Do not `return 0` unconditionally after this.** If `size > copied` (i.e. `size` was bigger than what was needed to finish the frame), set `payload = payload + copied; size = size - copied;` and let execution **continue** into the normal classification chain below (the same `is_http_request(payload)`/`looks_like_http2_frame(...)`/etc. `else if` chain `handle_request`/`handle_response` already run for a fresh buffer) instead of returning. Only `return 0` early when `size <= copied` (buffer fully consumed by the continuation). This is what makes "leftover bytes after finishing the in-flight frame" (see Problem section) work — the tail gets a normal classification pass, including running `http2_scan_trailing_incomplete` (Step 2) on it to correctly decide whether *that* tail itself ends incomplete.

- [ ] **Step 1b: Handle a partial frame *header* (`hdr_have`), checked before `remaining`**

`remaining > 0` and `hdr_have > 0` are mutually exclusive for a given key — check `hdr_have` first. If `hdr_have > 0`: let `need = 9 - hdr_have`.

- If `size < need`: the header is *still* incomplete even with these new bytes. Append them to `hdr_buf` (`hdr_buf[hdr_have + i] = payload[i]` for `i` in `[0, size)`, fully unrolled — max 8 bytes, no dynamic loop needed), `hdr_have += size`, store, `return 0`. (This can repeat across more than two calls if a header is split into 3+ tiny pieces — each call just grows `hdr_have` a little more.)
- Otherwise: splice `hdr_buf[0:hdr_have]` and `payload[0:need]` into one 9-byte header on the stack, and parse `length`/`type` from it — the exact same field layout `looks_like_http2_frame`/`http2_scan_trailing_incomplete` already use. If `type` is not `HTTP2_HEADERS`/`HTTP2_CONTINUATION`: clear `hdr_have`/`hdr_buf` (delete the map entry) and fall through to normal classification for the *entire* `payload` (the assembled header turned out to be something we don't track, e.g. DATA/SETTINGS — same "don't buffer DATA" rule as everywhere else). Otherwise: this collapses into exactly the `remaining > 0` logic above, just computed instead of looked up — `body_available = size - need`, `copied_body = MIN(body_available, length)`, `send_event` for `need + copied_body` bytes (the header-completing bytes plus whatever body fits), set `remaining = length - copied_body` (and `frame_type`), clear `hdr_have`/`hdr_buf`, and — if `size > need + copied_body` — fall through with `payload = payload + need + copied_body; size = size - need - copied_body;` into normal classification (including a fresh `http2_scan_trailing_incomplete` pass) for whatever is left, exactly as Step 1 already does for the `remaining` case.

This keeps the "at most 2 events per call" invariant: whichever sub-state (`remaining` or `hdr_have`) was pending, there is still only one fall-through classification pass per call.

- [ ] **Step 2: Replace the offset-0-only incomplete check with a bounded trailing-frame scan**

`looks_like_http2_frame` (as fixed in Step 0) still only looks at the *front* of the buffer to decide "is this HTTP/2-shaped at all" (preface, a complete frame, or now also an incomplete-but-well-typed `HEADERS`/`CONTINUATION` header) — that gating decision doesn't walk the whole buffer. What changes here is how `remaining`/`hdr_have` get set once we've decided to `send_event` these bytes as HTTP/2: **do not** derive them from the header at offset 0 alone (see Problem section — that silently misses a trailing incomplete frame after 1+ complete ones). Add `http2_scan_trailing_incomplete(buf, size, method, &remaining, &frame_type, &hdr_have, hdr_buf)`. It takes `method` because — like `looks_like_http2_frame` — it must skip a leading 24-byte client preface before it starts treating bytes as frame headers; without this, a buffer containing preface+SETTINGS+incomplete-HEADERS in one syscall would have its preface bytes misread as a bogus frame header (`type = 0x20 > 0x9`) and the scan would abort immediately, losing `remaining` for the real incomplete frame — see Problem section, "The trailing-frame scan also has to skip the client preface". The two new output params (`hdr_have`, `hdr_buf`) are the fix for "A trailing frame's own 9-byte header can itself be split mid-syscall":

```c
static inline __attribute__((__always_inline__))
int http2_scan_trailing_incomplete(char *buf, __u64 size, __u8 method, __u32 *remaining, __u8 *frame_type,
                                    __u8 *hdr_have, __u8 hdr_buf[8]) {
    __u64 offset = 0;
    // Skip the client preface if present, same check `looks_like_http2_frame` uses — otherwise
    // the frame walk below misreads "PRI * " as a garbage frame header and bails immediately.
    if (is_client_preface(buf, size, method)) {
        offset = 24;
    }
    #pragma unroll
    for (int i = 0; i < MAX_PAYLOAD_SIZE / 9; i++) {
        if (offset >= size) {
            return 0; // buffer ends cleanly on a frame boundary — nothing to track
        }
        if (size - offset < 9) {
            // Header itself split mid-syscall — no longer out-of-scope (see Problem section,
            // "A trailing frame's own 9-byte header can itself be split"): save the raw bytes
            // so the next read/write on this key can splice them with its own front bytes and
            // finish reading the header (Task 2, Step 1b). Bounded to <=8 bytes, unrolled.
            *hdr_have = (__u8)(size - offset);
            #pragma unroll
            for (int j = 0; j < 8; j++) {
                if (j < *hdr_have) {
                    bpf_read(buf + offset + j, hdr_buf[j]);
                }
            }
            return 0;
        }
        __u32 length;
        bpf_read(buf + offset, length);
        length = bpf_htonl(length) >> 8;
        __u8 type;
        bpf_read(buf + offset + 3, type);
        if (type > 0x9 || length > MAX_HTTP2_FRAME_LEN) {
            return 0; // not a frame we understand at this offset — bail out safely, don't track garbage
        }
        if (length + 9 <= size - offset) {
            offset += 9 + length; // this frame is complete; check whatever comes after it
            continue;
        }
        // trailing frame at `offset` doesn't fully fit — decide whether to track it
        if (type == HTTP2_HEADERS || type == HTTP2_CONTINUATION) {
            *remaining = length + 9 - (size - offset);
            *frame_type = type;
        }
        return 0;
    }
    return 0; // exhausted the bounded loop (MAX_PAYLOAD_SIZE/9 frames) without a trailing incomplete one
}
```

- The preface skip only ever applies once, at `offset == 0`; `is_client_preface` itself already gates on `method == METHOD_HTTP2_CLIENT_FRAMES`, so calling it unconditionally here (including from `handle_response`/`METHOD_HTTP2_SERVER_FRAMES`, and from the Step 1 fall-through tail, which is never actually a preface in practice) is safe — it simply returns 0 and `offset` stays 0.
- `size - offset < 9` no longer means "give up" — it now means "save these 0–8 trailing bytes into `*hdr_have`/`hdr_buf` so Step 1b can splice them with the next call's front bytes." This replaces the previously "accepted, out-of-scope" limitation (see Problem section, "A trailing frame's own 9-byte header can itself be split mid-syscall").
- `0 < length <= MAX_HTTP2_FRAME_LEN` caps a random/garbage frame from pinning a huge `remaining` (same cap as before, just applied per-frame during the walk instead of once at offset 0).
- Only `HEADERS`/`CONTINUATION` at the **trailing** position start progress — DATA/SETTINGS/etc. at the front are simply skipped over (`offset += 9 + length`) like any other complete frame; DATA/etc. that's itself the trailing incomplete one is *not* tracked, same "don't buffer DATA" rule as before. This is unchanged for the `remaining` path; `hdr_have` has no `frame_type` yet to filter on (that's decided in Step 1b once the header is complete), so it's tracked unconditionally.

Call this **after** deciding to `send_event` — both for a fresh buffer (right after the existing `looks_like_http2_frame` check passes) and for the Step 1 fall-through tail — and `bpf_map_update_elem` the progress map keyed with the caller's `method` whenever it returns a non-zero `remaining` **or** a non-zero `hdr_have`; delete/skip the update otherwise.

- [ ] **Step 2b: Close the inbound fd-reuse window in `handle_accept_exit`**

In `ebpftracer/ebpf/tcp/state.c`, at the top of `handle_accept_exit` (before the existing `active_connections` update, after the `ret < 0` guard), delete all four `{is_tls, method}` `http2_progress` entries for `cid.fd`/`cid.pid`:

```c
struct http2_progress_key k = {.fd = cid.fd, .pid = cid.pid};
k.is_tls = 0; k.method = METHOD_HTTP2_CLIENT_FRAMES; bpf_map_delete_elem(&http2_progress, &k);
k.method = METHOD_HTTP2_SERVER_FRAMES;                bpf_map_delete_elem(&http2_progress, &k);
k.is_tls = 1; k.method = METHOD_HTTP2_CLIENT_FRAMES;  bpf_map_delete_elem(&http2_progress, &k);
k.method = METHOD_HTTP2_SERVER_FRAMES;                bpf_map_delete_elem(&http2_progress, &k);
```

Zero-initialize `k` fully (including `pad`) before use — see the padding/map-key note surfaced while reviewing `http2_progress_key`. This is unconditionally safe: a fd that the kernel just handed back from `accept()`/`accept4()` cannot have a legitimate in-flight HTTP/2 continuation yet, so there is nothing this delete could incorrectly discard. Mirrors the existing `sys_exit_connect` deletion for outbound (Step 1's map sketch), applied to the other half of a connection's lifecycle — closing the "Residual fd-reuse risk on inbound sockets" gap instead of just documenting it (see Problem section and Self-review).

- [ ] **Step 3: Rebuild BPF blob**

Run from `ebpftracer/`: `make build` (docker clang → `ebpf.go`).

- [ ] **Step 4: Keep existing h2c tests green**

Run: `make docker-test DOCKER_TEST_ARGS='-count=1 -timeout 10m -v github.com/coroot/coroot-node-agent/ebpftracer -run "TestHttp2Ingress|TestHttp2Egress"'`  
Expected: PASS (complete frames still take the old path).

---



### Task 3: Stdlib TLS ingress VM test

**Files:**

- Modify: `ebpftracer/tracer_test.go` (already has stdlib `http2TlsServerSrc` / `http2TlsClientSrc`; keep them)

**Interfaces:**

- Consumes: `AttachGoTlsUprobes`, ready-file client, `waitHTTP2` / `feedHTTP2`
- Produces: `TestHttp2TlsIngressEvents` PASS with stdlib server

- [ ] **Step 1: Confirm tests still use stdlib** (`http.Server.ServeTLS`, `http.Client` + `ForceAttemptHTTP2`). Do not restore the custom Framer server.
- [ ] **Step 2: Run TLS tests**

Run: `make docker-test DOCKER_TEST_ARGS='-count=1 -timeout 10m -v github.com/coroot/coroot-node-agent/ebpftracer -run TestHttp2Tls'`

Expected:

- `TestHttp2TlsEgressEvents` PASS (already did).
- `TestHttp2TlsIngressEvents` PASS: `ProtocolHTTP2`, `IsInbound=true`, parser sees `GET /users` + 200.

If ingress still fails, dump `waitHTTP2` `seen` lines: you should now see a 9-byte `http2_client_frames` HEADERS prefix and a following HPACK chunk on the **server** PID, not only SETTINGS/preface.

---

### Task 4: Split-write regression test (plaintext h2c)

**Why:** Task 2's fix lives in `handle_request`/`handle_response`, shared by both the read path (`trace_exit_read`) and the write path (`trace_enter_write`). Tasks 1–3 only exercise a split caused by a **read** (`tls.Conn.Read(9)` then `Read(14)`). Nothing proves the same fix also reassembles a HEADERS frame that a **writer** splits across two `write()` calls (e.g. a non-buffering HTTP/2 client/library that writes the 9-byte frame header and the HPACK payload separately, or a short write on a small `SO_SNDBUF`). This is plaintext h2c, not TLS: the split has to be a deliberate two-`write()` client, and stdlib's `http2.Framer` always buffers a whole frame into one `Write` (`endWrite`), so it cannot be used to reproduce this — that is different from the Task 3 constraint (which bans a custom *reader* to avoid masking the real `net/http` server bug); here a custom *writer* is the only way to exercise this specific, already-legal-per-spec code path.

**Files:**
- Modify: `ebpftracer/tracer_test.go` (new minimal h2c client, no `golang.org/x/net/http2` Transport)

**Interfaces:**
- Consumes: `startHTTP2UsersServer` (existing plaintext h2c server), `waitHTTP2`
- Produces: `TestHttp2SplitWriteIngressEvents` PASS

- [ ] **Step 1: Write a failing test.** Add a minimal Go program (`http2SplitWriteClientSrc`, built via `buildHTTP2Prog`) that:
  1. Dials the server with plain `net.Dial("tcp", addr)` (h2c, no TLS, no `http2.Transport`).
  2. Writes the client preface (`conn.Write([]byte(http2.ClientPreface))`) and an empty SETTINGS frame in one `Write`.
  3. Builds a HEADERS frame for `GET /users` (same bytes as the existing h2c HEADERS test fixtures) and sends it as **two separate `conn.Write()` calls**: first the 9-byte frame header, then the HPACK payload — mirroring exactly the split this plan already handles on the read side, just from the write end.

```go
func TestHttp2SplitWriteIngressEvents(t *testing.T) {
	skipIfNotVM(t)
	getEvent, stop := runTracer(t, false)
	defer stop()

	serverPid, addr, stopServer := startHTTP2UsersServer(t)
	defer stopServer()

	clientBin := buildHTTP2Prog(t, "http2splitwriteclient", http2SplitWriteClientSrc)
	cmd := exec.Command(clientBin, addr)
	require.NoError(t, cmd.Run())

	got := waitHTTP2(t, getEvent, serverPid, true)
	require.Equal(t, l7.ProtocolHTTP2, got.L7Request.Protocol)
	require.True(t, got.L7Request.IsInbound)
}
```

- [ ] **Step 2: Run the test (expect fail/timeout) before Task 2 is implemented**

Run: `make docker-test DOCKER_TEST_ARGS='-count=1 -timeout 10m -v github.com/coroot/coroot-node-agent/ebpftracer -run TestHttp2SplitWriteIngressEvents'`  
Expected: timeout — the 9-byte write is dropped by `looks_like_http2_frame`, the HPACK-only write looks like garbage, same failure mode as the read-side bug.

- [ ] **Step 3: Re-run after Task 2's kernel fix lands**

Same command. Expected: PASS — the `http2_progress` map (keyed by `pid+fd+is_tls+method`, `method=METHOD_HTTP2_CLIENT_FRAMES` here since the client is writing a request) reassembles the two writes the same way it reassembles the two TLS reads in Task 3.

---

### Task 5: Leftover-after-continuation regression test (plaintext h2c)

**Why:** Task 2's fix must fall through to normal classification for any bytes *after* the ones needed to finish the in-flight frame (see Problem section, "A single read/write can contain both the rest of an in-flight frame *and* one or more new frames"). Nothing in Tasks 1–4 exercises a buffer that is `remaining`-bytes-to-finish plus one or more additional frames in the *same* call. This can't be forced against `net/http`'s server or client framer (both request exactly the bytes they need per `ReadFull`, never more), so this test deliberately uses a custom, non-`net/http` plaintext h2c **server** that reads with one generic, oversized `conn.Read(4096)` per call instead of precise `ReadFull` sizing. That's the same pattern the Problem section rejects for Task 3 (it would mask the real `net/http` ingress bug) — legitimate here because this test's target is the kernel's generic buffer-boundary handling, not `net/http`'s behavior, and Task 3 already covers the precise-read case.

**Files:**
- Modify: `ebpftracer/tracer_test.go` (new minimal h2c server using `conn.Read(4096)`, not `golang.org/x/net/http2.Server`)

**Interfaces:**
- Consumes: a raw h2c client that writes the client preface, then a HEADERS frame for `GET /users` split so that the first `write()` (or a small artificial `SO_SNDBUF`-forced short read on the server) leaves `remaining > 0`, immediately followed — in a buffer the server's *next* `Read(4096)` will scoop up together — by a complete SETTINGS frame and a second complete HEADERS frame (stream 3, e.g. `POST /orders`)
- Produces: `TestHttp2LeftoverPlusNewFrameIngressEvents` PASS, asserting **both** stream 1 (`GET /users`) and stream 3 (`POST /orders`) are eventually observed — proving the tail after the continuation wasn't dropped

- [ ] **Step 1: Write a failing test** with the custom big-buffer h2c server and a client that manufactures the byte layout described above (send header-only write, sleep briefly so the server's read returns just that, then send the rest of HEADERS-1 immediately followed by SETTINGS + HEADERS-3 in one write so they land in the server's next single `Read(4096)`).

- [ ] **Step 2: Run before the Task 2 fall-through fix**

Expected: `GET /users` is eventually seen (progress map completes it), but `POST /orders` (stream 3) is **never** observed — the bytes after `remaining` were silently dropped by the early `return 0`.

- [ ] **Step 3: Implement the fall-through** (the "Do not `return 0` unconditionally" step in Task 2).

- [ ] **Step 4: Re-run** — expect both `GET /users` and `POST /orders` observed.

---



### Task 6: Trailing-incomplete-frame regression test (plaintext h2c)

**Rationale:** Task 5 proves the fall-through doesn't drop bytes *after* a completed continuation. This task proves the opposite ordering — `[complete frame A][complete frame B][incomplete frame C — header only]` in a single buffer — is still tracked correctly, i.e. `remaining` gets set for C even though A and B were complete and came first. Without the Step 2 fix (offset-0-only check), this buffer looks entirely "complete" to the kernel, no progress entry is created for C, and C's continuation arrives on the wire with no frame header in front of it — the kernel's classifier rejects it as garbage and the event never reaches userspace at all (worse than a plain drop; see Problem section).

**Files:**
- Add test: `ebpftracer/tracer_test.go`

**Interfaces:**
- Consumes: a raw h2c client that writes the preface, then in **one** `write()` (so the server's single `Read(4096)` sees it as one buffer): a complete SETTINGS frame (A), a complete HEADERS frame for stream 1 `GET /users` (B), and only the 9-byte header + partial HPACK of a HEADERS frame for stream 3 `POST /orders` (C, header claims more `length` than is actually present in this write) — then, in a **second**, later `write()`, the rest of C's HPACK bytes (no frame header this time, matching what a real split write looks like)
- Produces: `TestHttp2TrailingIncompleteIngressEvents` PASS, asserting **both** `GET /users` (stream 1) and `POST /orders` (stream 3) are eventually observed

- [ ] **Step 1: Write a failing test** with the byte layout above (SETTINGS + complete HEADERS-1 + header-only HEADERS-3 in write #1; rest of HEADERS-3's HPACK in write #2).

- [ ] **Step 2: Run before the Step 2 fix (offset-0-only `http2_incomplete_headers`)**

Expected: `GET /users` (stream 1) is observed (it's the frame the old offset-0 check inspects and finds complete), but `POST /orders` (stream 3) is **never** observed — no `remaining` was set for C, so its continuation in write #2 fails classification and is dropped.

- [ ] **Step 3: Implement `http2_scan_trailing_incomplete`** (Task 2, Step 2) and wire it into both the fresh-buffer path and the Task 2 Step 1 fall-through tail.

- [ ] **Step 4: Re-run** — expect both `GET /users` and `POST /orders` observed.

---



### Task 7: Preface-plus-incomplete-frame regression test (plaintext h2c)

**Rationale:** Task 6 proves the scan finds a trailing incomplete frame after 1+ *complete frames*. This task proves it also works when the buffer starts with the 24-byte **client preface** instead of a frame header — a case `http2_scan_trailing_incomplete` gets wrong unless it explicitly skips the preface first (see Problem section, "The trailing-frame scan also has to skip the client preface"). Without that fix, the scan misreads `'P','R','I',' '` as a bogus frame header (`type = 0x20 > 0x9`) and aborts immediately, so no `remaining` gets set for a genuinely incomplete HEADERS frame that follows the preface+SETTINGS in the same `write()` — the same "worse than a plain drop" failure mode as Task 6, triggered by a different byte pattern at offset 0.

**Files:**
- Add test: `ebpftracer/tracer_test.go`

**Interfaces:**
- Consumes: a raw h2c client that sends, in **one** `write()`: the 24-byte client preface, a complete SETTINGS frame, and only the 9-byte header + partial HPACK of a HEADERS frame for stream 1 `GET /users` (header claims more `length` than is actually present) — then, in a **second**, later `write()`, the rest of that HEADERS frame's HPACK bytes (no frame header this time)
- Produces: `TestHttp2PrefacePlusIncompleteIngressEvents` PASS, asserting `GET /users` (stream 1) is eventually observed

- [ ] **Step 1: Write a failing test** with the byte layout above (preface + complete SETTINGS + header-only HEADERS-1 in write #1; rest of HEADERS-1's HPACK in write #2).

- [ ] **Step 2: Run before `http2_scan_trailing_incomplete` skips the preface**

Expected: timeout — `looks_like_http2_frame` classifies the buffer as HTTP/2 via `is_client_preface`, the whole thing ships as one event, but the scan (reading raw bytes from offset 0) aborts on the preface's `'P','R','I',' '` bytes before ever reaching the incomplete HEADERS frame; no `remaining` is set, so write #2's continuation fails classification and is dropped.

- [ ] **Step 3: Implement the preface skip** in `http2_scan_trailing_incomplete` (Task 2, Step 2: check `is_client_preface(buf, size, method)` and start the walk at `offset = 24` when it matches).

- [ ] **Step 4: Re-run** — expect `GET /users` observed.

---

### Task 8: Split frame-header regression test (plaintext h2c)

**Rationale:** Tasks 6 and 7 prove `http2_scan_trailing_incomplete` correctly tracks a trailing frame that has a *complete* 9-byte header but a short body. This task proves the harder case from the Problem section ("A trailing frame's own 9-byte header can itself be split mid-syscall"): the buffer ends with **fewer than 9 bytes** of a brand-new frame's header — not enough to even read `length`/`type` from. Without Step 1b (`hdr_have`/`hdr_buf`), the scan bails out on those trailing bytes with nothing tracked, and the new frame's continuation — which arrives on the wire with no header in front of it, since the header itself was split across two events — fails classification from scratch and is silently dropped. Same failure class as Task 6/7, one byte-offset deeper.

**Files:**
- Add test: `ebpftracer/tracer_test.go`

**Interfaces:**
- Consumes: a raw h2c client/server pair that manufactures, across two `write()` calls: write #1 = preface + SETTINGS + a complete HEADERS frame for stream 1 (`GET /users`) + one or more complete DATA frames + the **first 8 bytes** of a new HEADERS frame's 9-byte header for stream 3 (`POST /orders`); write #2 = the 1 remaining header byte, followed immediately by the full HPACK payload for stream 3
- Produces: `TestHttp2SplitFrameHeaderIngressEvents` PASS, asserting both `GET /users` (stream 1) and `POST /orders` (stream 3) are eventually observed

- [ ] **Step 1: Write a failing test** with the byte layout above.

- [ ] **Step 2: Run before Step 1b is implemented**

Run: `make docker-test DOCKER_TEST_ARGS='-count=1 -timeout 10m -v github.com/coroot/coroot-node-agent/ebpftracer -run TestHttp2SplitFrameHeaderIngressEvents'`  
Expected: `GET /users` observed, `POST /orders` **never** observed — the 8-byte tail makes `http2_scan_trailing_incomplete` bail out with nothing tracked (no `remaining`, no `hdr_have`), so write #2's bytes (1 header byte + HPACK, no complete 9-byte header at the front) fail `looks_like_http2_frame` and are dropped.

- [ ] **Step 3: Implement Step 1b** (`hdr_have`/`hdr_buf` fields in `http2_progress`; the header-splicing branch in `handle_request`/`handle_response`; and the corresponding change to `http2_scan_trailing_incomplete`'s `size - offset < 9` branch — see Task 2, Step 1b and Step 2).

- [ ] **Step 4: Re-run** — expect both `GET /users` and `POST /orders` observed.

---

## Self-review

1. **Spec coverage:** stdlib ingress gap, `looks_like_http2_frame` gating fix so the motivating example is even accepted as HTTP/2-shaped (Task 2 Step 0), 9+payload example, no kernel HTTP/2 flag today, BPF map for `remaining` keyed with a direction/`method` discriminator (no request/response collision), CONTINUATION frames handled in both kernel and parser (no HPACK desync on large headers), parser leftover, reject fake servers / 8KB kernel stitch / `stream_id`-in-key, DATA not leftover, write-side split (Task 4), leftover-plus-new-frame fall-through (Task 5), trailing-incomplete-frame detection (Task 6), preface-plus-incomplete-frame detection (Task 7), split frame-header detection (Task 8), cross-plan write-accuracy dependency called out explicitly (Global Constraints, point 13), tests. All have tasks.
2. **Read vs write symmetry:** Task 2's fix sits in `handle_request`/`handle_response`, which both the read and write trampolines call — Task 4 exists specifically to prove the write side isn't just "probably fine by construction."
3. **No silent data loss on the continuation path:** Task 2's fall-through (don't `return 0` when `size > copied`) plus Task 5's regression test close the "second, self-inflicted version of the same bug" gap found while reviewing the `remaining`-consumption step.
4. **`remaining` is derived from the *last* frame boundary, not the first:** the original Step 2 design (check only the header at offset 0) misses `[complete A][complete B][incomplete C]` — C's continuation then fails classification on arrival (no header in front of it) and is dropped *before* it can even reach userspace's `leftover`, which is strictly worse than the bug this plan fixes. `http2_scan_trailing_incomplete` (bounded walk, capped iterations) and Task 6's regression test close this gap; see Problem section "The incomplete-frame check only ever looks at the first frame in a buffer."
5. **The trailing-frame scan must skip the client preface, or it inherits the same "first bytes aren't a frame header" blind spot:** found while re-reviewing `http2_scan_trailing_incomplete` against the real `is_client_preface`/`looks_like_http2_frame` code in `http2.c` — a buffer starting with preface+SETTINGS+incomplete-HEADERS (one `write()`) would otherwise abort the scan on the preface bytes and drop the incomplete frame's continuation the same way Task 6's bug did, just triggered by different bytes at offset 0. Fixed by threading `method` into `http2_scan_trailing_incomplete` and skipping 24 bytes when `is_client_preface` matches; Task 7 is the regression test.
6. **Map type and cleanup verified against the actual `active_l7_requests`/`active_connections` code, not assumed:** `http2_progress` is explicitly `BPF_MAP_TYPE_LRU_HASH` (self-evicting, matching the maps it's modeled on). The original draft's claim that cleanup happens "on connection close, same as `active_connections`" was checked against `ebpftracer/ebpf/tcp/state.c` and found inaccurate: `active_l7_requests` is actually cleaned only in `sys_exit_connect` (outbound-only, proactive fd-reuse guard), never in `sys_enter_close`, and never at all for inbound/`accept()` — inbound relies purely on LRU eviction for `active_l7_requests` today. `http2_progress` mirrors the outbound half of that (Task 2, Step 1's map sketch) but explicitly does **not** mirror the inbound gap — see point 11.
7. **Event-count invariant change, called out explicitly:** `handle_request`/`handle_response` go from "at most 1 `send_event` per call" to "at most 2" — bounded, not unbounded, because the kernel never loops per-frame (it inspects only the first frame header of whatever's left and ships the rest as one blob either way). Documented in "Chosen solution" so Task 2's implementation doesn't accidentally assume the old 1-event invariant elsewhere (e.g. in how `l7_event_heap` is reused).
8. **Placeholders:** none; map/layout and test commands are explicit.
9. **Types:** `Parse` signature unchanged; new BPF structs named in Task 2, including the `method` field in `http2_progress_key` and the `frame_type` cap in `http2_progress` (HEADERS/CONTINUATION only); `http2_scan_trailing_incomplete` now takes `method` as well.
10. **A trailing frame's own 9-byte header can be split mid-syscall, not just its body:** found while walking through a compound scenario (finish a pending `remaining`, fall through into a blob event containing DATA frames, then a trailing frame whose *header* — not body — is cut short). Combined with the Step 1 fall-through, the original "fewer than 9 bytes remain, accepted out-of-scope" bail-out reproduced the exact "worse than a plain drop" failure Task 6/7 fix for full-header trailing frames, just one byte-offset deeper — not meaningfully rarer, so leaving it unfixed would be an inconsistent scope cut. Closed by adding a second, mutually-exclusive sub-state to `http2_progress` (`hdr_have`/`hdr_buf`, Task 2 Step 1b) that buffers 1–8 raw header bytes and splices them with the next call's front bytes before falling into the existing `remaining`-style logic; Task 8 is the regression test. Considered and rejected a broader "sticky last-known-protocol" fallback for this and similar gaps (see Rejected Alternatives) — it would trade a bounded, self-healing loss for a risk of silently mislabeling unrelated fd-reused traffic and corrupting `Http2Parser`'s HPACK state.
11. **`looks_like_http2_frame` itself rejected the plan's own motivating example — found by tracing the primary Problem-section example (9-byte header, `length=14`) through the unmodified function byte-by-byte:** `frame_length + 9 > size` was routed unconditionally to `is_client_preface`, which returns 0 for anything under 24 bytes — so the function said "not HTTP/2" for exactly the input the whole plan exists to fix, meaning `handle_request` never even entered the HTTP/2 branch and the progress map (Task 2 Steps 1/1b/2) never got a chance to run. An earlier draft of this plan claimed "keep `looks_like_http2_frame` exactly as-is," which is incompatible with fixing this example. Closed by Task 2, Step 0: read `type` before falling back to `is_client_preface`, and accept (`return 1`) when it's `HEADERS`/`CONTINUATION`, even though the frame doesn't fit yet. No new regression test task was added for this specifically because Task 3 (`TestHttp2TlsIngressEvents`) already exercises exactly this input — it would have failed to detect `GET /users` at all without Step 0, catching this as a Task 3 failure rather than needing a dedicated test.
12. **Inbound fd-reuse risk, found and closed (deviates from the map this design is modeled on):** `active_l7_requests` has no explicit cleanup on `accept()`/inbound close — only `BPF_MAP_TYPE_LRU_HASH` protects it. Initially `http2_progress` was planned to mirror that gap ("inbound relies purely on LRU, same as `active_l7_requests`"). On review this was tightened instead of copied: `handle_accept_exit` (`tcp/state.c`) already receives the brand-new fd at the exact moment `accept()`/`accept4()` returns — the inbound mirror of the `sys_exit_connect` moment already used for outbound cleanup — and deleting all four `{is_tls, method}` `http2_progress` entries there is unconditionally safe (a fresh `accept()` fd cannot have a legitimate pending continuation). Task 2, Step 2b implements this. `BPF_MAP_TYPE_LRU_HASH` remains the backstop for cases this doesn't cover (e.g. a connection that leaves a dangling entry and then goes silent forever). This is a deliberate, called-out improvement over `active_l7_requests`'s own behavior, not an inconsistency with it.
13. **Cross-plan dependency made explicit, not left implicit:** Task 2's write-side logic (`handle_response`, plus every write-based test in Tasks 2/4/6/7/8) implicitly assumes `size` reflects bytes actually accepted by the kernel/TLS layer for that call — true today only for reads (`trace_exit_read`), not writes (`trace_enter_write` uses the requested size). Found while tracing through what happens if a short write hands `http2_progress` an inflated `size`: `remaining` would be computed against bytes that haven't necessarily reached the wire yet, corrupting the next write's classification the same way an uncorrected short write corrupts `bytes_sent` today. Rather than duplicating a fix here, this is called out as an explicit prerequisite on the sibling plan `2026-09-16-write-syscall-short-write-tracking.md` (Global Constraints) instead of silently assuming production writes are always full.

---

## Execution

Plan saved to `coroot-node-agent/docs/superpowers/plans/2026-09-16-http2-tls-ingress-reassembly.md`.

Two execution options:

1. **Subagent-Driven (recommended)** — one subagent per task, review between tasks
2. **Inline Execution** — implement in this session with checkpoints

Which approach?
# Sendfile/Splice Blind-Spot Containment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop `sendfile()`/`splice()` traffic on a traced socket from silently corrupting per-connection partial-protocol state (`http2_progress`, MySQL's partial-header tracking in `active_l7_requests`) that this tracer cannot observe the contents of — by detecting that such a syscall moved bytes on a tracked fd and invalidating any in-flight partial state for that fd, instead of leaving stale state around to be misinterpreted as "the continuation we were waiting for."

**Architecture:** Add enter/exit tracepoint pairs for `sendfile`, `splice` (raw syscalls; no userspace-visible buffer exists for either, so their payload can never be classified — this plan does not attempt to). At exit, use the real return value (bytes moved) plus a lookup against `active_connections` to determine (a) whether one side of the transfer is a socket this tracer is already tracking, and (b) the direction (bytes leaving vs entering that socket). Where the tracked fd is a socket: correct `bytes_sent`/`bytes_received` on `active_connections` using the real byte count (a direct accuracy fix, low risk), and delete any `http2_progress` / MySQL-partial `active_l7_requests` entries for that `{pid, fd}` (both `is_tls` variants, both HTTP/2 `method` variants) — the same "this state can no longer be trusted, drop it" pattern already used for fd-reuse in the HTTP/2 TLS ingress reassembly plan (`sys_exit_connect`, `handle_accept_exit`).

**Tech Stack:** cilium/ebpf C programs (`ebpftracer/ebpf/l7/l7.c`, `ebpftracer/ebpf/tcp/state.c`), VM tests via `make docker-test`.

## Global Constraints

- Do not git commit unless the user asks.
- Do not add README or extra summary docs beyond this plan.
- Tests first for Go integration tests (`tracer_test.go`); eBPF C has no unit test harness, verify via VM integration tests.
- This plan does **not** attempt to read, classify, or reassemble the actual bytes moved by `sendfile`/`splice` — there is no userspace buffer pointer in either syscall's signature for `bpf_probe_read_user` to read from (see Problem section). The goal is containment (stop silent misclassification of *later, normally-observed* bytes), not observation of these calls' own content.
- `vmsplice` is explicitly **out of scope** — it only ever moves bytes between a userspace buffer and a pipe, never directly to/from a socket (see Rejected Alternatives); the socket-facing leg of a `vmsplice`-fed transfer is always a separate `splice()` call, which this plan does cover.
- Kernel TLS (kTLS) is explicitly **out of scope** — see Rejected Alternatives. Treat every socket this plan touches as if it could be either plaintext or userspace-TLS (already the assumption everywhere else in this codebase); this plan invalidates both `is_tls` variants of the affected maps unconditionally rather than trying to detect kTLS.
- Do not change `handle_request`/`handle_response` signatures or call them from the new tracepoints — there is no payload to classify, only byte-count correction and state invalidation.
- Rebuild the embedded BPF blob (`ebpftracer/Makefile` / `ebpf.go`) after changing C.
- This plan depends on `http2_progress` existing (from `docs/superpowers/plans/2026-09-16-http2-tls-ingress-reassembly.md`, Task 2) — implement that plan first, or adapt Task 2 here if `http2_progress` doesn't exist yet when this plan is executed.

---

## Problem

### `sendfile`/`splice` move bytes kernel-to-kernel; there is no userspace buffer to inspect

`sendfile(int out_fd, int in_fd, off_t *offset, size_t count)` copies bytes directly from `in_fd` (almost always a regular file) to `out_fd` (typically a socket) **inside the kernel**. `splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)` does the same between two fds where at least one is a pipe. Neither syscall's signature contains a pointer to a userspace-addressable buffer holding the bytes being moved — unlike `write(fd, buf, count)`, where `buf` is exactly the pointer every existing protocol classifier (`is_http_request`, `looks_like_http2_frame`, `is_mysql_query`, ...) reads from via `bpf_probe_read_user`/`bpf_read`.

This means: **there is no way for this tracer — or any eBPF program limited to reading userspace memory — to see what bytes a `sendfile`/`splice` call actually put on the wire.** This isn't a missing tracepoint we could add; it's a structural property of these syscalls (their entire performance benefit over `read()`+`write()` is that the data *never* passes through a userspace-visible buffer).

### Why this matters specifically for `http2_progress` (and MySQL's partial-header tracking)

The HTTP/2 TLS ingress reassembly plan's `http2_progress` map (and the pre-existing MySQL partial-header logic in `active_l7_requests`) both work by remembering "this fd/direction owes N more bytes to finish the frame/packet it's mid-way through" and trusting that **the next observed `read`/`write`-family call on that fd delivers exactly the continuation of that same stream of bytes**. That assumption silently breaks if bytes are moved on the fd through a syscall this tracer doesn't hook at all:

1. A server hooked via `crypto/tls.(*Conn).Write`/raw `write()` sends the first 9 bytes of a HEADERS frame (`http2_progress` now has `remaining = N` for that `{pid, fd, is_tls, method}`).
2. Before the rest of that frame's body goes out, or as part of an unrelated response on a *different* stream multiplexed on the same connection, the application calls `sendfile()`/`splice()` on the same fd — e.g. streaming a DATA frame's body from a static file (a very common real-world optimization for HTTP/2 file-serving and gRPC-with-large-payloads).
3. This tracer never sees those bytes. `remaining` in `http2_progress` is untouched — it still says "still owe N bytes," even though, on the real wire, those N bytes may have already gone out via step 2's `sendfile()`, and whatever comes *next* via a normally-observed `write()` is actually the **start of a new frame**, not the continuation of the old one.
4. The next `write()` this tracer *does* observe gets misclassified: Step 1 of the HTTP/2 plan's Task 2 consumes `MIN(size, remaining)` bytes of what is actually a brand-new frame's header/HPACK bytes, sends them as HTTP/2 "continuation" of the *old* frame, and can feed genuinely new HPACK bytes into the decoder at the wrong offset — silent decoder desync for the rest of that connection, the exact failure class the HTTP/2 plan spent most of its effort avoiding for every *other* kind of gap (fd reuse, trailing incomplete frames, split headers).

The same reasoning applies to MySQL's `partial`/`payload_length` tracking in `active_l7_requests` (`ebpftracer/ebpf/l7/mysql.c:13-28`, `l7.c:420-425`): if a MySQL client used `sendfile`/`splice` to stream a `LOAD DATA LOCAL INFILE` payload split unusually, the same "next read's bytes aren't really the continuation we think they are" risk exists, even though it's a much rarer trigger for that protocol in practice.

### Why raw `write`/`read` classifiers don't already protect against this

`handle_request`/`handle_response` only run when this tracer's own `write`/`writev`/`sendmsg`/`sendmmsg`/`sendto`/`read`/`readv`/`recvmsg`/`recvfrom` tracepoints fire (`ebpftracer/ebpf/l7/l7.c:681-830`). `sendfile`/`splice` don't call any of these — from this tracer's point of view, **nothing happened on that fd** during that syscall. There is no hook today that even notices a `sendfile`/`splice` occurred, let alone reacts to it.

### Why this can't be "fixed" the way the HTTP/2 plan's other gaps were fixed

Every other gap that plan closed (trailing incomplete frames, split headers, fd reuse) was closed by **tracking more precisely** — because the bytes in question were always visible to the tracer eventually, just not accounted for correctly yet. Here, the bytes are permanently invisible by construction. The only thing achievable is **containment**: notice that an untrusted gap just occurred on this fd, and stop trusting whatever partial-frame state existed before it — converting a silent, wrong classification into a clean, bounded "we lost track here, start fresh," which is the same trade-off the HTTP/2 plan already made deliberately for the "frame header itself split beyond what we buffer" and "generic sticky protocol fallback" cases (see that plan's Rejected Alternatives).

---

## Chosen solution

**New tracepoints, stash-then-finish, mirroring the existing `read`/`write` split (`active_reads`/`active_writes`-style pattern already used in `ebpftracer/ebpf/l7/l7.c`):**

- `sys_enter_sendfile64` (and, if present on the target kernel, `sys_enter_sendfile` — name varies by architecture; verify with `ls /sys/kernel/debug/tracing/events/syscalls/ | grep -i sendfile` on the VM test image, see Task 1 Step 1): stash `{fd_a = out_fd, fd_b = in_fd, kind = BLIND_COPY_SENDFILE}` keyed by `bpf_get_current_pid_tgid()` into a new `active_blind_copies` map.
- `sys_enter_splice`: stash `{fd_a = fd_out, fd_b = fd_in, kind = BLIND_COPY_SPLICE}`, same map, same key.
- `sys_exit_sendfile64`/`sys_exit_sendfile`/`sys_exit_splice`: look up + delete the stash entry; if `ret <= 0`, return (nothing was actually moved). Otherwise call a shared `handle_blind_copy(pid, fd_a, fd_b, (__u64)ret)` helper.

**`handle_blind_copy(pid, fd_a, fd_b, n)`:**

- Look up `active_connections` for `{pid, fd_a}` and `{pid, fd_b}` (`struct connection_id` key, exactly as `handle_request`/`trace_enter_write` already do). At most one of the two will typically be a tracked socket (the other is a regular file or pipe, neither of which is ever inserted into `active_connections`) — but check both, don't assume which side.
- For whichever fd *is* a tracked connection:
  - **`fd_a` (the destination — `out_fd` for `sendfile`, `fd_out` for `splice`) matched:** bytes were written **into** the socket. `__sync_fetch_and_add(&conn->bytes_sent, n)` (mirrors the existing `bytes_sent` accounting in `trace_enter_write`, `l7.c:280`).
  - **`fd_b` (the source — `in_fd`/`fd_in`) matched:** bytes were read **out of** the socket. `__sync_fetch_and_add(&conn->bytes_received, n)`.
  - (Both could theoretically match for a socket-to-socket `splice` — handle independently, one add per matching side.)
- For whichever fd *is* a tracked connection, **unconditionally invalidate partial state for that `{pid, fd}`**, regardless of which side matched — the direction that had a byte-count update is the direction we know moved untracked bytes, but the *other* direction's in-flight state is not provably safe either (e.g. a half-duplex assumption that doesn't hold for HTTP/2, which is explicitly full-duplex — see the HTTP/2 plan's "direction discriminator" reasoning). Delete, for that `fd`/`pid`:
  - `http2_progress`: all four `{is_tls, method}` combinations (same four-delete pattern as `sys_exit_connect`/`handle_accept_exit` in the HTTP/2 plan).
  - `active_l7_requests`: both `is_tls` variants, keyed with `stream_id = -1` (matching the existing `struct l7_request_key` shape used for the MySQL-partial-header entry — `l7.c:420-425`). Only the `PROTOCOL_UNKNOWN`+`partial==1` entries are ever at risk here (a fully-classified, in-flight non-partial request isn't waiting on more bytes from *this* fd the same way); deleting unconditionally is still safe and cheap — a `bpf_map_delete_elem` on a key that isn't a partial entry (or doesn't exist) is a no-op.

**Event volume:** none — this plan produces zero `l7_event`s. It only corrects two counters and clears map entries.

### Rejected alternatives

| Approach | Why not |
|---|---|
| Try to read the file's contents via `in_fd` at `sendfile` time (e.g. `bpf_probe_read_kernel` on the page cache) | Wildly out of scope for an L7 socket tracer — would require file-content tracking infra this codebase doesn't have, wrong layer, and still wouldn't tell us the *socket-side* byte boundary (partial writes, TLS record framing, etc.) |
| Hook `vmsplice` too | `vmsplice(fd, iov, nr_segs, flags)` only moves bytes between a userspace buffer and a **pipe** — it is never called with a socket fd directly. A `vmsplice`-fed transfer that ends up on a socket always does so via a subsequent `splice(pipe_fd, ..., socket_fd, ...)` call, which this plan already covers. Hooking `vmsplice` itself would tell us nothing about which socket (if any) the data eventually reaches. |
| Detect and specially handle kernel TLS (kTLS, `setsockopt(SOL_TLS, ...)`) so `sendfile`/`splice` on a kTLS socket could be "supported" | kTLS lets the kernel encrypt/decrypt TLS records for a socket transparently, which is exactly why `sendfile`/`splice` work at all on an encrypted connection in that setup — but the plaintext still never touches a userspace buffer this tracer can read (encryption/decryption happens in-kernel, after/before this tracer's own hooks would see anything). Detecting kTLS wouldn't unlock classification; it would only tell us *why* the blind spot exists on that particular socket. Out of scope; the containment behavior (invalidate partial state) is identical whether or not kTLS is involved. |
| Mark a fd "permanently untrustworthy for HTTP/2" after any `sendfile`/`splice` on it, instead of just invalidating in-flight partial state once | Overly broad: a connection that uses `sendfile` for one response's DATA body (already out of `http2_progress`'s scope — DATA is never tracked) can go right back to normal `write()`-based HEADERS on the next request and should be trusted again immediately. A permanent flag would silently blind this tracer to a socket for its entire remaining lifetime over a single DATA-body optimization, which is a much larger observability loss than the (already rare) HPACK-desync risk being contained here. |
| A generic "sticky last-known-protocol" fallback (considered in the HTTP/2 plan for a different gap) | Same rejection reasoning applies here even more strongly: we have *zero* visibility into what `sendfile`/`splice` actually sent, so "assume it matches what we expected" has no evidence behind it at all — pure guessing, not a bounded fallback. |

---

## File map

| File | Role |
|---|---|
| `ebpftracer/ebpf/l7/l7.c` | New `active_blind_copies` map; `sys_enter_sendfile64`/`sys_enter_splice` stash tracepoints; `sys_exit_sendfile64`/`sys_exit_splice` finish tracepoints; `handle_blind_copy` helper |
| `ebpftracer/ebpf.go` | Regenerated BPF object |
| `ebpftracer/tracer_test.go` | New regression test(s) |

---

### Task 1: Detect `sendfile`/`splice` and correct byte counters

**Files:**
- Modify: `ebpftracer/ebpf/l7/l7.c`
- Regenerate: `ebpftracer/ebpf.go` via `ebpftracer/Makefile`

**Interfaces:**
- Consumes: existing `active_connections` map, `struct connection_id`, `struct connection`
- Produces: new map `active_blind_copies`; new helper `handle_blind_copy(pid, fd_a, fd_b, n)`; new tracepoints `sys_enter_sendfile64`, `sys_exit_sendfile64`, `sys_enter_splice`, `sys_exit_splice`

- [ ] **Step 1: Verify tracepoint names on the VM test image**

Run (on the same kernel `make docker-test` uses): `ls /sys/kernel/debug/tracing/events/syscalls/ | grep -iE 'sendfile|splice'`
Expected: `sys_enter_sendfile64`/`sys_exit_sendfile64` and `sys_enter_splice`/`sys_exit_splice` (exact names may vary by kernel version/arch — adjust the `SEC()` strings in Step 3 to whatever this command actually lists; do not guess).

- [ ] **Step 2: Add `struct blind_copy_args` and `active_blind_copies` map**

```c
#define BLIND_COPY_SENDFILE 1
#define BLIND_COPY_SPLICE   2

struct blind_copy_args {
    __u64 fd_a; // destination: out_fd (sendfile) / fd_out (splice)
    __u64 fd_b; // source: in_fd (sendfile) / fd_in (splice)
    __u8  kind;
    __u8  pad[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64)); // bpf_get_current_pid_tgid()
    __uint(value_size, sizeof(struct blind_copy_args));
    __uint(max_entries, 10240); // same order of magnitude as active_reads/active_writes
} active_blind_copies SEC(".maps");
```

- [ ] **Step 3: Add the enter tracepoints**

```c
SEC("tracepoint/syscalls/sys_enter_sendfile64")
int sys_enter_sendfile64(struct trace_event_raw_sys_enter__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct blind_copy_args args = {
        .fd_a = (__u64)ctx->args[0], // out_fd
        .fd_b = (__u64)ctx->args[1], // in_fd
        .kind = BLIND_COPY_SENDFILE,
    };
    bpf_map_update_elem(&active_blind_copies, &id, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_splice")
int sys_enter_splice(struct trace_event_raw_sys_enter__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct blind_copy_args args = {
        .fd_a = (__u64)ctx->args[2], // fd_out
        .fd_b = (__u64)ctx->args[0], // fd_in
        .kind = BLIND_COPY_SPLICE,
    };
    bpf_map_update_elem(&active_blind_copies, &id, &args, BPF_ANY);
    return 0;
}
```

Note: `struct trace_event_raw_sys_enter__stub` and `ctx->args[N]` indexing already match the pattern used by every other `sys_enter_*` tracepoint in this file (e.g. `sys_enter_sendto`, `l7.c:739`) — follow that exact struct/field usage, do not invent a new ctx shape.

- [ ] **Step 4: Add `handle_blind_copy` and the exit tracepoints**

```c
static inline __attribute__((__always_inline__))
int handle_blind_copy(__u32 pid, __u64 fd_a, __u64 fd_b, __u64 n) {
    struct connection_id cid_a = {.pid = pid, .fd = fd_a};
    struct connection *conn_a = bpf_map_lookup_elem(&active_connections, &cid_a);
    if (conn_a) {
        __sync_fetch_and_add(&conn_a->bytes_sent, n);
        invalidate_http2_and_partial_state(pid, fd_a);
    }
    struct connection_id cid_b = {.pid = pid, .fd = fd_b};
    struct connection *conn_b = bpf_map_lookup_elem(&active_connections, &cid_b);
    if (conn_b) {
        __sync_fetch_and_add(&conn_b->bytes_received, n);
        invalidate_http2_and_partial_state(pid, fd_b);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendfile64")
int sys_exit_sendfile64(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct blind_copy_args *args = bpf_map_lookup_elem(&active_blind_copies, &id);
    if (!args) {
        return 0;
    }
    struct blind_copy_args a = *args;
    bpf_map_delete_elem(&active_blind_copies, &id);
    if (ctx->ret <= 0) {
        return 0;
    }
    return handle_blind_copy(id >> 32, a.fd_a, a.fd_b, (__u64)ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_splice")
int sys_exit_splice(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct blind_copy_args *args = bpf_map_lookup_elem(&active_blind_copies, &id);
    if (!args) {
        return 0;
    }
    struct blind_copy_args a = *args;
    bpf_map_delete_elem(&active_blind_copies, &id);
    if (ctx->ret <= 0) {
        return 0;
    }
    return handle_blind_copy(id >> 32, a.fd_a, a.fd_b, (__u64)ctx->ret);
}
```

`invalidate_http2_and_partial_state` is defined in Task 2 — this task can stub it as a no-op (`return 0;`) to keep Task 1 independently buildable/testable, then Task 2 fills it in. Do not skip the stub: a task that doesn't compile on its own breaks the "each task ends with an independently testable deliverable" rule.

- [ ] **Step 5: Rebuild and run existing tests**

Run from `ebpftracer/`: `make build`, then `make docker-test DOCKER_TEST_ARGS='-count=1 -timeout 15m -v github.com/coroot/coroot-node-agent/ebpftracer'`.
Expected: full suite still PASS — no existing code path is modified, only new tracepoints added.

---

### Task 2: Invalidate `http2_progress` / MySQL-partial state on a blind copy

**Files:**
- Modify: `ebpftracer/ebpf/l7/l7.c`
- Regenerate: `ebpftracer/ebpf.go`

**Interfaces:**
- Consumes: `http2_progress` map and `struct http2_progress_key` (from `docs/superpowers/plans/2026-09-16-http2-tls-ingress-reassembly.md`, Task 2), `active_l7_requests` map and `struct l7_request_key`
- Produces: `invalidate_http2_and_partial_state(pid, fd)`, called from Task 1's `handle_blind_copy`

- [ ] **Step 1: Implement `invalidate_http2_and_partial_state`**

```c
static inline __attribute__((__always_inline__))
int invalidate_http2_and_partial_state(__u32 pid, __u64 fd) {
    struct http2_progress_key hk = {.pid = pid, .fd = fd};
    hk.is_tls = 0; hk.method = METHOD_HTTP2_CLIENT_FRAMES; bpf_map_delete_elem(&http2_progress, &hk);
    hk.method = METHOD_HTTP2_SERVER_FRAMES;                bpf_map_delete_elem(&http2_progress, &hk);
    hk.is_tls = 1; hk.method = METHOD_HTTP2_CLIENT_FRAMES; bpf_map_delete_elem(&http2_progress, &hk);
    hk.method = METHOD_HTTP2_SERVER_FRAMES;                bpf_map_delete_elem(&http2_progress, &hk);

    struct l7_request_key lk = {.pid = pid, .fd = fd, .stream_id = -1};
    lk.is_tls = 0; bpf_map_delete_elem(&active_l7_requests, &lk);
    lk.is_tls = 1; bpf_map_delete_elem(&active_l7_requests, &lk);
    return 0;
}
```

Zero-initialize both key structs fully (including any padding fields) before use — the same map-key padding hazard already noted for `http2_progress_key` in the HTTP/2 plan applies here too.

- [ ] **Step 2: Remove Task 1's stub** — delete the placeholder `return 0;` body and wire this real implementation in; `handle_blind_copy` (Task 1, Step 4) already calls it by name, no other change needed there.

- [ ] **Step 3: Rebuild and run existing tests**

Run: `make build`, then `make docker-test DOCKER_TEST_ARGS='-count=1 -timeout 15m -v github.com/coroot/coroot-node-agent/ebpftracer'`.
Expected: full suite still PASS — invalidation only ever deletes map entries keyed by a `{pid, fd}` that just had a `sendfile`/`splice` call on it; no existing test path exercises that syscall, so nothing existing should be affected.

---

### Task 3: Regression test — `sendfile` between two HTTP/2 HEADERS frames doesn't desync the next request

**Files:**
- Modify: `ebpftracer/tracer_test.go`

**Interfaces:**
- Consumes: `startHTTP2UsersServer`-style plaintext h2c server/client helpers (from the HTTP/2 TLS ingress reassembly plan's Tasks 4–8), `waitHTTP2`
- Produces: `TestSendfileBetweenHttp2FramesDoesNotDesync` PASS

- [ ] **Step 1: Write a failing test.** Reuse `startHTTP2UsersServer`/`waitHTTP2` exactly as the HTTP/2 TLS ingress reassembly plan's Tasks 3/6/7 do (`waitHTTP2` already succeeds on *any* event sequence that `feedHTTP2`/`http2UsersOK` can parse into a correct `GET /users` — it doesn't care which `stream_id` carried it). Add a minimal raw h2c client program (`http2SendfileBetweenFramesClientSrc`, built via `buildHTTP2Prog`) that, against `startHTTP2UsersServer`'s address, over a single `net.Dial("tcp", addr)` connection:
  1. `conn.Write(...)`: client preface + a complete SETTINGS frame + only the 9-byte header of a HEADERS frame for stream 1 (claims a `length` that is *not* satisfied by anything else in this write) — this leaves `http2_progress` with `remaining > 0` for this fd, same split-header technique as the HTTP/2 plan's Task 3/6, and this stream 1 HEADERS frame is deliberately **never completed** (its bytes are never sent again — it should end up GC'd, not observed, once invalidation runs).
  2. `syscall.Sendfile(int(connFile.Fd()), int(tmpFile.Fd()), nil, tmpFileSize)`: send the entire contents of a small temp file (any bytes — e.g. `[]byte("unrelated-blind-copy-payload")` written to a `os.CreateTemp` file) directly on the same connection's underlying fd (obtained via `conn.(*net.TCPConn).File()`).
  3. `conn.Write(...)`: a **complete**, brand-new HEADERS frame for stream 3, `GET /users` (full 9-byte header + complete HPACK body in one `Write`) — bytes that must be classified as a *fresh* frame, not as the continuation of step 1's still-incomplete stream-1 HEADERS frame.

```go
func TestSendfileBetweenHttp2FramesDoesNotDesync(t *testing.T) {
	skipIfNotVM(t)
	getEvent, stop := runTracer(t, false)
	defer stop()

	serverPid, addr, stopServer := startHTTP2UsersServer(t)
	defer stopServer()

	clientBin := buildHTTP2Prog(t, "http2sendfileclient", http2SendfileBetweenFramesClientSrc)
	cmd := exec.Command(clientBin, addr)
	require.NoError(t, cmd.Run())

	// Succeeds only if the server observes a correctly-classified GET /users on stream 3 —
	// i.e. the frame after the sendfile() call was NOT merged with/corrupted by stream 1's
	// still-incomplete HEADERS frame from before the sendfile() call.
	got := waitHTTP2(t, getEvent, serverPid, true)
	require.Equal(t, l7.ProtocolHTTP2, got.L7Request.Protocol)
	require.True(t, got.L7Request.IsInbound)
}
```

- [ ] **Step 2: Run before Task 1/2 are implemented**

Run: `make docker-test DOCKER_TEST_ARGS='-count=1 -timeout 10m -v github.com/coroot/coroot-node-agent/ebpftracer -run TestSendfileBetweenHttp2FramesDoesNotDesync'`
Expected: timeout/fail — without invalidation, `http2_progress` still has a stale `remaining` entry from step 1's incomplete stream-1 HEADERS; the stream-3 `GET /users` HEADERS frame's own header bytes get consumed as if they were the missing tail of stream 1's frame, feeding the wrong bytes into the HPACK decoder at the wrong offset — `waitHTTP2` never sees a correctly-parsed `GET /users` and times out.

- [ ] **Step 3: Re-run after Task 1 and 2**

Same command. Expected: PASS — the `sendfile()` call invalidates the stale `http2_progress` entry, so the next `write()` (the complete stream-3 `GET /users` HEADERS frame) is classified fresh, correctly, from `looks_like_http2_frame` onward.

- [ ] **Step 4: Add a byte-counter assertion.** Extend the test to also read the `EventTypeConnectionClose`/periodic connection event for this `serverPid`+`addr` (check `ebpftracer/tracer_test.go` for the existing field carrying `bytes_received` on inbound connection events — follow whatever field name the existing connection-lifecycle tests already assert on) and confirm it includes the `sendfile()`-transferred byte count, proving Task 1's counter fix works, not only the invalidation.

---

## Self-review

1. **Spec coverage:** why `sendfile`/`splice` are structurally invisible to this tracer, why that's dangerous specifically for `http2_progress`/MySQL-partial state, containment via invalidation (not attempted reconstruction), byte-counter correction, `vmsplice`/kTLS explicitly scoped out with reasons, tests. All have tasks.
2. **Dependency on the HTTP/2 plan is explicit, not assumed:** Global Constraints states this plan requires `http2_progress` to exist first; Task 2 names the exact struct/map it depends on.
3. **No new events, no classification attempted:** called out in "Chosen solution" and Global Constraints — this plan is purely defensive (byte counters + state invalidation), which keeps its blast radius small and matches the "containment, not reconstruction" framing from the Problem section.
4. **Placeholders:** Task 1's stubbed `invalidate_http2_and_partial_state` is a deliberate, stated placeholder to keep Task 1 independently buildable — allowed per the "Task Right-Sizing" rule (each task ends with an independently testable deliverable) and explicitly filled in by Task 2, not left as a silent gap.
5. **Types:** `struct blind_copy_args` fields and `handle_blind_copy`'s signature are used identically across Task 1 and Task 2; `http2_progress_key`/`l7_request_key` field names in Task 2 match the HTTP/2 plan's actual struct definitions, not guessed names.
6. **Exact tracepoint names flagged as needing on-VM verification, not assumed:** Task 1 Step 1 requires checking `/sys/kernel/debug/tracing/events/syscalls/` before writing the `SEC()` strings, because `sendfile` vs `sendfile64` naming is architecture/kernel-version-dependent — this is called out explicitly rather than silently guessed.

---

## Execution

Plan saved to `coroot-node-agent/docs/superpowers/plans/2026-09-16-sendfile-splice-blind-spot.md`.

Two execution options:

1. **Subagent-Driven (recommended)** — one subagent per task, review between tasks
2. **Inline Execution** — implement in this session with checkpoints

Which approach?

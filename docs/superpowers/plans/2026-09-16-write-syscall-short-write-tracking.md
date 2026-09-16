# Write-Syscall Short-Write Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make coroot-node-agent's L7 write tracing use the **actual** number of bytes a `write`-family syscall (or `crypto/tls.(*Conn).Write`) sent, instead of assuming the syscall sent everything the caller asked it to send. Fixes `bytes_sent` over-counting and payload/classification snapshots that can include bytes which never actually reached the wire in that call.

**Architecture:** Mirror the pattern the **read** path already uses (`active_reads` LRU map + `sys_enter_read` stash + `sys_exit_read` finish with the real `ret`). Split write tracing into a `sys_enter_write*` stash (store fd/buf/size/iovlen) and a new `sys_exit_write*` finish step that clamps `size = MIN(requested_size, actual_ret)` before doing anything else (connection lookup, `bytes_sent` counter, protocol classification). Do the same for the Go TLS write uprobe by adding a `go_crypto_tls_write_exit` uretprobe, mirroring the existing `go_crypto_tls_read_exit`.

**Tech Stack:** cilium/ebpf C programs (`ebpftracer/ebpf/l7/l7.c`, `ebpftracer/ebpf/l7/gotls.c`), VM tests via `make docker-test`.

## Global Constraints

- Do not git commit unless the user asks.
- Do not add README or extra summary docs beyond this plan.
- Tests first where practical for Go integration tests (`tracer_test.go`); eBPF C has no unit test harness, verify via VM integration tests.
- Scope is **raw syscalls** (`write`, `writev`, `sendmsg`, `sendto`, `sendmmsg`) and **Go TLS** (`crypto/tls.(*Conn).Write`), where "actual bytes accepted" is directly knowable from the syscall/function return value in the same units we classify (plaintext for GoTLS, raw bytes for syscalls).
- OpenSSL (`SSL_write`) and rustls write paths are explicitly **out of scope** for this plan (see "Rejected alternatives" — a short *raw* ciphertext write does not map 1:1 to a known amount of *plaintext*, so "clamp to actual" needs TLS-record-aware logic those two paths don't have today). Leave `ssl_check_write` / `rustls_write_pending` substitution behavior unchanged.
- Do not change `handle_request`/`handle_response` signatures — they already take `size`; this plan only changes what `size` they're called with, computed earlier in the write path.
- Rebuild the embedded BPF blob (`ebpftracer/Makefile` / `ebpf.go`) after changing C.

---

## Problem

### What we observe today

`trace_enter_write` in `ebpftracer/ebpf/l7/l7.c` runs entirely at **syscall entry** (`sys_enter_write`/`writev`/`sendmsg`/`sendto`/`sendmmsg`) and at the **Go TLS write uprobe entry** (`go_crypto_tls_write_enter` in `gotls.c`). It uses the caller-supplied `size` argument — how many bytes the application *asked* to write — for everything: the byte-counter (`conn->bytes_sent`), the payload snapshot copied into `l7_event.payload`, and every protocol classifier (`is_http_request`, `looks_like_http2_frame`, etc.).

There is no `sys_exit_write`/`sys_exit_writev`/`sys_exit_sendmsg`/`sys_exit_sendto`/`sys_exit_sendmmsg` tracepoint anywhere in `l7.c`, and no `go_crypto_tls_write_exit` uretprobe in `gotls.c` — only `go_crypto_tls_read_exit` exists. Contrast with the **read** path, which does exactly the right thing: `trace_enter_read` only stashes `{fd, buf, ret_ptr, iovlen}` in the `active_reads` LRU map; `trace_exit_read` (called from every `sys_exit_read*`) reads the *actual* return value and only then does the connection lookup, `bytes_received` counter, and protocol dispatch — using the real number of bytes the kernel actually delivered.

### Why this matters

POSIX allows `write()` (and friends) to accept **fewer** bytes than requested without it being an error — "short writes" are legal for non-blocking sockets, signal-interrupted calls, and sockets whose send buffer is nearly full. When that happens:

1. `conn->bytes_sent` (`l7.c:280`) is incremented by the *requested* size, not what the OS actually accepted. Byte counters can drift high over the life of a connection that ever does a short write.
2. The event's `payload`/`payload_size` and every classifier see the **full requested buffer**, even though only the first `ret` bytes of it were actually placed on the wire in *this* call — the remainder will go out in a **separate**, later `write()` call that the application makes to send the rest. A protocol parser could be shown bytes as "sent" that, at the time of this syscall, hadn't actually left the process yet.
3. Symmetric to the HTTP/2 TLS-ingress-reassembly plan's read-side fix: a short write of a HEADERS frame's header should look exactly like an *incomplete* frame to the HTTP/2 progress-map logic in that plan, but today it's fed the full intended `size`, so the classifier doesn't even get a chance to see it as incomplete — it sees bytes as "present" that the OS is going to send later, in a call this tracer hasn't observed yet.

### Why it hasn't caused visible bugs so far

Most application writes to a healthy, blocking socket succeed in full in one call, so the requested-size-vs-actual-size gap rarely shows up. It's a correctness gap that surfaces only under backpressure (slow consumer, full send buffer, non-blocking I/O, large payloads) — exactly the conditions under which accurate tracing matters most (that's when requests get slow/queued and users look at coroot for answers).

---

## Chosen solution

**Raw syscalls:** add a `struct write_args` LRU map (`active_writes`), symmetric to `active_reads`/`struct read_args`.

- `sys_enter_write`/`writev`/`sendmsg`/`sendto`/`sendmmsg`: after the existing `ssl_check_write` bypass (unchanged — OpenSSL substitution still happens at enter, out of scope here), stash `{fd, buf, size, iovlen, is_tls, socket_only}` keyed by `bpf_get_current_pid_tgid()` and return. Do **not** call `handle_request`/`handle_response` yet.
- New `sys_exit_write`/`writev`/`sendmsg`/`sendto`/`sendmmsg` tracepoints: look up `active_writes`, delete the entry, bail out if `ret <= 0`. Compute `size = MIN(stashed_size, ret)` (for iovec-based calls, still flatten via `read_iovec` but bound the total to `ret`, mirroring how `trace_exit_read` bounds `read_iovec`'s `max` parameter by the real `ret`). Then run the *rest* of today's `trace_enter_write` body (connection lookup/creation, `bytes_sent` increment, `handle_request`/`handle_response` dispatch) — refactored into a shared `finish_write(...)` helper so both this and the GoTLS path below call the same code.
- `rustls_write_pending` substitution (the `plain_buf`/`plain_size` swap for `!is_tls` raw writes) keeps using the plaintext size Rustls originally asked for — **not** clamped to the raw ciphertext `ret` (see Global Constraints: TLS record framing means ciphertext bytes accepted doesn't tell us plaintext bytes accepted; left as a known limitation, not silently "fixed" incorrectly).

**Go TLS write:** add `go_crypto_tls_write_exit` uretprobe, mirroring `go_crypto_tls_read_exit`.

- `go_crypto_tls_write_enter`: instead of calling `trace_enter_write` directly, stash `{fd, buf, size}` keyed by `pid<<32 | goroutine_id | IS_TLS_WRITE_ID` (new marker bit, distinct from `IS_TLS_READ_ID`, same reasoning as the read side: a goroutine can resume on a different OS thread between uprobe entry and uretprobe exit).
- `go_crypto_tls_write_exit`: read `n = GO_PARAM1(ctx)` (bytes written — `crypto/tls.(*Conn).Write` returns `(n int, err error)`, and `n` is exactly "plaintext bytes accepted", the same unit we classify in). If `n <= 0`, drop. Look up the stash, delete it, call `finish_write(ctx, fd, is_tls=1, socket_only=1, buf, MIN(stashed_size, n), 0)`.

**Event volume / behavior change:** none — this only changes *which* `size` is used for an event that was already going to be emitted; it does not add or remove events, except that the event now fires at syscall/function **exit** instead of **entry** for writes (already true for reads).

### Rejected alternatives

| Approach | Why not |
|---|---|
| Keep using enter-time `size`, just cap `bytes_sent` heuristically | Doesn't fix the deeper issue: classifiers still see bytes that weren't actually sent yet |
| Fix OpenSSL (`SSL_write`) and rustls write paths in the same plan | Ciphertext-bytes-accepted doesn't map to plaintext-bytes-accepted without TLS record-framing awareness; needs its own design, would bloat this plan |
| Move iovec flattening to enter time, only clamp the final `total_size` at exit | Loses precision for `sendmmsg`/`writev` where a short write can end mid-iovec; flattening at exit with a `ret`-bounded `read_iovec` (already supported, same as reads) is exact |
| Skip Go TLS, only fix raw syscalls | GoTLS is the primary path for the very tests (`TestHttp2TlsIngressEvents` etc.) most sensitive to accurate byte accounting; leaving it out defeats half the purpose |

---

## File map

| File | Role |
|---|---|
| `ebpftracer/ebpf/l7/l7.c` | `active_writes` map; split `trace_enter_write` into stash + `finish_write`; new `sys_exit_write*` tracepoints |
| `ebpftracer/ebpf/l7/gotls.c` | New `go_crypto_tls_write_exit` uretprobe; `go_crypto_tls_write_enter` becomes a stash-only probe |
| `ebpftracer/tls.go` | Attach the new `go_crypto_tls_write_exit` uretprobe alongside the existing write-enter uprobe |
| `ebpftracer/ebpf.go` | Regenerated BPF object |
| `ebpftracer/tracer_test.go` | New short-write regression test(s) |

---

### Task 1: Raw syscalls — defer write tracing to exit

**Files:**
- Modify: `ebpftracer/ebpf/l7/l7.c`
- Regenerate: `ebpftracer/ebpf.go` via `ebpftracer/Makefile`

**Interfaces:**
- Consumes: existing `active_connections`, `handle_request`, `handle_response`, `read_iovec`
- Produces: new map `active_writes`; new tracepoints `sys_exit_write`, `sys_exit_writev`, `sys_exit_sendmsg`, `sys_exit_sendto`, `sys_exit_sendmmsg`

- [ ] **Step 1: Add `active_writes` map and `struct write_args`** (mirror `struct read_args`/`active_reads`): `{__u64 fd; char *buf; __u64 size; __u64 iovlen; __u16 is_tls; __u8 socket_only;}`.

- [ ] **Step 2: Split `trace_enter_write`** into `trace_enter_write_stash` (bpf_map_update_elem into `active_writes`, keyed by `bpf_get_current_pid_tgid()`, return 0) and `finish_write(ctx, fd, is_tls, socket_only, buf, size, iovlen)` (today's body, unchanged, starting from the `rustls_write_pending` lookup). Update `sys_enter_write`/`writev`/`sendmsg`/`sendto`/`sendmmsg` to call the stash version (keep the existing `ssl_check_write` bypass — OpenSSL is unaffected by this plan).

- [ ] **Step 3: Add `trace_exit_write(ctx, id, ret)`**: look up + delete `active_writes[id]`; if `ret <= 0` return 0; `size = MIN(args->size, (__u64)ret)`; if `args->iovlen`, flatten via `read_iovec(args->buf, args->iovlen, ret, payload, &total_size)` (same `ret`-bounding the read path already does); call `finish_write(...)` with the clamped size.

- [ ] **Step 4: Add the five `sys_exit_write*` tracepoints**, each calling `trace_exit_write` with `ctx->ret`.

- [ ] **Step 5: Rebuild and run existing tests**

Run from `ebpftracer/`: `make build`, then `make docker-test DOCKER_TEST_ARGS='-count=1 -timeout 15m -v github.com/coroot/coroot-node-agent/ebpftracer'`.  
Expected: full suite still PASS — for normal (non-short) writes, `ret == size`, so behavior is unchanged; this step is a regression check, not a new-behavior check (that's Task 3).

---

### Task 2: Go TLS write — defer to `go_crypto_tls_write_exit`

**Files:**
- Modify: `ebpftracer/ebpf/l7/gotls.c`
- Modify: `ebpftracer/tls.go` (attach the new uretprobe)
- Regenerate: `ebpftracer/ebpf.go`

**Interfaces:**
- Consumes: `GOROUTINE`, `GO_PARAM1/2/3`, `finish_write` from Task 1
- Produces: new uretprobe `go_crypto_tls_write_exit`; new marker `IS_TLS_WRITE_ID`

- [ ] **Step 1: Add `IS_TLS_WRITE_ID` marker and a small stash map** (`active_go_tls_writes`, keyed by the same `pid<<32 | goroutine_id | marker` composite id pattern as `rustls_last_read_fd`/read side), value `{__u32 fd; char *buf; __u64 size;}`.

- [ ] **Step 2: Change `go_crypto_tls_write_enter`** to stash `{fd, buf_ptr, buf_size}` instead of calling `trace_enter_write` directly.

- [ ] **Step 3: Add `go_crypto_tls_write_exit`**: compute the same composite id, read `n = GO_PARAM1(ctx)` (return value of `crypto/tls.(*Conn).Write`), look up + delete the stash; if `n <= 0` return 0; call `finish_write(ctx, fd, /*is_tls=*/1, /*socket_only=*/1, buf, MIN(stashed_size, (__u64)n), 0)`.

- [ ] **Step 4: Attach the new uretprobe in `tls.go`** — add `{symbol: goTlsWriteSymbol, uretprobe: "go_crypto_tls_write_exit"}` to the `uprobeSpec` list in `AttachGoTlsUprobes`.

- [ ] **Step 5: Rebuild and run existing HTTP/2-TLS tests**

Run: `make docker-test DOCKER_TEST_ARGS='-count=1 -timeout 10m -v github.com/coroot/coroot-node-agent/ebpftracer -run TestHttp2Tls'`  
Expected: PASS unchanged (this plan's Task 3 test is what actually exercises a short write; normal writes behave the same as before since `n == size` when nothing is short).

---

### Task 3: Short-write regression test

**Files:**
- Modify: `ebpftracer/tracer_test.go`

**Interfaces:**
- Consumes: `runTracer`, a small helper program that forces a short raw `write()`
- Produces: a passing test that asserts the traced event's byte count matches the *actual* short write, not the requested size

- [ ] **Step 1: Write a failing test.** Add a minimal Go helper program that: opens a raw TCP connection to a server that never `read()`s (so the send buffer fills), sets a small `SO_SNDBUF` via `syscall.SetsockoptInt`, switches the socket to non-blocking (`syscall.SetNonblock`), and calls `syscall.Write` with a buffer larger than the send buffer until it observes a short write (`n < len(buf)`, no error) — recording that `n` to a file the test can read.

```go
func TestWriteSyscallShortWriteAccounting(t *testing.T) {
	skipIfNotVM(t)
	getEvent, stop := runTracer(t, false)
	defer stop()

	// server: accepts, never reads
	// client helper: shrinks SO_SNDBUF, writes a big buffer non-blocking,
	// writes the observed short-write `n` and the buffer's first bytes to a result file
	clientPid, addr, gotN, sentPrefix := runShortWriteClient(t)

	e := waitForRawWrite(t, getEvent, clientPid, addr)
	require.Equal(t, gotN, int(e.L7Request.PayloadSize), "traced size must match the actual short write, not the requested buffer size")
	require.Equal(t, sentPrefix, e.L7Request.Payload[:len(sentPrefix)])
}
```

- [ ] **Step 2: Run the test (expect fail) before Task 1**

Run: `make docker-test DOCKER_TEST_ARGS='-count=1 -timeout 10m -v github.com/coroot/coroot-node-agent/ebpftracer -run TestWriteSyscallShortWriteAccounting'`  
Expected: fail — today's traced size equals the full requested buffer length, not the short `n`.

- [ ] **Step 3: Re-run after Task 1**

Same command. Expected: PASS.

- [ ] **Step 4: (If time allows) add a GoTLS variant** using the existing `attachGoTls` helper and a Go TLS client whose peer never reads, to exercise Task 2's `go_crypto_tls_write_exit` path the same way. If reliably forcing a short write through `crypto/tls.(*Conn).Write` proves too flaky in CI (TLS buffering can absorb small backpressure), it's acceptable to leave this as a follow-up and rely on Task 2's unit-level review + the raw-syscall test for coverage — note that decision here rather than silently skipping it.

---

## Self-review

1. **Spec coverage:** requested-vs-actual size gap, `bytes_sent` over-count, classifier seeing unset bytes, raw syscalls + GoTLS fixed, OpenSSL/rustls explicitly deferred with a stated reason, tests. All have tasks.
2. **Placeholders:** none load-bearing; Task 3 Step 4 is explicitly allowed to be deferred with a stated reason rather than silently dropped.
3. **Types:** `finish_write` reuses today's `trace_enter_write` body unchanged; new structs (`write_args`, GoTLS write stash) are small and explicit.

---

## Execution

Plan saved to `coroot-node-agent/docs/superpowers/plans/2026-09-16-write-syscall-short-write-tracking.md`.

Two execution options:

1. **Subagent-Driven (recommended)** — one subagent per task, review between tasks
2. **Inline Execution** — implement in this session with checkpoints

Which approach?

# Drops that no metric shows

**Status:** open, unmeasured. **Severity:** unknown.

These paths drop data silently. If a run loses events with every counter at 0,
suspect one of them.

1. **`scratch_lookup` returning NULL** (`ebpf/tcp/state.c`, task storage via
   `bpf_task_storage_get`). Every caller just returns. A counter is not added
   inside the helper because it is inlined 40+ times and the programs are within
   a few percent of the verifier limit. Add one at a single site, for example
   `http1_flush`, to measure it.
2. **`http2_flush` / `send_event` when `active_connections` has no entry.** The
   event is discarded without a counter.
3. **`bpf_ringbuf_discard_dynptr` after a failed `bpf_dynptr_write` or
   `bpf_probe_read_*_dynptr`** in `http2_flush` and `send_event`. Only the
   reserve failure is counted (`l7_events_dropped`).
4. **Userspace:** `onConnectionOpen` returns without a log or counter for
   filtered ports/addresses (`PortFilter`, `ConnectionFilter`, loopback outside
   the host netns). `ConnectionError`/`Open` for an unknown process is dropped.
5. **`getOrCreateContainer` returning nil** for a pid whose cgroup cannot be read
   is counted only as `node_l7_dropped_unknown_container_total`; the pid is then
   negative-cached for 15 s (`IgnoredContainersCacheTTL`).
6. **A failed user-memory read after all retries** is counted
   (`node_ebpf_user_memory_read_failures_total`) but not retried further;
   `protocol_sniff` failed about once per stress run and means that the
   connection is never recognized as HTTP/HTTP2.

## Ideas

Add one counter per path above (kernel: indices 12-15 of `src_read_fail` are
free; userspace: `registry.go` counters) and run the stress series again.

# Untested environments

**Status:** nothing measured. All numbers in this directory come from one host.

The test host: Linux 6.18.15, `PREEMPT_LAZY`, 16 CPUs, THP enabled, a single
NUMA node, Docker over ssh (`DOCKER_CONTEXT=server`), a k3s node running on the
same machine.

Not tested:

- **arm64.** The BPF objects are compiled in `ebpftracer/Dockerfile` for the
  build machine's architecture only; there is no arm64 run. Check struct layouts
  (`_Static_assert(sizeof(struct connection) == 56)`), register conventions for
  the uprobes (`PT_REGS_PARM*`) and the Go-ABI argument registers in `gotls.c`.
- **Other kernels.** Task storage needs 5.11+; `bpf_loop` 5.17+; dynptrs 6.x. The
  fixed `struct sock_common` offsets in `emit_connection_open_lazy` (56 and 72 for
  the IPv6 addresses) are checked only on 6.18. Older kernels and `PREEMPT_NONE`
  or `PREEMPT_FULL` change how often BPF programs are preempted, which is where
  the scratch-space and recursion problems came from.
- **k3s/Kubernetes under real load.** Only a small k3s is on the test host. A
  busy node has many more processes, so the single `handleEvents` goroutine lags
  more (see the container-resolution race in `containers/registry.go`).
- **Other TLS libraries.** Only Node's embedded OpenSSL, Python's libssl, Go's
  `crypto/tls` and (by unit tests) the others in `ebpf/l7` were run. BoringSSL,
  GnuTLS, rustls and Java's JSSE were not.
- **Hosts with a small `max_entries` budget:** `active_connections`
  (`MAX_CONNECTIONS`), `http2_stream_budget` (8192), `http1_state` (4096),
  `write_replay` (8192), `active_l7_requests` (32768). LRU eviction on a busy
  node resets per-stream budgets and may drop connection state.

## Ideas

Run the stress series from [README.md](README.md) on a real node, an arm64 VM
and a 5.15 kernel, and compare the counters.

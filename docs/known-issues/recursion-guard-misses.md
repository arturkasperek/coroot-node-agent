# BPF programs skipped by the kernel's recursion guard

**Status:** open, impact unknown. **Severity:** unknown.

## Symptom

`node_ebpf_program_recursion_misses_total{program=...}` is non-zero in every
run, with and without stress:

- `inet_sock_set_state`: 10-60 per run
- `nf_ct_deliver_cached_events`: 150-270 per run
- `tcp_retransmit_skb`: 0-1

The kernel does not run a perf-attached tracepoint/kprobe program while another
BPF program is already active on the same CPU (softirq work arriving during a
long L7 walk is enough) and counts a miss instead.

## Why it matters

- A skipped `inet_sock_set_state` can be the `ESTABLISHED` transition (the
  connection-open event is never sent) or `SYN_SENT` (no `skaddr` is recorded, so
  the lazy open cannot recover it). The lazy open in `emit_connection_open_lazy`
  (`ebpf/tcp/state.c`) covers the first case only.
- A skipped `nf_ct_deliver_cached_events` loses the actual destination of a
  NATed connection (`actual_destinations`), so the span points at the service IP.
- We never saw a lost request that traced back to a miss, but we also could not
  tell one apart: the counter is global, not per connection.

## Ideas

1. Count the misses of the programs that matter per connection, or log the
   `(pid, fd)` when `SYN_SENT` is skipped.
2. For connections with no `skaddr`, recover the socket from the fd at the first
   data syscall (task -> files -> fdt -> file -> `private_data` -> `sock`). That
   needs CO-RE or fixed offsets; the program is built without kernel BTF.
3. Measure with `STRESS=cpu`: compare misses of `inet_sock_set_state` with
   `http2_dropped_no_connection_total` / `http1_dropped_no_connection_total`.

# TLS: a few requests never become spans

**Status:** open. **Severity:** low rate, but "no trace may be lost" is the goal.

## Symptom

`python-tls` and `node-tls` (the `h1-tls` targets of the e2e suite) lose one or
two requests per run of 4000, with and without stress. Typical output:

```
FAIL target=python-tls proto=h1-tls sent=3999 recorded=3997
     GET /users -> 2400 sent, 2399 recorded   MISSING n=[85]
```

Measured: about 1 loss per 50k requests at the start of the investigation, still
1-2 per 8000 later. Every other target (go/node/python/php/java h1, h2c,
keep-alive) is at 1.00 without stress.

A later latency run (`make docker-test-latency`, see ../latency-benchmark.md)
showed a higher rate for one case: `node-tls` (a new TLS connection per request,
10 KB echo body) produced 3275 spans for 3323 requests, 1.4%. The same case with
a reused connection (`node-tls-ka`) lost 1 of 3323 and `python-tls` lost none.
That is the best lead so far: fresh TLS connection per request on Node.

## What we know

- The lost request is not mis-parsed: no span with that `n` exists in any bucket.
- All drop counters are 0 at those moments: `node_ebpf_lost_samples_total`,
  `node_ebpf_user_memory_read_failures_total{stage=...}`,
  `node_l7_http2_dropped_*`, `node_l7_dropped_unknown_container_total`.
- A few times we saw a **zero or foreign decrypted TLS buffer at uprobe exit**:
  `stage="tls_buf_zero_at_exit"`, resolved by a bounded wait
  (`tls_buf_wait_nonzero`, counted as `tls_buf_zero_recovered`) or not
  (`tls_buf_zero_persisted`). That explains only some of the cases.
- Some losses are connections that produced **no L7 event at all**.
- The container-resolution race (process exited before the agent handled its
  events) is fixed in `containers/registry.go` and is not the cause.

## Ideas

1. Per-TLS-connection counters in the uprobes: SSL_write/SSL_read entered,
   exited with ret > 0, event emitted. A loss then shows which step was skipped.
2. Check the uprobe on `SSL_read` exit for the case where `SSL_read` returns
   data decrypted earlier (no inner syscall), see `ssl_last_fd` in `l7.c`.
3. Check Node's async BIO path (`TLSWrap`), where decryption and the socket read
   are decoupled.
4. Rule out the write-retry duplication on the TLS path (see
   [write-retry-dedup-gaps.md](write-retry-dedup-gaps.md)): `SSL_write` retried
   after `WANT_WRITE` is captured twice. That would give *extra* data, not a
   missing request, but it can corrupt HTTP/1 state.

## Reproduce

```
DOCKER_CONTEXT=server ONLY=python-tls,node-tls N_REQUESTS=4000 bash e2e/run.sh
```
Repeat 10 times; expect one or two failing runs.

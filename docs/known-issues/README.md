# Known issues: lost or mis-parsed L7 events

Problems found while chasing lost traces with the e2e suite (`e2e/run.sh`) that
are **not fixed**. One file per problem. Each has the symptom, the numbers we
measured, what is already ruled out, and where to start.

| File | Problem | Size of the loss |
|---|---|---|
| [tls-residual-loss.md](tls-residual-loss.md) | A few TLS requests never become spans | ~1-2 per 8000; 1.4% on node-tls with a new connection per request |
| [keepalive-rare-loss-under-cpu-stress.md](keepalive-rare-loss-under-cpu-stress.md) | Keep-alive HTTP/1 loses a request at 99% CPU | 2 per 4000, once |
| [write-retry-dedup-gaps.md](write-retry-dedup-gaps.md) | Retried writes still counted twice on some paths | not measured |
| [http1-pipelining-depth.md](http1-pipelining-depth.md) | Deep HTTP/1 pipelining loses the tail of a buffer | by design, ~12-14 |
| [http1-by-design-limits.md](http1-by-design-limits.md) | Header/payload caps, close-delimited keep-alive, pending-request age | by design |
| [silent-drops-without-counters.md](silent-drops-without-counters.md) | Drops that no metric shows | unknown |
| [recursion-guard-misses.md](recursion-guard-misses.md) | BPF programs skipped by the kernel's recursion guard | unknown impact |
| [untested-environments.md](untested-environments.md) | arm64, other kernels, k3s under load, other TLS libraries | unknown |

## How the e2e suite is run

```
DOCKER_CONTEXT=server N_REQUESTS=4000 bash e2e/run.sh
```

Useful knobs (all environment variables of `e2e/run.sh`):

- `ONLY=go-h2c,node-h2c` runs only those targets.
- `CONCURRENCY=80` concurrent requests per target (default 20).
- `STRESS=cpu` one busy-loop burner per core (about 99% CPU); `STRESS=cpu50` one
  burner per core, busy and asleep in alternating slices of `STRESS_SLICE_MS`
  (default 1 ms), for about half the CPU; `STRESS=mem` memory churn plus forced compaction; `STRESS=1` both
  cpu and mem.
- `make docker-test-latency` measures the agent's latency cost (see [../latency-benchmark.md](../latency-benchmark.md)).
- `EDGE=1 ONLY=edge` HTTP/1 traffic at the edge of the capture (see
  `e2e/loadgen/edge.go`).

`verify` prints `MISSING n=[...]` per bucket and `unexpected spans:` for spans
that were produced with the wrong method/path/status. Agent counters are
printed before and after the load (`node_ebpf_*`, `node_l7_*`).

Harness flakes that are **not** agent bugs: `status 255` (ssh to the docker
host), `lookup svc-...: no such host`, `DeadlineExceeded` during image build.
Rerun those.

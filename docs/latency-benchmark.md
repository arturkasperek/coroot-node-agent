# Latency benchmark

`make docker-test-latency` measures how much the agent adds to the latency of
the e2e example services. It runs from this repo against a Docker host (set
`DOCKER_CONTEXT` for a remote one; the host needs a kernel the agent supports).

## What it does

For each case the same amount of data is sent: `TOTAL_BYTES` (10 MB) as
`POST /echo` bodies of `BODY_BYTES` (10 KB), so 1024 requests, and the echo comes
back. Requests are sequential (`LAT_CONCURRENCY=1`) so the numbers are latency,
not throughput.

1. **Phase 1, agent off.** `ROUNDS` (3) rounds of every case.
2. **Phase 2, agent on.** The real `coroot-node-agent` and a mock OTLP backend
   are started in the same container, the run waits until the agent has captured
   every destination (and attached its Go TLS uprobes to the benchmark binary),
   then the same rounds are repeated.

Output: p50, p99 and mean per case, off vs on (median over the rounds), the
agent's average CPU and RSS during phase 2, and **spans per case against requests
sent**. A case with fewer spans than requests was not fully captured, so its
latency is not the cost of a working capture (that check found the keep-alive
bug described below).

Cases (`e2e/latency/main.go`): `h1` new connection per request, `h1-ka` reused
connection, `h1-tls` new TLS connection per request, `h1-tls-ka` reused TLS
connection, `h2c`; on Go, Node, Python, PHP and Java services.

Knobs: `ROUNDS`, `TOTAL_BYTES`, `BODY_BYTES`, `LAT_CONCURRENCY`, and
`ONLY=go-h1,node-tls-ka` to run a few cases.

## A result (one host, Linux 6.18, 16 CPUs, Docker bridge network)

Agent off vs on, p50 (median of 3 rounds, 10 KB echo):

| case | off | on | added |
|---|---|---|---|
| h1, new connection (go/node/php/java) | 270-280 us | 380-440 us | +110 to +170 us |
| h1, new connection (python) | 410-480 us | 476 us | +15 to +70 us |
| h1, reused connection | 59-69 us | 144-218 us | +80 to +150 us |
| h2c (go/node) | 111-134 us | 158-173 us | +40 to +47 us |
| TLS, new connection | 1.29-1.45 ms | 1.52-1.58 ms | +0.15 to +0.23 ms |
| TLS, reused connection | 83-88 us | 236-263 us | +150 to +180 us |

The agent used about 45% of one core on average while the benchmark ran and
520 MB of RSS. 49.8k spans were exported for ~50k requests.

Read the percentages with care. The base latency here is tens to hundreds of
microseconds (Docker bridge, tiny handler), so a constant cost of 100-180 us per
request looks like +100-200%. On a service whose requests take milliseconds the
same cost is a few percent. The cost is per request, not per byte: it comes from
the syscall hooks and the frame/HTTP walk that run on the request path (one on
the write, one on the read).

## Caveats

- One host, one run, no pinning of CPUs; use it to compare before and after a
  change, not as an absolute number. Repeat before trusting a small difference.
- The agent shares the CPUs with the benchmark. On a loaded node the numbers are
  worse (see [known-issues](known-issues/README.md)).
- `node-tls` (new TLS connection per request, 10 KB body) lost 48 of 3323 spans in
  the last run; see [known-issues/tls-residual-loss.md](known-issues/tls-residual-loss.md).

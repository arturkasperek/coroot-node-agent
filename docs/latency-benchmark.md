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

## Memory

The run also prints the agent's memory twice (idle before the benchmark, and
after it): the process (`VmRSS` split into `RssAnon` and `RssFile`) and the
kernel memory pinned by the BPF maps and programs it loaded (`bytes_memlock`
from `bpftool`, taken as everything that did not exist before the agent
started). One measurement on the test host:

| | size | notes |
|---|---|---|
| Process, anonymous memory | ~73 MB | after startup settles; the startup peak was 470-860 MB (`VmHWM`) |
| Process, file-backed pages (`RssFile`) | ~391 MB | the binary, libraries and mapped files; clean pages, reclaimable, shared |
| BPF maps, pinned kernel memory | **465 MB** | 61 maps |
| BPF programs | 1.3 MB | 64 programs |

So "RSS 520 MB" is mostly file-backed pages and says little. The memory the agent
really owns is roughly 75 MB in the process plus 465 MB in the kernel, and almost
all of the kernel part is a handful of maps that are sized for the worst case and
allocated up front:

| map | type | pinned | max_entries |
|---|---|---|---|
| `active_connections` | LRU hash | 137 MB | 1,000,000 |
| `l7_events` | ring buffer | 135 MB | 128 MiB |
| `connection_id_by_socket` | LRU hash | 89 MB | 1,000,000 |
| `active_l7_requests` | LRU hash | 37 MB | 32,768 |
| `stacks` | stack trace | 17 MB | 16,384 |
| `tcp_connect_events` | ring buffer | 17 MB | 16 MiB |

None of this grows with load in the benchmark (the numbers before and after were
identical). To cut it, lower `MAX_CONNECTIONS` (`ebpf/tcp/state.c`) and the
`l7_events` size; both trade memory for headroom on a busy node (a full ring
buffer drops events, an over-full LRU map evicts live connections).

## Caveats

- One host, one run, no pinning of CPUs; use it to compare before and after a
  change, not as an absolute number. Repeat before trusting a small difference.
- The agent shares the CPUs with the benchmark. On a loaded node the numbers are
  worse (see [known-issues](known-issues/README.md)).
- `node-tls` (new TLS connection per request, 10 KB body) lost 48 of 3323 spans in
  the last run; see [known-issues/tls-residual-loss.md](known-issues/tls-residual-loss.md).

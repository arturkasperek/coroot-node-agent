# OOM kill of the agent at startup with a 1 GiB memory limit

**Status:** reproduced on the dev k3s node (2 of 3 starts killed). Measured 2026-10-08.
The second heap surge (reading the symbol tables) is fixed in `ebpftracer/elf.go`
(`GetSymbol` / `PrefetchSymbols` read the tables in place; see the tests in `ebpftracer/elf_test.go`).
Not yet re-measured on a real restart of the agent. The first surge (`loadCollection`) and the
fixed cost of the BPF maps are not fixed.
Nothing here was measured on EKS: no credentials were available.

The operator's default for the agent is `requests.memory 200Mi, limits.memory 1Gi`
(`coroot-operator/controller/node_agent.go:78-88`). The dev DaemonSet uses 1Gi too.

## Symptom

A freshly started agent container is `OOMKilled` within 7 s (`exitCode 137`),
twice in a row, then a third start survives. Same image, same node, nothing else
changed:

```
start 20:10:26 -> OOMKilled 20:10:33
start 20:10:33 -> OOMKilled 20:10:40
start 20:10:53 -> running (survived)
```

An agent that is already running is stable: `anon` 153-174 MB, `kernel` ~500 MB.

## Where the memory is (cgroup of the agent pod, `memory.stat`)

Only `anon` and `kernel` count against the limit when the page cache is
reclaimed. The page cache (`file`) fills up to the limit by design, so
`memory.peak == limit` proves nothing by itself.

| | steady state | startup peak (successful start) |
|---|---|---|
| `kernel` (BPF maps, vmalloc 302 MB) | ~500 MB | ~480 MB |
| `anon` (Go heap and stacks) | 153-174 MB | **460-472 MB** |
| `anon + kernel` (not reclaimable) | ~650-675 MB | **~950 MB** of 1024 MiB |

Kernel part: 65 BPF maps pinned **461 MB** (`/proc/PID/fdinfo`, `memlock`),
allocated at once by `loadCollection`. The big ones: `active_connections` 137 MB,
`l7_events` ring buffer 135 MB (was 16 MiB in `fcfdd9a`, raised to 128 MiB in
`3bb6c59`), `connection_id_by_socket` 89 MB, `active_l7_requests` 37 MB, two
`stacks` 17 MB each, `tcp_connect_events` 17 MB.

## Two Go heap surges at startup

1. **Loading the programs** (`ebpftracer/tracer.go`, `loadCollection`): one goroutine
   per program (59), each does `spec.Copy()` of the whole collection. One copy is
   2.8 MB, all 59 are alive together: ~150 MB of heap (165 MB allocated, measured on
   the real ELF; the live agent's allocation profile shows ~173 MB under `loadCollection`).
   With a 1 CPU limit this takes 26-28 s (`loaded ebpf collection in 26.122s`), so the
   copies stay alive for the whole time. The failed starts died in this window: `anon`
   293 MB and rising with `kernel` 456 MB at +2.5 s.
2. **The first uprobe attach after the load.** `ELFFile.readSymbols`
   (`ebpftracer/elf.go`) materializes the whole symbol table (`elf.Symbols()` plus
   `DynamicSymbols()`, every name copied into a string) to look up two names. For the
   agent's own binary (182 MB, 493k + 328k symbols) one call holds **216 MB live**
   (308 MB allocated). The attach to the agent's own process is logged at 20:11:25.7;
   the `anon` jump from 94 to 460 MB starts at 20:11:25.9. The memory then stays
   resident for ~10 s (Go returns it slowly): 472 MB for ~5 s, 391 MB for ~5 s, 70 MB
   after that.

`readSymbols` cost on the node's binaries (`debug/elf`, measured on copies):

| binary | symbols | live while read | allocated |
|---|---|---|---|
| coroot-node-agent (182 MB) | 821k | 216 MB | 308 MB |
| node (119 MB) | 227k | 67 MB | 103 MB |
| coroot-cluster-agent (148 MB) | 162k | 56 MB | 77 MB |
| k3s (213 MB, stripped) | 0 | 0 | 0 |

`clickhouse` (801 MB) and `clickhouse-keeper` (504 MB) run on that node too; their
symbol tables were not measured (the agent reads the symbols of Go and Node
binaries; whether it reads those of other C++ binaries was not checked).

When `attach()` returns no links (stripped k3s, python `libpthread`),
`AcquireGlobalUprobe` caches nothing, so the same table is read again for every
process that runs that binary. The attach runs under `globalUprobesLock`, so reads
are serialized, but each one still allocates the whole table.

## Why it is a coin flip

Surge 1 and surge 2 each need ~150-220 MB on top of ~480 MB of kernel memory and
~90-160 MB of baseline Go memory. They land 90-120 MB below the limit when
everything goes well. Anything that arrives at the same time (a Node.js process, the
profiler, the `dbus` reader, a larger binary) tips it over. The dev node has ~10
pods; a production node with more and bigger processes has less margin.

## Not the cause (measured)

- The steady-state Go heap: `HeapAlloc` 55-120 MB, 440 MB `HeapSys` only because of
  the startup peak (324 MB of it already returned to the OS).
- HTTP body capture: bounded by `--http-body-max-bytes` per message, `node_l7_http_bodies_total`
  shows `dropped_queue_full 0` here.

## Where to start

- (done) `readSymbols`: look names up without materializing the table. A prototype that
  streams the `.symtab` / `.dynsym` entries and compares the name in the string
  table in place found the same symbols with a **peak heap of 4.2 MB** instead of
  217 / 67 / 57 MB (agent / node / cluster-agent binaries), 0.1-0.4 s each.
- `loadCollection`: bound the parallelism (a semaphore of 4-8); with a 1 CPU limit
  it does not shorten the 26 s anyway, it only keeps 59 copies of the spec alive.
- Cache a failed attach by `(dev, ino)` too.
- `L7_EVENTS_RINGBUF_SIZE` (128 MiB) and `MAX_CONNECTIONS` (1,000,000, two maps of
  137 + 89 MB): the biggest fixed cost; a flag or a smaller default.
- `GOMEMLIMIT` below the limit minus the kernel part, so the Go heap shrinks before
  the kill.
- Stopgap: `spec.nodeAgent.resources.limits.memory: 2Gi` in the Coroot CR.

## Measurement caveats

- One small k3s node (kernel 6.18.15, 1 CPU limit on the pod), one image
  (`tilt-c3dccb98d1665009`); 3 starts observed.
- `memory.current` was ~170 MB above `anon + file + kernel` in `memory.stat` all the
  time; not explained.
- The copies of the binaries were read through `kubectl exec cat`, which put ~140 MB
  of page cache into the agent's cgroup (reclaimable, it does not change the numbers
  above).
- The surge sizes come from the symbol-table experiment (`debug/elf` on copies of
  the real binaries) and the timing match with the log, not from a heap profile
  taken at the peak.

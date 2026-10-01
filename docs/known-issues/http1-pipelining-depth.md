# Deep HTTP/1 pipelining loses the tail of a buffer

**Status:** open, partly by design. **Severity:** low (real clients hardly pipeline).

## Symptom

`EDGE=1 ONLY=edge bash e2e/run.sh` with `edgePipelineDepth` set to 28 or 40
(`e2e/loadgen/edge.go`): the first requests are recorded, the rest of the buffer
is not. Before the fix 13 of 40 were recorded; now about 28 requests without
bodies, or about 12-14 responses with bodies per read.

## Why

`http1_walk_impl` (`ebpf/l7/http1.c`) handles one phase per round and chains
rounds with `bpf_tail_call`. The kernel allows 33 tail calls per chain
(`HTTP1_MAX_ROUNDS` is 30 now, was 24). A request without a body takes one round
(it took two before the "known empty body" change), a response with a body takes
two (headers, data), a chunked body one per chunk piece. Whatever is left in the
buffer after the last round is never looked at: there is no next buffer to resume
in.

## Ideas

1. Handle a small body that is fully inside the buffer in the same round as
   its headers (no separate DATA round). Check the verifier budget first.
2. Continue the walk in the *next* syscall: remember the unread offset and
   resume. Needs the iovec to survive, which it does not now.
3. Replace the tail-call chain by a `bpf_loop` over phases. The comment in
   `http1_walk_impl` says an unrolled version blew the verifier limit.

The chunked case has the same cap: a body with many small chunks arriving in one
read can need more rounds than one buffer provides. The e2e `chunkedresp`
scenario (200 chunks, flushed one by one) passes because the chunks arrive in
separate reads.

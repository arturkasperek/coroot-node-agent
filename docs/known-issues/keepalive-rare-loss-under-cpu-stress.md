# Keep-alive HTTP/1 loses a request at 99% CPU

**Status:** open, seen once. **Severity:** low.

## Symptom

```
STRESS=cpu CONCURRENCY=80 N_REQUESTS=4000 bash e2e/run.sh
FAIL target=node-keepalive proto=h1-keepalive sent=4000 recorded=3998
```
Seen in 1 of 2 full-suite runs at about 99% CPU (`x_full_cpu_1`); the other run
and all runs without stress were clean. The target uses one shared connection
for every request, with response bodies from a few bytes to far past the
capture caps (`e2e/services/node-keepalive`).

## What we know

- Not the exit race and not the HTTP/2 duplicate-write bug (both fixed).
- No counter moved. The missing `n` values were not printed for this target
  (it matches by full URL, not by `?n=`); that makes it harder to see which
  response size was lost.

## Ideas

1. Make `h1-keepalive` carry `?n=&r=` (the service looks the whole URL up in a
   table, so it needs a route that ignores the query) so verify can name the
   missing requests and their response size.
2. Check the HTTP/1 state machine across a lost or reordered event on one
   long-lived connection: a single bad phase breaks every later request, so
   look at `http1_state` (`ebpf/l7/http1.c`) after an `EAGAIN`.
3. Re-run with `STRESS=cpu` and `ONLY=node-keepalive` many times to get a
   failure rate first.

#!/bin/bash
# Runs inside the privileged "agent" container: starts the mock OTLP
# backend, starts the real coroot-node-agent binary pointed at it, fires
# load against the example services (this container's own outbound
# requests are what coroot-node-agent's containers package needs to see —
# see the e2e design notes in e2e/README.md), then verifies everything
# sent shows up as recorded spans. Exit code is the verifier's.
set -uo pipefail

: "${TARGETS:?TARGETS env var required, e.g. go-h1|h1|http://svc-go:8081,go-h2c|h2c|http://svc-go:8082}"
N_REQUESTS="${N_REQUESTS:-500}"
CONCURRENCY="${CONCURRENCY:-20}"
# Upper bound only: on a host with a big pre-existing container population
# (e.g. a real k8s cluster sharing this box), coroot-node-agent's discovery
# scan can take well over 30s to even register this container's own cgroup.
# The actual gate is the readiness poll below, not a fixed sleep.
WARMUP_MAX_SECONDS="${WARMUP_MAX_SECONDS:-90}"
# 30s, not 15s: the OTLP batch exporter is asynchronous, and at 15s the last
# spans of a run were still in flight when verify read the backend. That
# showed up as targets sitting at 495-496/500 with nothing actually lost —
# every one of them disappeared at 30s (60/60 target measurements landed on
# exactly 1.00 across 6 consecutive runs), so it was the window being too
# tight, not a capture failure. Keep it generous: a shortfall reported here
# should mean a real one.
FLUSH_SECONDS="${FLUSH_SECONDS:-30}"
MOCKBACKEND_ADDR="${MOCKBACKEND_ADDR:-127.0.0.1:4318}"
MANIFEST=/tmp/manifest.json

echo "[run-agent] starting mockbackend on ${MOCKBACKEND_ADDR}"
mockbackend -addr "${MOCKBACKEND_ADDR}" &
MOCKBACKEND_PID=$!

echo "[run-agent] starting coroot-node-agent"
# --instrumentation-delay=0s: production defaults to 30s (avoid
# instrumenting short-lived processes) — this whole warmup+load+verify
# cycle can finish well inside that window, so the h1-tls targets'
# SSL_write/SSL_read uprobes (see attachTlsUprobes in containers/
# container.go) would never get attached in time otherwise.
# --log-per-second/--log-burst: the agent rate-limits its own log to 10 lines
# a second (burst 100) by default. Anything this suite greps the log for —
# the TLS-uprobe attach confirmation, per-connection diagnostics — is
# silently truncated to that budget, and a missing line then reads as "it
# never happened". Effectively unlimited here so the log can be trusted.
AGENT_LOG=/tmp/agent.log
coroot-node-agent \
  --listen=0.0.0.0:10300 \
  --collector-endpoint="http://${MOCKBACKEND_ADDR}" \
  --disable-gpu-monitoring \
  --disable-log-parsing \
  --scrape-interval=5s \
  --min-container-age=0s \
  --instrumentation-delay=0s \
  --log-per-second=1000000 \
  --log-burst=10000000 \
  > "${AGENT_LOG}" 2>&1 &
AGENT_PID=$!
# The agent's own log goes to AGENT_LOG only (not streamed live): the TLS
# uprobe gate below greps it, and a `tail -f` alongside that turned out to
# drop most of it from the combined e2e log, leaving no agent diagnostics
# at all. It's dumped in full at the end instead — see "agent log" below.

cleanup() {
  kill "${AGENT_PID}" "${MOCKBACKEND_PID}" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

# Resolve every distinct target host:port to the ip:port coroot-node-agent
# will actually see on the wire (it records raw socket destinations, never
# DNS names — see e2e/verify/main.go's hostPort()), so we can tell real
# discovery/capture readiness apart from "the agent process is merely up".
declare -A target_ipports=()
declare -A tls_ipports=()
IFS=',' read -ra target_specs <<< "${TARGETS}"
for spec in "${target_specs[@]}"; do
  proto="$(cut -d'|' -f2 <<< "${spec}")"
  base_url="${spec##*|}"
  hostport="${base_url#https://}"
  hostport="${hostport#http://}"
  host="${hostport%%:*}"
  port="${hostport##*:}"
  ip="$(getent hosts "${host}" | awk '{print $1}' | head -1)"
  if [ -n "${ip}" ]; then
    target_ipports["${ip}:${port}"]=1
    if [ "${proto}" = "h1-tls" ]; then
      tls_ipports["${ip}:${port}"]=1
    fi
  fi
done

echo "[run-agent] waiting (up to ${WARMUP_MAX_SECONDS}s) for coroot-node-agent to discover+capture all ${#target_ipports[@]} targets: ${!target_ipports[*]}"

deadline=$((SECONDS + WARMUP_MAX_SECONDS))
ready=0
while [ "${SECONDS}" -lt "${deadline}" ]; do
  for spec in "${target_specs[@]}"; do
    base_url="${spec##*|}"
    # /healthz, not /users: this probe traffic gets captured too, and if a
    # probe's span lands just after the /api/reset below (the eBPF-ringbuf
    # -> OTLP export pipeline is async, so the last probe or two can still
    # be in flight when reset fires), it must not be able to land in one of
    # verify's counted (method, path, status) buckets and inflate the real
    # measured ratio — see e2e/verify/main.go's matching, which is coarse
    # (ip:port + method + path + status, no per-request id).
    curl -sk -m 2 -o /dev/null "${base_url}/healthz" || true
  done
  spans_seen="$(curl -s -m 5 "http://${MOCKBACKEND_ADDR}/api/spans" || true)"
  missing=0
  for ipport in "${!target_ipports[@]}"; do
    if ! grep -qF "${ipport}" <<< "${spans_seen}"; then
      missing=$((missing + 1))
    fi
  done
  if [ "${missing}" -eq 0 ]; then
    ready=1
    break
  fi
  sleep 1
done

if [ "${ready}" -eq 1 ]; then
  echo "[run-agent] all targets observed, resetting mockbackend before real load"
else
  echo "[run-agent] WARNING: not all targets observed capture within ${WARMUP_MAX_SECONDS}s, proceeding anyway" >&2
fi
# Prime the loadgen binary, then confirm its Go TLS uprobes are actually
# attached — and do it HERE, after the readiness loop above, not before it.
# Go TLS uprobes (see ebpftracer/tls.go's AcquireGlobalUprobe) attach to the
# *executable file*, not a specific PID, and once attached they cover every
# later process of that same binary. But nothing attaches until the agent
# sees that process's own EventTypeConnectionOpen (registry.go), which a
# priming run can only produce once the target service actually accepts the
# connection. Run before the readiness loop, every priming attempt failed at
# connect() against a service that wasn't listening yet, so the gate always
# timed out and the real, measured load then raced the attach itself —
# losing whichever prefix of the run happened first, uniformly across every
# route (measured: ratios down to 0.72 with the per-route split flat at
# 72/73/72, and http1_events_tls scaling down in exact proportion while
# every drop counter stayed 0).
if [ "${#tls_ipports[@]}" -gt 0 ]; then
  echo "[run-agent] priming+confirming loadgen's Go TLS uprobes"
  # Prime sparsely, then just watch the log. An earlier version re-ran
  # loadgen every second for up to 180s; that spawned ~180 short-lived
  # processes opening ~10 connections each, and the resulting churn is
  # itself what starves handleEvents (each new pid costs a ReadCgroup, and
  # every one of them is dead by the time its events are handled). It left
  # the agent ~10k unresolvable-container events deep in backlog at the
  # moment the measured load started — measured: 5502 HTTP/1 events
  # processed during a run that began that way, versus 14159 for one that
  # did not, with identical load. One prime is enough to trigger the
  # attach; the rest is just waiting for it — but it has to stay alive
  # while that happens (-hold), or the agent reaches its connect event
  # after the process is gone, finds no /proc entry, resolves no container,
  # and never attaches. Measured before -hold: the loadgen attach landed at
  # the start of the *real* load every single time, i.e. this gate could
  # never succeed and the measured run always raced the attach.
  loadgen -n 1 -concurrency 1 -hold 20s -targets "${TARGETS}" -manifest /tmp/manifest-warmup.json >/dev/null 2>&1 &
  last_prime=${SECONDS}
  tls_deadline=$((SECONDS + 120))
  tls_ready=0
  while [ "${SECONDS}" -lt "${tls_deadline}" ]; do
    if grep -F 'golang_app=/usr/local/bin/loadgen' "${AGENT_LOG}" 2>/dev/null | grep -q 'crypto/tls uprobes attached'; then
      tls_ready=1
      break
    fi
    if [ $((SECONDS - last_prime)) -ge 20 ]; then
      loadgen -n 1 -concurrency 1 -hold 20s -targets "${TARGETS}" -manifest /tmp/manifest-warmup.json >/dev/null 2>&1 &
      last_prime=${SECONDS}
    fi
    sleep 1
  done
  if [ "${tls_ready}" -eq 1 ]; then
    echo "[run-agent] loadgen's TLS uprobes confirmed working (waited ~${SECONDS}s since agent start)"
  else
    echo "[run-agent] WARNING: could not confirm loadgen's TLS uprobes within 120s, proceeding anyway" >&2
  fi
fi

# The held priming processes have served their purpose (the attach is
# per-executable and outlives them); don't leave them sitting in the
# process table across the measured load.
pkill -f 'loadgen .*-hold' >/dev/null 2>&1 || true

# Let anything still in flight (priming spans, and whatever backlog the
# warmup left in the agent's event queue) settle before the reset below.
# Priming drives the same routes the real load does, so a priming span that
# lands after the reset is counted as if the real load produced it — that
# is what pushed measured ratios above 1.00 (1.01, 1.02) in earlier runs.
sleep 5

curl -s -m 5 -X POST "http://${MOCKBACKEND_ADDR}/api/reset" -o /dev/null || true

echo "[run-agent] agent health counters (before load):"
curl -s http://127.0.0.1:10300/metrics 2>&1 | grep "node_ebpf_\|node_traces_\|node_l7_http1_\|node_l7_http2_\|node_l7_payloads_truncated\|node_l7_event_queue_depth\|node_l7_tls_attach_seconds\|node_l7_dropped_unknown_container" | grep -v '^#' || true

# STRESS=1: background pressure while the measured load runs — CPU burners on
# every core, memory churn plus forced compaction (page migration is what makes
# nofault user-memory reads fail transiently), to probe loaded-host behavior.
STRESS_PIDS=()
# STRESS=cpu or STRESS=mem runs just one of the two.
if [ "${STRESS:-0}" != "0" ]; then
  echo "[run-agent] STRESS=${STRESS}: cpu burners + memory churn + forced compaction (cpu/mem select one)"
fi
if [ "${STRESS:-0}" = "1" ] || [ "${STRESS:-0}" = "cpu" ]; then
  for _ in $(seq "$(nproc)"); do
    ( while :; do :; done ) &
    STRESS_PIDS+=($!)
  done
fi
if [ "${STRESS:-0}" = "1" ] || [ "${STRESS:-0}" = "mem" ]; then
  ( while :; do
      python3 -c 'b=[bytearray(64<<20) for _ in range(16)]
import time; time.sleep(0.5)' 2>/dev/null
      echo 1 > /proc/sys/vm/compact_memory 2>/dev/null
    done ) &
  STRESS_PIDS+=($!)
fi

echo "[run-agent] generating load: ${N_REQUESTS} requests/target, targets=${TARGETS}"
if ! loadgen -n "${N_REQUESTS}" -concurrency "${CONCURRENCY}" -targets "${TARGETS}" -manifest "${MANIFEST}"; then
  echo "[run-agent] loadgen failed" >&2
  exit 1
fi

if [ "${#STRESS_PIDS[@]}" -gt 0 ]; then kill "${STRESS_PIDS[@]}" 2>/dev/null || true; fi

echo "[run-agent] waiting ${FLUSH_SECONDS}s for the OTLP batch exporter to flush"
sleep "${FLUSH_SECONDS}"

echo "[run-agent] agent health counters (after load):"
curl -s http://127.0.0.1:10300/metrics 2>&1 | grep "node_ebpf_\|node_traces_\|node_l7_http1_\|node_l7_http2_\|node_l7_payloads_truncated\|node_l7_event_queue_depth\|node_l7_tls_attach_seconds\|node_l7_dropped_unknown_container" | grep -v '^#' || true

# Dump the agent's own warnings/errors (deduplicated, pids/ids masked so
# repeats collapse) — the single most useful thing to have when a run
# undercaptures, and invisible otherwise since the agent logs to a file.
echo "[run-agent] agent log: warnings/errors (deduplicated)"
grep -E "^(W|E)" "${AGENT_LOG}" 2>/dev/null \
  | sed 's/[0-9]\{4,\}/N/g' | sort | uniq -c | sort -rn | head -25 || true
echo "[run-agent] agent log: TLS uprobe attachments"
grep -F "uprobes attached" "${AGENT_LOG}" 2>/dev/null | tail -5 || true
echo "[run-agent] agent log: L7 events for unresolvable containers"
grep -F "l7 event for unresolvable container" "${AGENT_LOG}" 2>/dev/null | head -10 || true

echo "[run-agent] verifying"
verify -backend "http://${MOCKBACKEND_ADDR}" -manifest "${MANIFEST}" -wait 20s
RC=$?
exit "${RC}"

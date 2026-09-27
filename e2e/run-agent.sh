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
FLUSH_SECONDS="${FLUSH_SECONDS:-15}"
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
coroot-node-agent \
  --collector-endpoint="http://${MOCKBACKEND_ADDR}" \
  --disable-gpu-monitoring \
  --disable-log-parsing \
  --scrape-interval=5s \
  --min-container-age=0s \
  --instrumentation-delay=0s \
  2>&1 | sed 's/^/[agent] /' &
AGENT_PID=$!

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
IFS=',' read -ra target_specs <<< "${TARGETS}"
for spec in "${target_specs[@]}"; do
  base_url="${spec##*|}"
  hostport="${base_url#http://}"
  host="${hostport%%:*}"
  port="${hostport##*:}"
  ip="$(getent hosts "${host}" | awk '{print $1}' | head -1)"
  if [ -n "${ip}" ]; then
    target_ipports["${ip}:${port}"]=1
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
curl -s -m 5 -X POST "http://${MOCKBACKEND_ADDR}/api/reset" -o /dev/null || true

echo "[run-agent] generating load: ${N_REQUESTS} requests/target, targets=${TARGETS}"
if ! loadgen -n "${N_REQUESTS}" -concurrency "${CONCURRENCY}" -targets "${TARGETS}" -manifest "${MANIFEST}"; then
  echo "[run-agent] loadgen failed" >&2
  exit 1
fi

echo "[run-agent] waiting ${FLUSH_SECONDS}s for the OTLP batch exporter to flush"
sleep "${FLUSH_SECONDS}"

echo "[run-agent] verifying"
verify -backend "http://${MOCKBACKEND_ADDR}" -manifest "${MANIFEST}" -wait 20s
RC=$?
exit "${RC}"

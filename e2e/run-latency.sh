#!/bin/bash
# Runs inside the privileged "agent" container: measures request latency of the
# example services first WITHOUT the agent, then with the real
# coroot-node-agent running, and prints both side by side. Both phases run from
# this same container against the same service containers, so the only
# difference between them is the agent. See e2e/latency/main.go for the cases.
set -uo pipefail

: "${LAT_TARGETS:?LAT_TARGETS env var required, e.g. go-h1|h1|http://svc-go:8081}"
ROUNDS="${ROUNDS:-3}"
TOTAL_BYTES="${TOTAL_BYTES:-10485760}"
BODY_BYTES="${BODY_BYTES:-10240}"
LAT_CONCURRENCY="${LAT_CONCURRENCY:-1}"
WARMUP_MAX_SECONDS="${WARMUP_MAX_SECONDS:-90}"
MOCKBACKEND_ADDR="${MOCKBACKEND_ADDR:-127.0.0.1:4318}"
OUT=/tmp/lat
mkdir -p "${OUT}"

bench() { # bench <out.json> [extra latbench args]
  local out="$1"; shift
  latbench -targets "${LAT_TARGETS}" -total-bytes "${TOTAL_BYTES}" -body-bytes "${BODY_BYTES}" \
    -concurrency "${LAT_CONCURRENCY}" -out "${out}" "$@" 2>&1 | sed 's/^[0-9/]* [0-9:]* /  /'
}

cpu_ticks() { # utime+stime of a pid, in clock ticks
  awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0
}

echo "[latency] ${ROUNDS} rounds per phase, $((TOTAL_BYTES / 1024 / 1024)) MB per case in ${BODY_BYTES}-byte requests, concurrency ${LAT_CONCURRENCY}"

# Phase 1: no agent. One unmeasured pass first so connection pools, JITs and
# page caches of the services are warm for both phases alike.
echo "[latency] phase 1: baseline (no agent)"
bench "${OUT}/discard.json" -total-bytes 524288 >/dev/null
for r in $(seq "${ROUNDS}"); do
  echo "[latency] baseline round ${r}"
  bench "${OUT}/base_${r}.json"
done

# Phase 2: with the agent.
echo "[latency] starting mockbackend and coroot-node-agent"
mockbackend -addr "${MOCKBACKEND_ADDR}" &
MOCKBACKEND_PID=$!
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
cleanup() {
  kill "${AGENT_PID}" "${MOCKBACKEND_PID}" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

declare -A target_ipports=()
IFS=',' read -ra target_specs <<< "${LAT_TARGETS}"
for spec in "${target_specs[@]}"; do
  base_url="${spec##*|}"
  hostport="${base_url#https://}"; hostport="${hostport#http://}"
  host="${hostport%%:*}"; port="${hostport##*:}"
  ip="$(getent hosts "${host}" | awk '{print $1}' | head -1)"
  [ -n "${ip}" ] && target_ipports["${ip}:${port}"]=1
done

echo "[latency] waiting (up to ${WARMUP_MAX_SECONDS}s) for the agent to capture all ${#target_ipports[@]} destinations"
deadline=$((SECONDS + WARMUP_MAX_SECONDS))
ready=0
while [ "${SECONDS}" -lt "${deadline}" ]; do
  for spec in "${target_specs[@]}"; do
    curl -sk -m 2 -o /dev/null "${spec##*|}/healthz" || true
  done
  spans_seen="$(curl -s -m 5 "http://${MOCKBACKEND_ADDR}/api/spans" || true)"
  missing=0
  for ipport in "${!target_ipports[@]}"; do
    grep -qF "${ipport}" <<< "${spans_seen}" || missing=$((missing + 1))
  done
  if [ "${missing}" -eq 0 ]; then ready=1; break; fi
  sleep 1
done
[ "${ready}" -eq 1 ] || echo "[latency] WARNING: not every destination was captured within ${WARMUP_MAX_SECONDS}s" >&2

# latbench is a Go program: the agent attaches its crypto/tls uprobes per
# executable once it has seen a live process of it (see run-agent.sh).
if grep -q 'tls' <<< "${LAT_TARGETS}"; then
  echo "[latency] priming latbench's Go TLS uprobes"
  latbench -targets "${LAT_TARGETS}" -total-bytes 2048 -body-bytes 1024 -warmup 0 -hold 20s >/dev/null 2>&1 &
  for _ in $(seq 120); do
    grep -F 'golang_app=/usr/local/bin/latbench' "${AGENT_LOG}" 2>/dev/null | grep -q 'crypto/tls uprobes attached' && break
    sleep 1
  done
  pkill -f 'latbench .*-hold' >/dev/null 2>&1 || true
fi
sleep 5
curl -s -m 5 -X POST "http://${MOCKBACKEND_ADDR}/api/reset" -o /dev/null || true

echo "[latency] phase 2: with the agent"
bench "${OUT}/discard.json" -total-bytes 524288 >/dev/null
TICKS_PER_SEC="$(getconf CLK_TCK)"
t0_ticks="$(cpu_ticks "${AGENT_PID}")"
t0_wall="${SECONDS}"
for r in $(seq "${ROUNDS}"); do
  echo "[latency] agent round ${r}"
  bench "${OUT}/agent_${r}.json"
done
t1_ticks="$(cpu_ticks "${AGENT_PID}")"
t1_wall="${SECONDS}"

sleep 20 # let the exporter flush before counting spans
spans="$(curl -s -m 10 "http://${MOCKBACKEND_ADDR}/api/spans" | grep -o '"http.url"' | wc -l)"
rss_kb="$(awk '/VmRSS/{print $2}' "/proc/${AGENT_PID}/status" 2>/dev/null)"

# Spans per destination against the requests sent there during the agent
# phase (measured rounds, their warm-up and the two unmeasured passes). A
# destination with far fewer spans than requests was not (fully) captured, and
# its latency above says little about the agent's cost.
curl -s -m 10 "http://${MOCKBACKEND_ADDR}/api/spans" > "${OUT}/spans.json"
python3 - "${OUT}/spans.json" "${LAT_TARGETS}" "${ROUNDS}" "${TOTAL_BYTES}" "${BODY_BYTES}" <<'PY'
import json, sys, collections
spans = json.load(open(sys.argv[1]))
targets = [t.split("|", 2) for t in sys.argv[2].split(",")]
rounds, total, body = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
per = total // body
got = collections.Counter()
for sp in spans:
    u = sp.get("attributes", {}).get("http.url", "")
    if "case=" in u:
        got[u.split("case=", 1)[1].split("&", 1)[0]] += 1
# measured rounds + 50 warm-up each, and the one unmeasured pass of the agent phase
want = rounds * (per + 50) + (524288 // body + 50)
print("spans per case (agent phase):")
bad = 0
for name, proto, base in targets:
    mark = "" if got[name] >= 0.99 * want else "   <-- FEWER SPANS THAN REQUESTS"
    bad += bool(mark)
    print("  %-16s %-10s %6d spans for ~%6d requests%s" % (name, proto, got[name], want, mark))
if bad:
    print("  %d case(s) were not fully captured: their latency above is not the cost of a working capture." % bad)
PY

files=""
for r in $(seq "${ROUNDS}"); do
  files="${files:+${files},}${OUT}/base_${r}.json,${OUT}/agent_${r}.json"
done
echo
echo "== latency, agent off vs on (median over ${ROUNDS} rounds; $((TOTAL_BYTES / BODY_BYTES)) requests per case and round) =="
latbench -compare "${files}"
echo
awk -v t0="${t0_ticks}" -v t1="${t1_ticks}" -v w0="${t0_wall}" -v w1="${t1_wall}" -v hz="${TICKS_PER_SEC}" -v rss="${rss_kb:-0}" -v spans="${spans}" \
  'BEGIN{ w=w1-w0; if (w<1) w=1; printf "agent: %.1f%% of one core on average while the benchmark ran (%.0f CPU-seconds in %ds), RSS %.0f MB, %d spans exported\n", 100*(t1-t0)/hz/w, (t1-t0)/hz, w, rss/1024, spans }'

#!/bin/bash
# Orchestrates the whole e2e suite from the host (or CI) side: builds the
# swiss-army-knife image, starts one sibling container per example
# language service (so coroot-node-agent's cgroup-based container
# discovery sees each as its own container — see the design notes this
# script's comments reference), starts the privileged agent container
# (which itself runs the mock OTLP backend + the real agent binary + the
# load generator + the verifier — see run-agent.sh), and exits with the
# verifier's pass/fail status.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

IMAGE=coroot-node-agent-e2e
NET=coroot-e2e-net
KEEP="${KEEP:-0}"
N_REQUESTS="${N_REQUESTS:-500}"

containers=()

cleanup() {
  if [ "${KEEP}" = "1" ]; then
    echo "[run.sh] KEEP=1: leaving containers/network up for inspection:"
    printf '  %s\n' "${containers[@]}"
    echo "  network: ${NET}"
    return
  fi
  echo "[run.sh] cleaning up"
  for c in "${containers[@]}"; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  docker network rm "${NET}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[run.sh] building ${IMAGE}"
docker build -f e2e/Dockerfile -t "${IMAGE}" . || exit 1

docker network rm "${NET}" >/dev/null 2>&1 || true
docker network create "${NET}" >/dev/null

start_service() {
  local name="$1"; shift
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --network "${NET}" "${IMAGE}" "$@" >/dev/null
  containers+=("$name")
}

echo "[run.sh] starting example services"
start_service svc-go go-service -addr1 :8081 -addr2 :8082
start_service svc-node node-service 8081 8082
start_service svc-python python-service 8081
start_service svc-php php-service 8081
start_service svc-java java-service 8081

TARGETS="go-h1|h1|http://svc-go:8081"
TARGETS="${TARGETS},go-h2c|h2c|http://svc-go:8082"
TARGETS="${TARGETS},node-h1|h1|http://svc-node:8081"
TARGETS="${TARGETS},node-h2c|h2c|http://svc-node:8082"
TARGETS="${TARGETS},python-h1|h1|http://svc-python:8081"
TARGETS="${TARGETS},php-h1|h1|http://svc-php:8081"
TARGETS="${TARGETS},java-h1|h1|http://svc-java:8081"

echo "[run.sh] running agent + load + verify"
docker rm -f coroot-e2e-agent >/dev/null 2>&1 || true
containers+=("coroot-e2e-agent")
docker run --name coroot-e2e-agent \
  --network "${NET}" \
  --privileged \
  --pid=host \
  --cgroupns=host \
  --ipc=host \
  --uts=host \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  --ulimit memlock=-1 \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -e TARGETS="${TARGETS}" \
  -e N_REQUESTS="${N_REQUESTS}" \
  "${IMAGE}" agent-orchestrator
RC=$?

if [ "$RC" -eq 0 ]; then
  echo "[run.sh] PASS"
else
  echo "[run.sh] FAIL (exit ${RC})"
  echo "[run.sh] --- coroot-node-agent / run-agent.sh output was printed above ---"
fi
exit "$RC"

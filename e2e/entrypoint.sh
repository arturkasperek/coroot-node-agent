#!/bin/bash
# Dispatches the swiss-army-knife e2e image to whichever role it's asked to
# play. Each example-language service and the agent-orchestrator role share
# this one image; only the command differs.
set -euo pipefail

role="${1:-}"
shift || true

case "$role" in
  go-service)
    exec go-service "$@"
    ;;
  node-service)
    exec node /e2e/services/node/server.js "$@"
    ;;
  node-keepalive-service)
    exec node /e2e/services/node-keepalive/server.js "$@"
    ;;
  python-service)
    exec python3 /e2e/services/python/server.py "$@"
    ;;
  php-service)
    port="${1:-8081}"
    exec php -S 0.0.0.0:"$port" /e2e/services/php/router.php
    ;;
  java-service)
    exec java -cp /usr/local/bin/java-classes Server "$@"
    ;;
  agent-orchestrator)
    exec run-agent.sh "$@"
    ;;
  latency-orchestrator)
    exec run-latency.sh "$@"
    ;;
  *)
    echo "unknown role: $role (expected go-service|node-service|node-keepalive-service|python-service|php-service|java-service|agent-orchestrator|latency-orchestrator)" >&2
    exit 2
    ;;
esac

#!/bin/sh
# Privileged containers still start without debugfs/tracefs; the tracer needs both
# to attach kprobes. Harmless if the host already mounted them (or they were bind-mounted).
set -e
mkdir -p /sys/kernel/debug /sys/kernel/tracing /sys/fs/bpf
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
# go-nvml leaves the NVML symbols undefined until libnvidia-ml is loaded, which only works
# with lazy symbol binding. The release build passes the same flag (see Dockerfile); without
# it the containers test binary dies at startup: "undefined symbol: nvmlDeviceSetMemClkVfOffset".
exec go test -ldflags "-extldflags='-Wl,-z,lazy'" "$@"

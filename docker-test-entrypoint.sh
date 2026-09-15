#!/bin/sh
# Privileged containers still start without debugfs/tracefs; the tracer needs both
# to attach kprobes. Harmless if the host already mounted them (or they were bind-mounted).
set -e
mkdir -p /sys/kernel/debug /sys/kernel/tracing /sys/fs/bpf
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
exec go test "$@"

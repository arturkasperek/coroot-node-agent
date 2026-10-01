# "Swiss army knife" image for the e2e suite: one image that can act as
# every role (the coroot-node-agent + mock backend + load generator +
# verifier, or any one of the example language services), selected by the
# command passed to entrypoint.sh. The eBPF bytecode is already embedded in
# ebpftracer/ebpf.go (committed, built via `make build-ebpf`), so building
# the agent here is a plain `go build` — no clang/eBPF toolchain needed.
FROM golang:1.24-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libsystemd-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /repo
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# -Wl,-z,lazy matches the real Dockerfile: go-nvml's cgo bindings declare
# (but don't link) the whole NVML C API, resolved at runtime via dlopen only
# if a GPU is actually present. Debian's toolchain defaults to eager
# (-z now) symbol binding, which would make the dynamic linker try to
# resolve every declared-but-unlinked NVML symbol at process startup and
# crash immediately on any host without libnvidia-ml — regardless of
# --disable-gpu-monitoring, since that flag is only checked after the
# process has already failed to start.
RUN mkdir -p /out/java-classes && \
    CGO_ENABLED=1 go build -ldflags "-extldflags='-Wl,-z,lazy'" -o /out/coroot-node-agent . && \
    go build -o /out/go-service ./e2e/services/go && \
    go build -o /out/mockbackend ./e2e/mockbackend && \
    go build -o /out/loadgen ./e2e/loadgen && \
    go build -o /out/verify ./e2e/verify && \
    go build -o /out/latbench ./e2e/latency

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl bash bpftool \
        nodejs npm \
        python3 \
        php-cli \
        default-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/ /usr/local/bin/
COPY --from=build /repo/e2e/services /e2e/services
COPY --from=build /repo/e2e/certs /e2e/certs
COPY e2e/entrypoint.sh e2e/run-agent.sh e2e/run-latency.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/run-agent.sh /usr/local/bin/run-latency.sh && \
    javac -encoding UTF-8 -d /usr/local/bin/java-classes /e2e/services/java/Server.java

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

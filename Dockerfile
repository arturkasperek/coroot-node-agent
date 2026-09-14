FROM debian:bookworm AS builder
# Debian rather than the official Golang image, which tracks a newer distro
# whose glibc would be newer than the UBI runtime below.
# Bookworm is glibc 2.36; UBI10 is 2.39.

RUN apt-get update && apt-get install -y \
    curl git build-essential pkg-config libsystemd-dev

ARG GO_VERSION=1.24.9
RUN curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz -o go.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz && rm go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /tmp/src
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
ARG VERSION=unknown
RUN CGO_ENABLED=1 go build -mod=readonly -ldflags "-extldflags='-Wl,-z,lazy' -X 'github.com/coroot/coroot-node-agent/flags.Version=${VERSION}'" -o coroot-node-agent .

FROM registry.access.redhat.com/ubi10/ubi

ARG VERSION=unknown
LABEL name="coroot-node-agent" \
      vendor="Coroot, Inc." \
      maintainer="Coroot, Inc." \
      version=${VERSION} \
      release="1" \
      summary="Coroot Node Agent." \
      description="Coroot Node Agent container image."

COPY LICENSE /licenses/LICENSE

COPY --from=builder /tmp/src/coroot-node-agent /usr/bin/coroot-node-agent
ENTRYPOINT ["coroot-node-agent"]

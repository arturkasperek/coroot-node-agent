.PHONY: all
all: lint test

.PHONY: test
test: go-test

.PHONY: lint
lint: go-mod go-vet go-fmt go-imports

.PHONY: go-mod
go-mod:
	go mod tidy

.PHONY: go-vet
go-vet:
	go vet ./...

.PHONY: go-fmt
go-fmt:
	gofmt -w .

.PHONY: go-imports
go-imports:
	go install golang.org/x/tools/cmd/goimports@latest
	goimports -w .

.PHONY: go-test
go-test:
	go test ./...

.PHONY: build-ebpf
build-ebpf:
	$(MAKE) -C ebpftracer build

# The agent only builds on linux, so on any other host `go test ./...` fails while
# resolving platform-specific packages. This runs the same suite in a container.
#
# VM=1 is always set: the ebpftracer tests load programs into the kernel.
# Flags share host PID/cgroup/IPC/UTS namespaces and kernel debug filesystems
# (Tetragon-style) so eBPF, /proc, and os.Getpid() see the same view as a
# host process. Network stays in the container so `tc netem` on lo does not
# break the host. The entrypoint still mounts tracefs/debugfs if missing.
DOCKER_TEST_IMAGE ?= coroot-node-agent-test
DOCKER_TEST_ARGS ?= -count=1 -timeout 10m ./...

.PHONY: docker-test
docker-test:
	docker build -f Dockerfile.test -t $(DOCKER_TEST_IMAGE) .
	docker run --rm \
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
		-e VM=1 \
		$(DOCKER_TEST_IMAGE) $(DOCKER_TEST_ARGS)

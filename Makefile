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

# The agent only builds on linux, so on any other host `go test ./...` fails while
# resolving platform-specific packages. This runs the same suite in a container.
#
# Tests that load programs into the kernel are gated behind VM, as they are when run
# under Vagrant: `make docker-test VM=1`. They additionally need kernel BTF, so they
# report themselves as skipped where the host kernel does not expose it.
DOCKER_TEST_IMAGE ?= coroot-node-agent-test
DOCKER_TEST_ARGS ?= ./...
VM ?=

.PHONY: docker-test
docker-test:
	docker build -f Dockerfile.test -t $(DOCKER_TEST_IMAGE) .
	docker run --rm --privileged -e VM=$(VM) $(DOCKER_TEST_IMAGE) $(DOCKER_TEST_ARGS)

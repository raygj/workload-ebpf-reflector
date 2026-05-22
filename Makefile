# MCP eBPF Reflector — Makefile
#
# Targets are ordered by the test hierarchy:
#   generate → build → vet → lint → test → vulncheck
#
# The eBPF generate step requires clang and Linux headers.
# On macOS, you can build and test the Go userspace code without
# generating eBPF bytecode (use `make test-extract` for pure Go tests).

.PHONY: all generate proto build vet lint test test-extract test-session test-stream test-adr006 vulncheck clean ci

# Default: full CI pipeline (minus generate, which needs clang + Linux)
all: build vet lint test vulncheck

# --- Code Generation ---

generate:
	@echo "==> Generating eBPF bytecode (requires clang)"
	go generate ./internal/ebpf/

proto:
	@echo "==> Generating protobuf + gRPC code"
	protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       api/v1/reflector.proto

# --- Build ---

build:
	@echo "==> Building reflector"
	go build -o bin/reflector ./cmd/reflector/
	@echo "==> Building reflector-map"
	go build -o bin/reflector-map ./cmd/reflector-map/

# --- Quality Gates ---

vet:
	@echo "==> go vet"
	go vet ./internal/extract/... ./internal/session/... ./internal/stream/... ./cmd/...

lint:
	@echo "==> golangci-lint"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./internal/extract/... ./internal/session/... ./internal/stream/... ./cmd/...; \
	else \
		echo "SKIP: golangci-lint not installed"; \
	fi

test: test-extract test-session test-stream
	@echo "==> All tests passed"

# Pure Go tests — no eBPF, runs anywhere
test-extract:
	@echo "==> Testing extract package"
	go test -race -v ./internal/extract/...

test-session:
	@echo "==> Testing session package"
	go test -race -v ./internal/session/...

test-stream:
	@echo "==> Testing stream package (gRPC integration)"
	go test -race -v ./internal/stream/...

# ADR-006 Option 4 prototype: d2i_X509 uprobe for SPIFFE extraction
# Requires Docker (Colima or Linux daemon). Runs a privileged container.
test-adr006:
	@chmod +x test/integration/adr006/run_test.sh
	@test/integration/adr006/run_test.sh

# Full tests including eBPF loading — Linux only
test-ebpf:
	@echo "==> Testing eBPF loader (Linux only)"
	go test -race -v ./internal/ebpf/...

vulncheck:
	@echo "==> govulncheck"
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "SKIP: govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)"; \
	fi

# --- CI (what GitHub Actions runs) ---

ci: build vet lint test vulncheck
	@echo "==> CI passed"

# --- Container Images ---

REGISTRY ?= ghcr.io/jray
TAG ?= latest

docker-build:
	@echo "==> Building container images"
	docker build -f build/Dockerfile.reflector -t $(REGISTRY)/mcp-ebpf-reflector:$(TAG) .
	docker build -f build/Dockerfile.reflector-map -t $(REGISTRY)/mcp-ebpf-reflector-map:$(TAG) .
	docker build -f build/Dockerfile.test-workload -t $(REGISTRY)/mcp-ebpf-reflector-test-workload:$(TAG) .

docker-push:
	@echo "==> Pushing container images"
	docker push $(REGISTRY)/mcp-ebpf-reflector:$(TAG)
	docker push $(REGISTRY)/mcp-ebpf-reflector-map:$(TAG)
	docker push $(REGISTRY)/mcp-ebpf-reflector-test-workload:$(TAG)

# --- Lab Demo ---

lab-demo:
	@chmod +x scripts/lab-demo.sh
	@scripts/lab-demo.sh

lab-down:
	docker compose down

# --- Cleanup ---

clean:
	rm -rf bin/
	rm -f reflector reflector-map
	docker compose down --rmi local 2>/dev/null || true

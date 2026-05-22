//go:build linux

package certebpf

// ADR-006 Option 4: generate Go bindings for the cert_hook eBPF program.
//
// Run: go generate ./internal/certebpf/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 certHook ./bpf/cert_hook.c

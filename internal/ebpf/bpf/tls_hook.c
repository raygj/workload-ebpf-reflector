// eBPF uprobe program for TLS plaintext capture — CRAWL stage.
//
// Hooks:
//   uprobe/SSL_write  — capture plaintext before encryption (outbound)
//   uprobe/SSL_read   — capture plaintext after decryption (inbound)
//
// Captures the first MAX_CAPTURE_BYTES of each SSL_write/SSL_read call
// and sends to userspace via ring buffer. Go code parses the plaintext
// for JWT (Authorization header), MCP tool names (JSON-RPC method), and
// byte counters.
//
// SPIFFE extraction from X.509 certificates requires reading OpenSSL
// internal structs (version-dependent offsets). Deferred to walk stage.
// The SPIFFE parser in Go is ready — it just needs DER bytes.
//
// Reflect-only mode per ADR-002. Observer, not enforcer.

#include "vmlinux_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Maximum bytes to capture from each SSL_write/SSL_read.
// 4096 bytes covers HTTP headers + OTLP protobuf export payloads (1-10 spans).
// Also covers JWT extraction and MCP JSON-RPC bodies (well under 1KB).
#define MAX_CAPTURE_BYTES 4096

// Event types for TLS data events
#define TLS_EVENT_WRITE 0  // SSL_write: outbound plaintext
#define TLS_EVENT_READ  1  // SSL_read: inbound plaintext

// TLS data event: captured plaintext from SSL_write or SSL_read.
// Struct layout must match extract.TLSDataEvent in Go.
struct tls_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u32 len;                          // actual bytes captured (<= MAX_CAPTURE_BYTES)
	__u32 original_len;                 // total bytes in the SSL call
	__u8  event_type;                   // TLS_EVENT_WRITE or TLS_EVENT_READ
	__u8  _pad[3];
	__u8  data[MAX_CAPTURE_BYTES];      // captured plaintext (NOT encrypted)
} __attribute__((packed));

// Ring buffer for TLS events
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MB
} tls_events SEC(".maps");

// Scratch map: store SSL_write/SSL_read arguments across entry/return probes.
// Keyed by pid_tgid (unique per thread).
// Store buf as address integer — bpf2go can't generate bindings for pointer fields.
struct ssl_args {
	__u64 buf;
	__u32 num;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct ssl_args);
} ssl_write_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct ssl_args);
} ssl_read_args SEC(".maps");

// --- SSL_write: capture outbound plaintext ---

SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct ssl_args args = {};
	args.buf = (__u64)(unsigned long)PT_REGS_PARM2(ctx);
	args.num = (__u32)PT_REGS_PARM3(ctx);

	bpf_map_update_elem(&ssl_write_args, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_write")
int uretprobe_ssl_write(struct pt_regs *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct ssl_args *args = bpf_map_lookup_elem(&ssl_write_args, &pid_tgid);
	if (!args)
		return 0;

	int ret = (int)PT_REGS_RC(ctx);
	if (ret <= 0)
		goto cleanup;

	struct tls_event *e = bpf_ringbuf_reserve(&tls_events, sizeof(*e), 0);
	if (!e)
		goto cleanup;

	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->event_type = TLS_EVENT_WRITE;
	e->original_len = (__u32)ret;
	__builtin_memset(e->_pad, 0, sizeof(e->_pad));

	// AND at assignment so verifier sees u32 range [0, 0xFFFF] from the start.
	// ret is already checked > 0; & 0xFFFF is safe (SSL sizes are << 65535).
	__u32 capture = ((__u32)ret) & 0xFFFF;
	if (capture > MAX_CAPTURE_BYTES)
		capture = MAX_CAPTURE_BYTES;
	if (!capture) {
		bpf_ringbuf_discard(e, 0);
		goto cleanup;
	}
	e->len = capture;

	if (bpf_probe_read_user(e->data, capture, (const void *)(unsigned long)args->buf) < 0) {
		bpf_ringbuf_discard(e, 0);
		goto cleanup;
	}

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&ssl_write_args, &pid_tgid);
	return 0;
}

// --- SSL_read: capture inbound plaintext ---

SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct ssl_args args = {};
	args.buf = (__u64)(unsigned long)PT_REGS_PARM2(ctx);
	args.num = (__u32)PT_REGS_PARM3(ctx);

	bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct ssl_args *args = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
	if (!args)
		return 0;

	int ret = (int)PT_REGS_RC(ctx);
	if (ret <= 0)
		goto cleanup;

	struct tls_event *e = bpf_ringbuf_reserve(&tls_events, sizeof(*e), 0);
	if (!e)
		goto cleanup;

	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->event_type = TLS_EVENT_READ;
	e->original_len = (__u32)ret;
	__builtin_memset(e->_pad, 0, sizeof(e->_pad));

	__u32 capture = ((__u32)ret) & 0xFFFF;
	if (capture > MAX_CAPTURE_BYTES)
		capture = MAX_CAPTURE_BYTES;
	if (!capture) {
		bpf_ringbuf_discard(e, 0);
		goto cleanup;
	}
	e->len = capture;

	if (bpf_probe_read_user(e->data, capture, (const void *)(unsigned long)args->buf) < 0) {
		bpf_ringbuf_discard(e, 0);
		goto cleanup;
	}

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&ssl_read_args, &pid_tgid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

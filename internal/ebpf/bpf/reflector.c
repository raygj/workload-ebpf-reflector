// eBPF program for the MCP eBPF Reflector — CRAWL stage.
//
// Hooks:
//   kprobe/tcp_connect     — outbound TCP connections (connect syscall)
//   kretprobe/inet_csk_accept — inbound TCP connections (accept syscall)
//
// Extracts 5-tuple (src IP, dst IP, src port, dst port, protocol) from
// the kernel sock struct and writes events to a BPF ring buffer.
//
// Does NOT: decrypt payloads, redirect traffic, modify connections.
// Reflect-only mode per ADR-002.

#include "vmlinux_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// Event types
#define EVENT_CONNECT 0
#define EVENT_ACCEPT  1

// IP protocol — we only hook TCP kprobes so this is always TCP
#define IPPROTO_TCP 6

// Connection event written to ring buffer, read by Go userspace.
// Struct layout must exactly match extract.RawEvent in Go.
struct event {
	__u64 timestamp_ns;     // bpf_ktime_get_ns()
	__u32 pid;              // process ID
	__u32 tid;              // thread ID
	__u32 src_addr;         // IPv4 source, network byte order
	__u32 dst_addr;         // IPv4 dest, network byte order
	__u16 src_port;         // source port, host byte order
	__u16 dst_port;         // dest port, host byte order
	__u8  protocol;         // IPPROTO_TCP
	__u8  event_type;       // EVENT_CONNECT or EVENT_ACCEPT
	__u8  af;               // AF_INET or AF_INET6
	__u8  _pad;
	__u8  src_addr6[16];    // IPv6 source (valid when af == AF_INET6)
	__u8  dst_addr6[16];    // IPv6 dest (valid when af == AF_INET6)
} __attribute__((packed));

// Ring buffer for events — sized in Go loader via map spec override
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MB, overridable from Go
} events SEC(".maps");

// Emit a connection event from a sock struct.
// Uses bpf_probe_read_kernel (no CO-RE) — struct layout must match kernel exactly.
// sock_common layout verified for Linux 4.x–6.x in vmlinux_types.h.
static __always_inline int emit_event(struct sock *sk, __u8 event_type) {
	struct event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->event_type = event_type;
	e->protocol = IPPROTO_TCP;
	e->_pad = 0;

	// Read sock_common in one probe_read (sk == &sk->__sk_common at offset 0)
	struct sock_common skc = {};
	if (bpf_probe_read_kernel(&skc, sizeof(skc), sk) < 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	__u16 family = skc.skc_family;
	e->af = (__u8)family;
	e->src_port = skc.skc_num;
	e->dst_port = bpf_ntohs(skc.skc_dport);

	if (family == AF_INET) {
		e->src_addr = skc.skc_rcv_saddr;
		e->dst_addr = skc.skc_daddr;
		__builtin_memset(e->src_addr6, 0, 16);
		__builtin_memset(e->dst_addr6, 0, 16);
	} else if (family == AF_INET6) {
		e->src_addr = 0;
		e->dst_addr = 0;
		// IPv6 addrs live in ipv6_pinfo — zero out for now; walk stage handles this
		__builtin_memset(e->src_addr6, 0, 16);
		__builtin_memset(e->dst_addr6, 0, 16);
	} else {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Hook: outbound TCP connection (client side)
// Plain kprobe (not BPF_KPROBE) — avoids function-type CO-RE relocations
// that require kernel BTF to export tcp_connect's signature.
SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *)(unsigned long)PT_REGS_PARM1(ctx);
	return emit_event(sk, EVENT_CONNECT);
}

// Hook: inbound TCP connection accepted (server side)
// inet_csk_accept returns the new child sock in the return register.
SEC("kretprobe/inet_csk_accept")
int kretprobe_inet_csk_accept(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *)(unsigned long)PT_REGS_RC(ctx);
	if (!sk)
		return 0;
	return emit_event(sk, EVENT_ACCEPT);
}

char LICENSE[] SEC("license") = "GPL";

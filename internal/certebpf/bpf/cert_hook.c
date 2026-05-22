// eBPF uprobe for X.509 cert DER capture — ADR-006 Option 4 prototype.
//
// Hook: uprobe/d2i_X509 + uretprobe/d2i_X509
//
// d2i_X509 is the public OpenSSL API that parses DER-encoded X.509 certificates.
// It is called internally by OpenSSL during TLS handshake processing when the
// peer's certificate arrives on the wire. No application modification required.
//
// Signature:
//   X509 *d2i_X509(X509 **px, const unsigned char **in, long len)
//     arg1 (rdi): X509 **px    — output (ignore at entry)
//     arg2 (rsi): const unsigned char **in  — pointer-to-pointer to DER input
//     arg3 (rdx): long len     — byte count of DER input
//
// Strategy:
//   - Entry probe: dereference **in to capture the DER buffer pointer + len, save to scratch map
//   - Return probe: if successful (ret != NULL), read DER bytes using the saved pointer
//
// The captured DER bytes flow to userspace via ring buffer. Go parses the
// X.509 cert and extracts the SPIFFE URI SAN (if present).
//
// Why d2i_X509 and not i2d_X509:
//   - d2i_X509 is called by OpenSSL itself during handshake — no app cooperation needed
//   - i2d_X509 (DER serialization) is typically called by the application explicitly
//   - d2i_X509 captures the cert at parse time, before it enters internal structs
//
// ADR-002 compliance: Reflect-only. Observer, not enforcer.

#include "vmlinux_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// BPF_ANY: flag for bpf_map_update_elem — overwrite any existing entry.
// Defined in linux/bpf.h; redefined here to avoid pulling in kernel headers.
#ifndef BPF_ANY
#define BPF_ANY 0
#endif

// Maximum DER bytes to capture. SPIFFE SVID certs (EC P-256) are typically
// 400–900 bytes. 2048 covers RSA-2048 certs and chains with extensions.
#define MAX_DER_BYTES 2048

// Cert event: captured DER bytes from a successful d2i_X509 call.
// Struct layout must match CertEvent in cert_loader.go.
struct cert_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u32 der_len;    // bytes captured in der[] (capped at MAX_DER_BYTES)
	__u32 orig_len;   // original len argument to d2i_X509
	__u8  der[MAX_DER_BYTES];
} __attribute__((packed));

// Ring buffer for cert events.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); // 4 MB
} cert_events SEC(".maps");

// Scratch map: save d2i_X509 args at entry so the return probe can use them.
// Keyed by pid_tgid. Stores the already-dereferenced DER pointer and length.
struct d2i_args {
	__u64 in_p;  // actual DER buffer address (dereferenced from **in at entry)
	__u32 len;
	__u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct d2i_args);
} d2i_active SEC(".maps");

SEC("uprobe/d2i_X509")
int uprobe_d2i_x509(struct pt_regs *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	// arg3 (rdx): long len — byte count of DER input
	long len = (long)PT_REGS_PARM3(ctx);

	// Sanity: reject zero or absurdly large cert claims
	if (len <= 0 || len > 65536)
		return 0;

	// arg2 (rsi): const unsigned char **in — pointer-to-pointer
	// PT_REGS_PARM2 returns unsigned long; store as u64 to avoid int-cast warnings.
	__u64 in_pp_addr = (__u64)PT_REGS_PARM2(ctx);
	if (!in_pp_addr)
		return 0;

	// Dereference once: read the 8-byte pointer value at in_pp_addr.
	// Result is the actual DER buffer address.
	__u64 in_p_addr = 0;
	if (bpf_probe_read_user(&in_p_addr, sizeof(in_p_addr), (void *)in_pp_addr) < 0)
		return 0;
	if (!in_p_addr)
		return 0;

	struct d2i_args args = {
		.in_p = in_p_addr,
		.len  = (__u32)len,
		._pad = 0,
	};
	bpf_map_update_elem(&d2i_active, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("uretprobe/d2i_X509")
int uretprobe_d2i_x509(struct pt_regs *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	// Only capture successful calls — return value is X509* (non-NULL on success)
	__u64 ret = (__u64)PT_REGS_RC(ctx);
	if (!ret)
		goto cleanup;

	struct d2i_args *args = bpf_map_lookup_elem(&d2i_active, &pid_tgid);
	if (!args)
		return 0;

	struct cert_event *e = bpf_ringbuf_reserve(&cert_events, sizeof(*e), 0);
	if (!e)
		goto cleanup;

	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid          = pid_tgid >> 32;
	e->tid          = (__u32)pid_tgid;
	e->orig_len     = args->len;

	__u32 capture = args->len;
	if (capture > MAX_DER_BYTES)
		capture = MAX_DER_BYTES;
	e->der_len = capture;

	// bpf_probe_read_user writes exactly MAX_DER_BYTES. Unused trailing bytes
	// are irrelevant — Go uses der_len to bound the valid DER data.
	if (bpf_probe_read_user(e->der, MAX_DER_BYTES, (void *)args->in_p) < 0) {
		bpf_ringbuf_discard(e, 0);
		goto cleanup;
	}

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&d2i_active, &pid_tgid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

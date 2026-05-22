// Minimal kernel type definitions for CO-RE eBPF programs.
// These use __attribute__((preserve_access_index)) so libbpf/cilium-ebpf
// relocates field offsets at load time via BTF. No full vmlinux.h needed.
//
// Targets: Linux 5.8+ (ring buffer), RHEL 9 / OCP 4.16 (kernel 5.14).

#ifndef __VMLINUX_TYPES_H__
#define __VMLINUX_TYPES_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum; // used by bpf_helper_defs.h (bpf_csum_diff)

// Map update flags (linux/bpf.h)
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2

// BPF map types (from linux/bpf.h — stable values, won't change across kernels)
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC      = 0,
	BPF_MAP_TYPE_HASH        = 1,
	BPF_MAP_TYPE_ARRAY       = 2,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_RINGBUF     = 27,
};

// Address families
#define AF_INET  2
#define AF_INET6 10

// IPv6 address
struct in6_addr {
	union {
		__u8 s6_addr[16];
		__be32 s6_addr32[4];
	} in6_u;
};

// Socket common fields — must match kernel layout exactly (no CO-RE).
// Linux 4.x–6.x layout (verified against kernel source):
//   [0]  skc_daddr       4B
//   [4]  skc_rcv_saddr   4B
//   [8]  skc_hash        4B  ← required gap; missing this shifts port/family reads
//   [12] skc_dport       2B
//   [14] skc_num         2B
//   [16] skc_family      2B
struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		unsigned int skc_hash;
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	unsigned short skc_family;
};

// Socket — embeds sock_common at offset 0.
// IPv6 addr fields are in struct ipv6_pinfo (accessed separately if needed).
struct sock {
	struct sock_common __sk_common;
};

// pt_regs: architecture-specific register context for kprobe/uprobe programs.
// bpf_tracing.h and PT_REGS_* macros require this struct to be defined.
// bpf2go sets __TARGET_ARCH_<arch> based on the -target flag.
#if defined(__TARGET_ARCH_x86)
// x86_64 register context for kprobe/uprobe programs
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_ax;
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
};
#elif defined(__TARGET_ARCH_arm64)
// arm64: bpf_tracing.h casts ctx to user_pt_regs (not pt_regs)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
// pt_regs aliases user_pt_regs on arm64 for our purposes
struct pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#endif

#endif // __VMLINUX_TYPES_H__

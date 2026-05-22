// tc_drop.c — TC ingress/egress classifier.
// Drops packets whose 5-tuple matches an entry in the deny_map.
// Userspace writes denied flows via DenyFlow(); kernel drops them at wire speed.
//
// Walk-stage enforcement: OPA evaluates SPIFFE identity → deny → userspace
// inserts the flow → TC drops subsequent packets on that connection.
//
// Self-contained: uses vmlinux_types.h + inline definitions to avoid system
// header dependency chain (linux/bpf.h → linux/types.h → asm/types.h).

#include "vmlinux_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// TC action codes (linux/pkt_cls.h)
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

// Protocol numbers
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6

// LRU_HASH map type (not in our vmlinux_types.h subset)
#define BPF_MAP_TYPE_LRU_HASH 9

// BPF-accessible sk_buff context (uapi/linux/bpf.h — fields up through data_end).
// preserve_access_index enables CO-RE so the verifier matches fields by name via BTF.
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
} __attribute__((preserve_access_index));

// Ethernet header
struct ethhdr {
    __u8   h_dest[6];
    __u8   h_source[6];
    __be16 h_proto;
};

// IPv4 header
struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl:4;
    __u8 version:4;
#else
    __u8 version:4;
    __u8 ihl:4;
#endif
    __u8   tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8   ttl;
    __u8   protocol;
    __u16  check;
    __be32 saddr;
    __be32 daddr;
};

// TCP header (fields we need)
struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16  doff_flags;  // doff in high 4 bits
    __be16 window;
    __u16  check;
    __be16 urg_ptr;
};

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad;
};

// deny_map: flows to drop. Value is nanosecond timestamp of insertion (for TTL).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct flow_key);
    __type(value, __u64);
} deny_map SEC(".maps");

static __always_inline int check_and_drop(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < 20)
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    struct flow_key key = {
        .src_ip   = ip->saddr,
        .dst_ip   = ip->daddr,
        .dst_port = tcp->dest,
        .protocol = IPPROTO_TCP,
        .pad      = 0,
    };

    if (bpf_map_lookup_elem(&deny_map, &key))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

SEC("tc")
int tc_drop_ingress(struct __sk_buff *skb)
{
    return check_and_drop(skb);
}

SEC("tc")
int tc_drop_egress(struct __sk_buff *skb)
{
    return check_and_drop(skb);
}

char __license[] SEC("license") = "GPL";

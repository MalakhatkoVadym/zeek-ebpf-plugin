#include <linux/bpf.h>
#include <linux/byteorder/little_endian.h>
#include <linux/if_ether.h>
// #include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_helpers.h"

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER) __compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((unsigned long)&((TYPE *)0)->MEMBER)
#endif

struct flow
{
    union
    {
        __u32 ports;
        __be16 port16[2];
    };
};

static inline int ip_is_fragment(struct __sk_buff *ctx, __u64 nhoff)
{
    return load_half(ctx, nhoff + offsetof(struct iphdr, frag_off)) & (IP_MF | IP_OFFSET);
}

static inline __u64 parse_ip(struct __sk_buff *skb, __u64 nhoff, __u64 *ip_proto)
{
    __u64 verlen;
    if (unlikely(ip_is_fragment(skb, nhoff)))
        *ip_proto = 0;
    else
        *ip_proto = load_byte(skb, nhoff + offsetof(struct iphdr, protocol));

    verlen = load_byte(skb, nhoff + 0 /*offsetof(struct iphdr, ihl)*/);
    if (likely(verlen == 0x45))
        nhoff += 20;
    else
        nhoff += (verlen & 0xF) << 2;

    return nhoff;
}

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
    // __u64 nhoff = ETH_HLEN;
    // __u64 ip_proto;
    // // FILTERED PORT
    // __be16 filter_port = 514;

    // __u64 proto = load_half(skb, 12);
    // if (likely(proto == ETH_P_IP))
    // {
    //     struct flow flow;
    //     nhoff = parse_ip(skb, nhoff, &ip_proto);
    //     flow.ports = load_word(skb, nhoff);
    //     //__u64 ports_e = load_word(skb, nhoff);
    //     if (flow.port16[0] == filter_port || flow.port16[1] == filter_port)
    //     {
    //         return SK_DROP;
    //     }
    // }
    // return skb->len;
}
char _license[] SEC("license") = "GPL";

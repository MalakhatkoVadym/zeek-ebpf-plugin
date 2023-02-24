#include <linux/bpf.h>
#include <linux/byteorder/little_endian.h>
#include <linux/if_ether.h>
// #include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	//return skb->len;
	return SK_PASS;
	//return SK_DROP;
	
	void *data = (void *)(long)skb->data;
    // void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;

    // __u32 proto = load_half(skb, 12);
    // if (data + sizeof(*eth) > data_end) {
    //      return 0;
    // }

    if (eth->h_proto != __constant_htons(ETH_P_IP))
    {
        return skb->len;
    }

    struct iphdr *ip = data + sizeof(*eth);
    // if ((void *)ip + 1 > data_end) {
    //     return 0;
    // }

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
    {
        return skb->len;
    }

    // if (ip->protocol == IPPROTO_TCP) {
    //     struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
    //     // if ((void *)tcp + 1 > data_end) {
    //     //      return 0;
    //     //  }

    //     __be16 src_port = tcp->source;
    //     __be16 dst_port = tcp->dest;

    //     if (dst_port == 80) {
    //         return SK_PASS;
    //     }
    // }
    // 	// struct PortFilterSpec dst_filter = {dst_port, IPPROTO_TCP};
    // 	// struct port_stats *dst_stats = bpf_map_lookup_elem(&port_filtering_map, &dst_filter);
    //     // if (dst_stats) {
    //     //     dst_stats->count++;
    // 	// 	return 0;
    //     // }

    // 	// struct PortFilterSpec src_filter = {src_port, IPPROTO_TCP};
    // 	// struct port_stats *src_stats = bpf_map_lookup_elem(&port_filtering_map, &src_filter);
    //     // if (src_stats) {
    //     //     src_stats->count++;
    // 	// 	return 0;
    //     // }

    //     // Do something with src_port and dst_port for TCP packets
    // } else if (ip->protocol == IPPROTO_UDP) {
    //     struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
    //     if ((void *)udp + 1 > data_end) {
    //         return 0;
    //     }

    //     __be16 src_port = udp->source;
    //     __be16 dst_port = udp->dest;

    //     // Do something with src_port and dst_port for UDP packets
    // }
    return skb->len;
}
char _license[] SEC("license") = "GPL";

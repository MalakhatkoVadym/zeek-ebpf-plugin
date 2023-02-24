#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	//return SK_PASS;
	return skb->len;
}
char _license[] SEC("license") = "GPL";

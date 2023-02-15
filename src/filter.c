#include <linux/bpf.h>

int filter(struct __sk_buff *skb)
{
	// The UDP packet starts at offset 0, so the length is at offset 4.
	unsigned short length = load_half(skb, 4);

	if (length == 8)
	{
		// Drop this empty packet.
		return 0;
	}
	else
	{
		// Forward this packet userspace, do not modify.
		return skb->len;
	}
}

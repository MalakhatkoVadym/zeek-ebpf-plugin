
#include "SF_Ring.h"

#include <cstring>
#include <utility>

extern "C"
{
#include <linux/if_packet.h> // AF_PACKET, etc.
#include <sys/socket.h>		 // socketopt consts
#include <sys/mman.h>		 // mmap
#include <unistd.h>			 // sysconf
}

SF_Ring::SF_Ring(int sock, size_t bufsize, size_t blocksize, int blocktimeout_msec)
{
	int ret, ver = TPACKET_VERSION;

	if (sock < 0)
		throw SF_RingException("invalid socket");

	// Configure socket
	ret = setsockopt(sock, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));
	if (ret)
		throw SF_RingException("unable to set TPacket version");

	InitLayout(bufsize, blocksize, blocktimeout_msec);
	ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (uint8_t *)&layout,
					 sizeof(layout));
	if (ret)
		throw SF_RingException("unable to set ring layout");

	pfd.fd = sock;
	pfd.events = POLLIN | POLLERR;
	pfd.revents = 0;

	// Map memory
	size = layout.tp_block_size * layout.tp_block_nr;
	ring = (uint8_t *)mmap(NULL, size, PROT_READ | PROT_WRITE,
						   MAP_SHARED, sock, 0);
	if (ring == MAP_FAILED)
		throw SF_RingException("unable to map ring memory");

	block_num = packet_num = 0;
	packet = NULL;

	// Init block mapping
	blocks = new tpacket_block_desc *[layout.tp_block_nr];
	for (unsigned int i = 0; i < layout.tp_block_nr; i++)
		blocks[i] = (struct tpacket_block_desc *)(ring +
												  i * layout.tp_block_size);
}

SF_Ring::~SF_Ring()
{
	ReleasePacket();

	delete[] blocks;
	munmap(ring, size);

	blocks = 0;
	size = 0;
}

bool SF_Ring::GetNextPacket(tpacket3_hdr **hdr)
{
	struct tpacket_hdr_v1 *block_hdr = &(blocks[block_num]->hdr.bh1);

	if ((block_hdr->block_status & TP_STATUS_USER) == 0)
	{
		poll(&pfd, 1, -1);
		// return false;
	}

	if (packet == NULL)
	{
		// New block
		packet_num = block_hdr->num_pkts;
		if (packet_num == 0)
		{
			NextBlock();
			return false;
		}
		packet = (struct tpacket3_hdr *)((uint8_t *)blocks[block_num] + block_hdr->offset_to_first_pkt);
	}
	else
		// Continue with block
		packet = (struct tpacket3_hdr *)((uint8_t *)packet + packet->tp_next_offset);

	*hdr = packet;
	packet_num--;
	return true;
}

void SF_Ring::ReleasePacket()
{
	if (packet_num == 0)
		NextBlock();
}

void SF_Ring::InitLayout(size_t bufsize, size_t blocksize, int blocktimeout_msec)
{
	memset(&layout, 0, sizeof(layout));
	layout.tp_block_size = blocksize;
	layout.tp_frame_size = TPACKET_ALIGNMENT << 7; // Seems to be irrelevant for V3
	layout.tp_block_nr = bufsize / layout.tp_block_size;
	layout.tp_frame_nr = (layout.tp_block_size / layout.tp_frame_size) * layout.tp_block_nr;
	layout.tp_retire_blk_tov = blocktimeout_msec;
}

void SF_Ring::NextBlock()
{
	struct tpacket_hdr_v1 *block_hdr = &(blocks[block_num]->hdr.bh1);

	block_hdr->block_status = TP_STATUS_KERNEL;
	block_num = (block_num + 1) % layout.tp_block_nr;
	packet = NULL;
}
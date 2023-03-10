#ifndef IOSOURCE_PKTSRC_SF_RING_H
#define IOSOURCE_PKTSRC_SF_RING_H

extern "C"
{
#include <poll.h>
#include <linux/if_packet.h> // AF_PACKET, etc.
}
#include <stdint.h>
#include <stdexcept>
#include <string>

#define TPACKET_VERSION TPACKET_V3

class SF_RingException : public std::runtime_error
{
public:
	SF_RingException(const std::string &what_arg) : std::runtime_error(what_arg) {}
};

class SF_Ring
{
public:
	/**
	 * Constructor
	 */
	SF_Ring(int sock, size_t bufsize, size_t blocksize, int blocktimeout_msec);
	~SF_Ring();

	bool GetNextPacket(tpacket3_hdr **hdr);
	void ReleasePacket();

protected:
	void InitLayout(size_t bufsize, size_t blocksize, int blocktimeout_msec);
	void NextBlock();

private:
	struct tpacket_req3 layout;
	struct tpacket_block_desc **blocks;
	struct tpacket3_hdr *packet;

	unsigned int block_num;
	unsigned int packet_num;

	struct pollfd pfd;

	uint8_t *ring;
	size_t size;
};

#endif
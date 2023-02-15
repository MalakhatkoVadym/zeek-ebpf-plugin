/**
 * Copyright (c) 2018 by Iwan Timmer
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "zeek-config.h"
#include "AF_XDP.h"
#include <bpf/bpf.h>
#include "sock_example.h"
#include "bpf_insn.h"
#include <net/if.h>

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define DEFAULT_COMPLETION_RING_SIZE 32
#define DEFAULT_FILL_RING_SIZE 1024
#define DEFAULT_RX_RING_SIZE 1024
#define NUM_FRAMES 2048
#define FRAME_SIZE 2048
char bpf_log_buf[BPF_LOG_BUF_SIZE];

using namespace iosource::pktsrc;

AF_XDPSource::~AF_XDPSource()
{
	Close();
}

AF_XDPSource::AF_XDPSource(const std::string &path, bool is_live)
{
	if (!is_live)
		Error("AF_XDP source does not support offline input");

	props.path = path;
	props.is_live = is_live;
}

void AF_XDPSource::Open()
{
	int sock, prog_fd, map_fd, opt, ret;

	struct bpf_insn prog[] = {
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
		BPF_MOV32_IMM(BPF_REG_0, 0xffffff),
		BPF_ALU64_REG(BPF_AND, BPF_REG_6, BPF_REG_0),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_redirect_map),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
	};
	
	int insns_count = sizeof(prog) / sizeof(struct bpf_insn);

	
	prog_fd = bpf_load_program(BPF_PROG_TYPE_SOCKET_FILTER, prog, insns_count,
				   "GPL", 0, bpf_log_buf, BPF_LOG_BUF_SIZE);
				   
	sock = open_raw_sock(props.path.c_str());

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
		       sizeof(prog_fd)) < 0) {
		printf("setsockopt %s\n", strerror(errno));
	}

	fd = sock;

	stats = {};

	Opened(props);
}

void AF_XDPSource::Close()
{
	if (fd)
	{
		close(fd);
		fd = 0;
	}

	// bpf.Unload(ifindex);

	Closed();
}

bool AF_XDPSource::ExtractNextPacket(zeek::Packet *pkt)
{
	if (!fd)
		return false;

	u_char buffer[65535];
	struct iphdr *ip_header;

	size_t bytes = recv(fd, buffer, sizeof(buffer), 0);
	size_t undefined = -1;
	if (bytes == undefined)
	{
		return false;
		// printf("Received %ld bytes\n", bytes);
	}
	// write(1, buffer, bytes);

	// current = rx.Next();
	// if (!current)
	//	return false;

	struct timeval ts;
	gettimeofday(&ts, NULL);

	ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	int len = ntohs(ip_header->tot_len);


	pkt->Init(props.link_type, &ts, bytes, len, buffer);

	stats.received++;
	stats.bytes_received += bytes;

	return true;
}

void AF_XDPSource::DoneWithPacket()
{
	// fill.Enqueue(current->addr);
}

bool AF_XDPSource::PrecompileFilter(int index, const std::string &filter)
{
	return true;
}

bool AF_XDPSource::SetFilter(int index)
{
	return true;
}

void AF_XDPSource::Statistics(Stats *s)
{
	/*struct xdp_statistics xdp_stats;

	socklen_t opt_length = sizeof(xdp_stats);

	if (getsockopt(fd, SOL_XDP, XDP_STATISTICS, &xdp_stats, &opt_length) < 0)
	{
		Error(errno ? strerror(errno) : "unable to retrieve statistics");
		return;
	}

	stats.dropped = xdp_stats.rx_dropped;
	stats.link = stats.received + stats.dropped;

	*s = stats;*/
}

zeek::iosource::PktSrc *AF_XDPSource::InstantiateAF_XDP(const std::string &path, bool is_live)
{
	return new AF_XDPSource(path, is_live);
}

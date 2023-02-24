/**
 * Copyright (c) 2018 by Iwan Timmer
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef IOSOURCE_PKTSRC_SF_SOURCE_H
#define IOSOURCE_PKTSRC_SF_SOURCE_H

#define PCAP_DONT_INCLUDE_PCAP_BPF_H

extern "C"
{
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <bpf/bpf.h>
}

#include "iosource/PktSrc.h"
#include "SF_Ring.h"

namespace iosource
{
	namespace pktsrc
	{

		class SFSource : public zeek::iosource::PktSrc
		{
		public:
			SFSource(const std::string &path, bool is_live);

			virtual ~SFSource();

			static PktSrc *InstantiateSF(const std::string &path, bool is_live);

		protected:
			virtual void Open();
			virtual void Close();
			virtual bool ExtractNextPacket(zeek::Packet *pkt);
			virtual void DoneWithPacket();
			virtual bool PrecompileFilter(int index, const std::string &filter);
			virtual bool SetFilter(int index);
			virtual void Statistics(Stats *stats);

		private:
			Properties props;
			Stats stats;

			SF_Ring *sf_ring;
			unsigned short ifindex;
			char bpf_log_buf[BPF_LOG_BUF_SIZE];
			int fd;
			struct pcap_pkthdr current_hdr;

		};

	}
}

#endif
